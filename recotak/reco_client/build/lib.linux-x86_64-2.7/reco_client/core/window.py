"""
the window representation
# Copyright (c) 2014, curesec GmbH
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
# conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
# of conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used
# to endorse or promote products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

A window is something like a local instance of the remote plugin. It prints its
output and takes input which is forwarded to the real plugin. You can even
remotely kill plugins using windows.

"""

import reco_client.connection.comm as comm
import reco_client.connection as conn
from tempfile import SpooledTemporaryFile
from M2Crypto import X509
import errors
import logging
import select
import socket
import ssl
import sys
import os

logger = logging.getLogger("client.%s" % __name__)

MAX_WINDOWS = 255

#: window is initialised. usually no real state
INIT = "initialised"

#: plugin is running
RUNNING = "running.."

#: plugin is successfully finished. return code 0
FINISHED = "finished"

#: plugin finished with return code not 0
ERROR = "terminated unsuccuessfully"

#: plugin finished with return code 9
KILLED = "killed"

#: links window state strings to actuall return code ints
STATE = [ERROR] * 11
STATE[0] = RUNNING
STATE[1] = FINISHED
STATE[10] = KILLED

class RecvWindow(object):
    """
    Receiver windows receive data on a socket to fill their
    buffer.

    A window instance has the following attributes:

        name        Name of the window. The name of all windows is shown by
                    '> win show' in command line interface. It's usually the
                    name of the plugin appended by the arguments passed for
                    execution (e.g. ps.plg -A -t curesec.com)
        status      indicates the state of the plugin (e.g. RUNNING or FINISHED)
        req_t       request tuple that triggered plugin execution. It's used to
                    verify incoming packets
        plg_id      id of the plugin
        rid         request id of the packet triggering execution
        wid         the id of the window. Derived from a class variable which
                    is increased after window creation. The window id is not
                    fixed. So every new client session, the windows might have
                    a new id.
        session     the actual client session
        is_used     flag, that indicates, whether the windows is used by user
                    (via '> win show <id>')

    """

    #: command to close window
    CMD_CLOSE = "close"

    #: window id, increased for every new window
    ID = 1

    def __init__(self, name, req_t, session):
        logger.debug("creating window %s", name)
        self.name = name
        self.status = RUNNING
        self.req_t = req_t
        self.sid = req_t[1]
        self.rid = req_t[2]
        self.plg_id = req_t[4]
        self.wid = RecvWindow.ID
        self.session = session
        self.is_used = False
        self.closed = False

        self._buffer = SpooledTemporaryFile(max_size="8096", mode="wr+b")
        RecvWindow.ID += 1

    def close(self):
        self.closed = True
        print("closing window %d" % self.wid)

    def set_state(self, input_code):
        state = None
        try:
            state = STATE[input_code + 1]
        except (IndexError, TypeError) as e:
            logger.warning('Could not get window state for code %d: %s', input_code, e)
            logger.exception(e)

        if not state:
            state = "Unknown"

        if self.is_used and state in (FINISHED, ERROR, KILLED):
            self.is_used = False

        code = "(%s)" % str(input_code)
        self.status = "{state} {code}".format(state=state, code=code)

        logger.debug("new window(id:%s) state: %s", self.wid, self.status)

    def _write_to_output(self, data):
        # if no more data is coming, set window state to
        # finished and break if we have a non-interactive
        # window (otherwise we need to wait for the user
        # to enter further input).
        #if not data:
        #    self.status = FINISHED
        # TODO: that seems a bit heuristic to me ...

        # ok, we have data, so verify 'em and print it. this is
        # done by unpack
        try:
            actual_output = self._unpack(data)
            if actual_output:
                sys.stdout.write(actual_output)
                sys.stdout.flush()
                self._buffer.write(actual_output)
                self._buffer.flush()

        except errors.ClientError as e:
            if e.request:
                logger.warning('Request: %s', conn.ccdlib.pkt2str(e.request))
            if e.response:
                logger.warning('Response: %s', conn.ccdlib.pkt2str(e.response))
            logger.debug("received invalid packet:'%s'", e)
            logger.exception(e)
        except Exception as e:
            logger.debug("received invalid packet:'%s'", e)
            logger.exception(e)

    def _unpack(self, resp_t):
        #if not resp_t[0] == cnnm.ccdlib.OP_SUCCESS:
        #    raise Exception("received packet that indicates a failure(%s)!",
        #                    hex(resp_t[0]))

        ## sid
        #if not resp_t[1] == self.req_t[1]:
        #    raise Exception("received packet with invalid session id(%s)!",
        #                    resp_t[1])

        ## rid
        #if not resp_t[2] == self.req_t[2]:
        #    raise Exception("received packet with invalid rid(%s)!",
        #                    resp_t[2])

        ## plg_id
        #if not resp_t[4] == self.req_t[4]:
        #    raise Exception("received packet with invalid plugin id(%s)!",
        #                    resp_t[4])

        # method indicates a plugin's state change.
        if resp_t[6] == conn.ccdlib.MTH_TERMINATE:
            state = 2
            try:
                state = resp_t[-1]["code"]
            except (KeyError, IndexError):
                raise errors.InvalidServerResponse(
                    message="No state in terminate response payload",
                    request=self.req_t, response=resp_t)
            self.set_state(state)
            return

        elif resp_t[6] == conn.ccdlib.MTH_INPUT:
            return ""

        # plugin gives outpout
        elif not resp_t[6] == conn.ccdlib.MTH_OUTPUT:
            try:
                MTH_str = conn.ccdlib.rev_MTH_map[resp_t[6]]
            except:
                MTH_str = repr(resp_t[6])
            raise errors.InvalidServerResponse(
                message="Invalid method %s, expected MTH_OUTPUT, _TERMINATE or _INPUT" % MTH_str,
                request=self.req_t, response=resp_t)

        return resp_t[-1]

    def _pack(self, data):
        req_t = list(self.req_t)

        req_t[0] = conn.ccdlib.OP_PLUGIN  # indicate operation concerning plugin
        req_t[6] = conn.ccdlib.MTH_INPUT  # indicate plugin input is coming
        req_t[-1] = data  # payload

        # if no input to commit, raise EmptyException
        if not req_t[-1]:
            raise conn.ccdlib.EmptyException

        return tuple(req_t)

    def use(self):
        # to get the plugin's output, we need to register
        rid = self.req_t[2]
        plg_id = self.req_t[4]
        pld = comm.sendpacket(self.session,
                              op=conn.ccdlib.OP_REGISTER,
                              plg=plg_id,
                              pld=dict(rid=rid))[-1]
        interactive = pld["interactive"]
        logger.debug("successfully registered to plugin. have fun!")

        if interactive:
            print("Enter '%s' to leave interactive mode." %
                  RecvWindow.CMD_CLOSE)

        sock = self.session.sock

        # write content that is already buffered
        for line in self._buffer:
            sys.stdout.write(line)

        # start window interaction
        self.is_used = True
        while self.is_used:

            try:
                r, _, _ = select.select([sys.stdin, sock], [], [])
            except KeyboardInterrupt:
                print("catched keyboard interrupt. closing window.")
                self.is_used = False
                break

            # if there is something to print to window
            if sock in r:
                # read data, that should be written to stdout.
                # the data is sent by the ccd
                resp_t = None
                try:
                    resp_t = conn.ccdlib.recv(sock)
                    #resp_t = comm.wait_for_response(self.session, self.req_t)
                except Exception as e:
                    logger.error("Exception while receiving data: %s", e)
                    logger.exception(e)
                    self.is_used = False
                    break

                if resp_t:
                    self._write_to_output(resp_t)

            # there is something to read form window console
            if sys.stdin in r:
                if not interactive:
                    # any keystroke sends active plugin to background
                    self.is_used = False
                    break

                # read the user's input to be sent to the ccd plugin
                #data = sys.stdin.readline()
                data = ''
                try:
                    data = os.read(sys.stdin.fileno(), 1024)
                except Exception, e:
                    logger.error("Error reading from stdin: '%s'!", e)
                    logger.exception(e)
                    continue

                logger.debug('all read on stdin \'%s\'', data)

                # catch command to close the interactive window
                if data.rstrip() == RecvWindow.CMD_CLOSE:
                    self.is_used = False
                    break

                # the actual write of the user's input
                actual_packet = self._pack(data)

                try:
                    conn.ccdlib.send(sock, actual_packet)
                    comm.wait_for_response(self.session, actual_packet)
                except Exception as e:
                    logger.error("Failed to send user input to plugin!:'%s'", e)
                    logger.exception(e)

        try:
            comm.sendpacket(self.session,
                            op=conn.ccdlib.OP_UNREGISTER,
                            plg=plg_id,
                            pld=dict(rid=rid))
        except KeyboardInterrupt:
                print("catched keyboard interrupt. closing window.")
        except Exception as e:
            logger.error("Failed to unregister properly:'%s'!", e)
            logger.exception(e)

def _get_socket(client, addr, secure=True, timeout=10):
    """
    return a socket. in case of ssl, verifies ccd server cert fingerprint
    matches the fingerprint given in config file

    input:
        addr        address tuple to connect to
        secure      use ssl. if True, the ccd server cert's fingerprint is
                    checked against fp in config
    output:
        socket_fd   socket that holds connection

    """
    cert_fingerprint = _get_socket.cert_fingerprint

    socket_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_fd.settimeout(timeout)
    socket_fd.connect(addr)

    if secure and cert_fingerprint:
        logger.debug("connecting to %s via ssl.", str(addr))
        socket_fd = ssl.wrap_socket(socket_fd,
                                    certfile=client._cert,
                                    keyfile=client._cert_key,
                                    ssl_version=client._ssl_version)

        cert_der = socket_fd.getpeercert(binary_form=True)
        x509 = X509.load_cert_string(cert_der, X509.FORMAT_DER)
        fp = x509.get_fingerprint("sha1")

        if not fp == cert_fingerprint:
            raise Exception("Invalid certificate %s" % fp)

        logger.debug("server cert has valid fingerprint (%s)", fp)
    else:
        logger.debug('ssl disabled')

    return socket_fd

def showWindows(session, wid):
    """
    if not window id is passed, outputs the current listed output buffers.
    otherwise switchs to window with the corresponding id.

    input:
        wid     window id

    """
    if wid:
        win = get_win(session, wid)
        win.use()

    else:
        wording = "\n"
        for wid, win in session._win_by_wid.items():
            if win.closed:
                continue
            wording += "\twin {id} ({name}) - {status}\n".\
                format(id=wid,
                       name=win.name,
                       status=win.status)
        print(wording)

def killWindow(session, wid, force):
    """ kills window and sends kill request to ccd """
    logger.debug("killing window %d (force=%s)", wid, force)
    win = get_win(session, wid)

    if win.status == RUNNING and not force:
        print("Nope, the plugin is still running. "
              "Use -f if you want to kill it anyways.")
        return None

    if win.wid > 0:
        comm.sendpacket(session,
                        op=conn.ccdlib.OP_KILL,
                        mth=conn.ccdlib.MTH_FORCE,
                        plg=win.plg_id,
                        pld=dict(rid=win.rid))

        print("killed plugin.")

    win.close()
    #del_win(session, win)

def createWindow(session, winname, req_t):
    """
    creates a new window to represent the plugin's output

    input:
        winname     name of the new window
        rid         id of the request that issued the window
        plg_id      id of the plugin that issued the file descriptor
        log         boolean to indicate whether the window is a
                    general logging window.

    output:
        win     the new window

    """
    # create window
    win = RecvWindow(winname,
                     req_t,
                     session)

    # store window for later access
    set_win(session, win)

    return win

def set_win(session, win):

    """" adds a window to a session """

    if win.wid in session._win_by_wid.keys():
        raise errors.AlreadyExistingError(message='Window id:%s already exists' % (win.wid))

    if win.rid in session._win_by_rid.keys():
        raise errors.AlreadyExistingError(message='Window for rid:%s already exists' % win.rid)

    session._win_by_wid[win.wid] = win
    session._win_by_rid[win.rid] = win

def reset_all_win(session):

    """ delete all windows and reset RecvWindow.ID """

    session._win_by_wid = {}
    session._win_by_rid = {}

    RecvWindow.ID = 1

def del_win(session, win):
    """ deletes a window from a session """
    logger.info('Deleting window wid:%s, rid:%s', win.wid, win.rid)
    del(session._win_by_wid[win.wid])
    del(session._win_by_rid[win.rid])

def get_win(session, wid):
    """ return window """
    try:
        win = session._win_by_wid[wid]
    except (IndexError, KeyError):
        raise errors.NotFoundError(message="No such window id %s!" % str(wid))

    return win

def get_win_by_rid(session, rid):
    """
    returns a window that is associated with the corresponding request id.
    If not window found, raises a NotFoundError

    input:
        rid     request id

    output:
        win     returns the window

    """
    try:
        win = session._win_by_rid[rid]
    except KeyError:
        raise errors.NotFoundError(message="No window for request id %s!" % str(rid))

    return win
