"""
registering and unregistering for plugins
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

In order to receive a plugin's output, the client needs to register for the
plugin. This is done by sending a OP_REGISTER packet. If so, the plugin's
stdout is forwarded to the client, while the client's stdin is received and
forwarded to the plugin.
Forwarding is done by a ForwarderThread of the ccdSession object.
In order to stop forwarding, the client unregisters for the plugin

"""

from database.ccdErrors import EClosed
from connection import ccdSession
from connection import ccdSocket
from database import ccddb
import logging
import socket

logger = logging.getLogger("ccd.%s" % __name__)

def close(ccd, conn, sid, fid, uid):
    """ Unregisters a user associated with sid that interacts with a
        fd given in pld.

        input:
            sid:    session id
            pld:    list of fds to unregister from

        ouputs:
            a string
    """
    fd_database_entry = ccddb.getFdByFid(conn, fid, uid)

    #fd_in = fd_database_entry[0][3]
    #fd_out = fd_database_entry[0][4]

    if not fd_database_entry:
        logger.error("Database returned no fd that I can close!")
        return

    logger.debug('Closing %s', fd_database_entry)
    unregister(ccd, sid)
    ses = ccd.get_session(sid)

    rid = fd_database_entry[0][6]

    try:
        ses.close_fds(rid)
    except Exception as e:
        logger.warning('Could not close %s/%s: %s', fd_database_entry[0][4], fd_database_entry[0][3], e)


def unregister(ccd, sid):
    """ Unregisters a user associated with sid that interacts with a
        fd given in pld.

        input:
            sid:    session id
            pld:    list of fds to unregister from

        ouputs:
            a string
    """
    logger.debug("unregistering for plugin..")
    ses = ccd.get_session(sid)
    ses.stop_forwarding()


def register(ccd, sock, req_t):
    """ Registers a user associated with sid to interact with a plugin
        given in pld.
        If forwarder not running, start forwarder in separete thread.

        input:
            sid    session id
            req_t  the actual request containing the payload

    """

    pld = req_t[-1]
    uid = ccd.get_user_and_workgroup(req_t[1])[0].uid
    plg_id_register = req_t[4]
    logger.debug("registering for plugin %s, pld:%s",
                 plg_id_register, pld)

    try:
        # extract payload
        rid = pld["rid"]

        fd_database_entry = ccddb.getFdByRid(ccd._db.conn, rid, uid)
        logger.debug("fds:%s", fd_database_entry)

    except (KeyError, ValueError):
        raise Exception("Unproper payload!")
    except Exception as err:
        raise Exception("Failed to get fd for uid '%s':'%s'" % (uid, err))

    # check whether uid is allowed to access fd
    # the for-loop is mainly due to logging-fds. there multiple
    # logging-fd entries in db (for every user that is allowed to
    # access)
    f_in = fd_database_entry[3]
    f_out = fd_database_entry[4]
    plg_id = fd_database_entry[5]

    ses = ccd.get_session(req_t[1])
    if not plg_id_register == plg_id:
        raise Exception("Invalid plugin id!")

    # get the plugin state: -1 = running, >=0 = terminated
    state = fd_database_entry[8]
    if state < 0:
        # if the pulgin is still running, we use the forwarder thread to read from
        # the fifo and pass the data along to the client

        # add the correspondig fds to the session. Now, the session is able
        # to forward content from fd to client and vice versa
        try:
            #ses.set_fd(f_out, f_in, rid)
            ses.start_forwarding(f_out, f_in, sock, rid, req_t)
        except EClosed as e:
            logger.info(e)
        except Exception as e:
            logger.error('Could not set fds for client io forwarding: %s', e)

    else:
        # if the plugin is terminated and does not produce any more output,
        # just send the saved output to the client
        logger.info('Plugin is not running -> sending buffered output')
        ccdSession.Session.resend_output(sock, f_out, rid, req_t)

    # check whether plugin is interactive
    interactive = ccddb.is_fd_interactive(ccd._db.conn, plg_id)
    return dict(interactive=interactive)


def getstate(ccd, sid):
    """ returns all plugin names and fid that are created by the user
        associated with the given sid
    """
    logger.debug("get state for sid %s", sid)
    res = []

    # get information from database
    uid = ccd.get_user_and_workgroup(sid)[0].uid
    fd_db = ccddb.getFdByUid(ccd._db.conn, uid)

    # return fds and plugin name
    for e in fd_db:
        try:
            res.append(dict(
                       command=e[1],
                       plg_id=e[5],
                       rid=e[6],
                       state=e[8]))
        except Exception as err:
            logger.warning("Failed to get state for %s: %s",
                           str(e), str(err))

    return res

