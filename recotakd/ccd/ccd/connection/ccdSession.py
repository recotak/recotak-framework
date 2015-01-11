"""
session handling
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

how incoming requests are handled
----------------------------------

there is a three staged verification. the first stage verifies that a valid
session id is provided. without session id it is allowed to login in order to
get one. the second stage checks for a valid request id. without request id it
is allowed to request one or to write to plugins stdin, which is relevant for
interactive plugins. the third stage verifies, that the user has selected a
project. without selecting a project, it is only allowed to create or manipulate
projects. executing plugins for instance remains forbidden.


    +---------------+    +---------------+    +---------------+
    |    stage 1    |--->|    stage 2    |--->|    stage 3    |---> process
    +---------------+    +---------------+    +---------------+
    ccd state:           ccd state:           ccd state:
    - no session id      - no request id      - no project set
                                              exception:
                                              - user is superadmin
                                              - user is workgroup admin


    allowed:             allowed:             allowed:
    - OP_LOGIN           - OP_GETRID          - OP_LOGOUT
                         - OP_PLUGIN          - OP_SETPROJ
                                              - OP_SHOWPROJ
                                              - OP_NEWPROJ
                                              - OP_DELPROJ
                                              - OP_UPDATEPROJ
                                              - OP_ADDPROJMEMBER
                                              - OP_DELPROJMEMBER
                                              - OP_ADDPROJPLG
                                              - OP_DELPROJPLG
                                              - OP_SHOWWGROUP


"""

from database.ccdErrors import InvalidSessionID
from database.ccdErrors import SessionError
from database.ccdErrors import EClosed
from database.ccdUser import User
from connection import ccdCrypto
from datetime import timedelta
from connection import ccdlib
from datetime import datetime
from database import ccddb
from time import sleep
import threading
import logging
import select
import os

logger = logging.getLogger("ccd.%s" % __name__)


def get_sessions(db):
    """ returns a dictionary with session ids as key and users as value """
    from database.ccdProject import Project
    sessions_db = ccddb.get_sessions(db)
    sessions = dict()
    for s in sessions_db:
        sid = s[0]

        #  user associated with the session
        user = User.by_uid(db, uid=s[1])

        # project associated with the session
        if s[2]:
            project = Project.by_pid(db, pid=s[2])
        else:
            project = None

        # create new session
        s = Session(sid, user, project)
        sessions[sid] = s
    return sessions

def get_rid(ccd, sid):
    """ return a request id """
    s = ccd.get_session(sid)
    return dict(rid=s.assign_rid())

def invalidate_session(ccd, sid):
    """ invalidate a user's session """
    del(ccd.sessions[sid])

class Session(object):
    """
    A session represents a connection between a specifc user and the ccd.
    It holds request ids that were linked to the session
    and the project associated with it.

    Note that request ids are not stored persistently.

    members:
        sid     session id
        user    user object that is linked to that session
        project project object the user is currently logged in

    """
    # expiration time in secs
    RID_EXP_SEC = 60 * 5

    def __init__(self, sid, user, project):

        """
        Initialize a session

        Input:
            sid     session id
            use     user object that is linked to that session
            project project object the user is currently logged in
        """

        self.sid = sid
        self.user = user
        self.project = project
        self._rids = {}
        self._closed_rids = []

        # this dictionary connects the rid to according fifos for plugin io  forwarding
        self._npipes_in = {}
        self._npipes_out = {}

        self._forwarder_thread = None

        # in order to maintain a consisten session state
        # close and start_forwarding must not overlap.
        #
        # close -> called from plugin.wait thread
        # register -> called from ccd after plugin fork
        #
        # this lock serves to make those calls mutually exclusive
        # possible state routes:
        # started --> registered --> closed
        # started --> closed --> (nothing as start_forwarding raises EClosed)
        self._register_lock = threading.Lock()

    @classmethod
    def from_user(cls, db, user):
        """
        return a session object. The session id is created and the
        session is stored in the database.

        input:
            cls     session constructur provided by annotation
            db      database connection to use for db requests
            user    database.ccdUser object

        output:
            session object

        """
        sid = ccdCrypto.genSID()
        logger.info('Created session. sid: %s', sid)
        ccddb.store_session(db, sid=sid, uid=user.uid)
        return cls(sid, user, None)

    def start_forwarding(self, npipe_out_name, npipe_in_name, sock, rid, req_t):
        """
        Input:
            npipe_out_name      named pipe for plugin output
            npipe_in_name       named pipe for plugin input
            sock                socket object connected to ccd client instance
            rid                 request id (of the register request as well as the exec request)
            req_t               request triggering the registration

        """

        # block close calls until named pipes have been set and the forwarding
        # thread has been started
        with self._register_lock:
            # check if the communacation end has already been closed
            # this might happen, if e.g. the plugin terminates right away
            # in which case close is invoked concurrently and adds the rid
            # to the _closed_rids
            if rid in self._closed_rids:
                raise EClosed('%s is already closed' % rid)

            # set named pipe for stdout
            if rid not in self._npipes_out.keys():
                self._npipes_out[rid] = open(npipe_out_name, 'r+b', 0)
                logger.info('new output npipe/file created %s for session %s', npipe_out_name, self.sid)
            else:
                logger.debug('output npipe/file %s already created for session %s', npipe_out_name, self.sid)

            # set named pipe for stdin
            if npipe_in_name != '/dev/null':
                if rid not in self._npipes_in.keys():
                    self._npipes_in[rid] = open(npipe_in_name, 'r+b', 0)
                    logger.info('new input npipe/file created %s for session %s', npipe_in_name, self.sid)
                else:
                    logger.debug('input npipe/file %s already created for session %s', npipe_in_name, self.sid)

            # start forwarding
            self._start_forwarding(sock, rid, req_t)

    def write_plugin_input(self, rid, plg_id, mth, pld):
        """
        if a remote plugin produces input (e.g. sshlogin), the data needs to be
        written to the original plugin. this is done via the forwarder_thread.
        this thread listens to _plugin_input and waits for incoming input to
        forward it to the plugin.

        input:
            mth     method that indicates how the data should be handled
            pld     the actuall data

        """

        # block close and register calls until the data (pld) has been
        # forwarded
        with self._register_lock:
            # check if the communacation end has already been closed
            # this might happen, if e.g. the plugin terminates right away
            # in which case close is invoked concurrently and adds the rid
            # to the _closed_rids
            if rid in self._closed_rids:
                raise EClosed('%s is already closed' % rid)

            if not self._forwarder_thread or not self._forwarder_thread.is_alive():
                raise Exception("No io forwarding with this session.")

            if not mth == ccdlib.MTH_INPUT:
                raise Exception("Invalid method!")

            if not rid == self._forwarder_thread.rid:
                raise Exception("Invalid rid!")

            if not plg_id == self._forwarder_thread.plg_id:
                raise Exception("Invalid plugin in!")

            npipe_in = self._npipes_in[rid]
            try:
                if not npipe_in.closed:
                    logger.debug("writing plugin input to \'%s\'", npipe_in)
                    npipe_in.write(pld)
                    npipe_in.flush()
            except Exception as e:
                raise Exception("Failed to write plugin input:'%s'", e)

    @staticmethod
    def resend_output(sock, fn, rid, req_t):

        """
        After a plugin is terminated, we just resend all previously produced output,
        which is stored in the file named by fn

        Input:
            sock    socket object connected to ccd client instance
            fn      path to stored plugin output
            rid     request id (of the register request as well as the exec request)
            req_t   the initial request that triggered forwarding
        """

        t = ResendThread(
            sock,
            req_t,
            rid,
            fn,
        )
        t.daemon = True
        t.start()

    def _start_forwarding(self, sock, rid, req_t):
        """
        start the actual forwarding of plugins' output to client and vice versa

        Input:
            sock    socket object connected to ccd client instance
            rid     request id (of the register request as well as the exec request)
            req_t   the initial request that triggered forwarding

        """

        if self._forwarder_thread and self._forwarder_thread.is_alive():
            logger.warning('Forwarding thread already active')
            return

        npipe = self._npipes_out[rid]

        if npipe.closed:
            logger.error('Can\'t read output from closed npipe %s (sid: %s, rid: %s)',
                         npipe, self.sid, rid)

        t = ForwarderThread(
            sock,  # channel_in
            req_t,  # the request triggering the registration
            rid,  # lock to access the fds
            npipe,
        )
        t.daemon = True
        t.start()

        self._forwarder_thread = t

    def close_fds(self, rid):

        """
        Close files and npipe associated with plugin in/output.
        This should only be called after the plugin terminated.

        """

        # if forwarding thread is running, we should stop it first
        self.stop_forwarding()

        with self._register_lock:
            self._closed_rids.append(rid)

            # close stdout
            try:
                npipe = self._npipes_out[rid]
            except:
                logger.debug('No stdout for %s (yet)', rid)
            else:
                logger.info('closing %s', npipe)
                npipe.close()
                os.unlink(npipe.name)
                del self._npipes_out[rid]

            # close stdin
            try:
                npipe = self._fds_in[rid]
            except:
                logger.debug('No stdin for %s', rid)
            else:
                logger.info('closing %s', npipe)
                npipe.close()
                os.unlink(npipe.name)
                del self._npipes_in[rid]

    def stop_forwarding(self):
        if self._forwarder_thread:  # and self._forwarder_thread.is_alive():
            logger.info('stopping forwarder thread')
            self._forwarder_thread.stop()
            self._forwarder_thread.join()
        else:
            logger.info('not stopping forwarder thread')

    def assign_rid(self):
        now = datetime.now()
        exp_date = now + timedelta(seconds=Session.RID_EXP_SEC)
        rid = ccdCrypto.genRID()
        logger.info('Assigning rid %s to session %s', rid, self.sid)
        self._rids[rid] = exp_date
        return rid

    def has_rid(self, rid):
        return rid in self._rids

    def invalidate_rid(self, rid):
        del(self._rids[rid])

    def get_rid_info(self, rid):
        info = None
        try:
            info = self._rids[rid]
        except KeyError:
            pass
        return info

    def unsetproject(self, db, project):
        """ unlink a project to a session and update database """
        if not self.project or not self.project.pid == project.pid:
            logger.warning("Tried to unset a project of a session that is not "
                           "set.")
            return

        logger.debug("unsetting project pid:%s", project.pid)
        self.project = None
        ccddb.update_session(
            db,
            sid=self.sid,
            pid=''
        )

    def setproject(self, db, project):
        """ assign a project to a session and update database """
        logger.debug("session now associated with project pid:%d", project.pid)
        self.project = project
        ccddb.update_session(
            db,
            sid=self.sid,
            pid=project.pid
        )

    def getproject(self):
        """ return project """
        return self.project


def validate_rid(ccd, sid, rid):
    """ returns True if request id is valid, otherwise False """
    s = ccd.get_session(sid)
    # session does not exist
    if not s:
        return False

    # request id does not exist
    if not s.has_rid(rid):
        return False

    # request id is expired
    exp_date = s.get_rid_info(rid)
    if exp_date < datetime.now():
        return False

    # ok, id is valid and from now invalid
    s.invalidate_rid(rid)

    return True


class ForwarderThread(threading.Thread):
    """
    actually forwards data between plugin and client

    In order to receive a plugin's output, the client needs to register for the
    plugin. This is done by sending a OP_REGISTER packet. If so, the plugin's
    stdout is forwarded to the client, while the client's stdin is received and
    forwarded to the plugin.


      +-----------------+  stdout +---------------+ stdout  +---------------+
      |                 | ------> |               | ------> |               |
      |      plugin     |         |    forwarder  |         |     client    |
      |                 | <-----  |               | <------ |               |
      +-----------------+   stdin +---------------+  stdin  +---------------+


    """

    def __init__(self, sock, req_t, rid, npipe_out):
        """ Constructor, setting initial variables """
        self._stopevent = threading.Event()
        self.sock = sock
        self.req_t = req_t
        self.rid = rid
        self.npipe_out = npipe_out
        self.plg_id = req_t[4]

        threading.Thread.__init__(self,
                                  name="forwarder_thread_for_plugin_output")

    def stop(self):
        logger.info('Stop Event Set for %s', self.npipe_out)
        self._stopevent.set()

    def run(self):
        logger.debug("starting io forwarder for %s", self.npipe_out)
        sleep(0.5)

        while not self._stopevent.isSet():
            data = ''

            try:
                r, _, _ = select.select([self.npipe_out], [], [], 1)
            except Exception as e:
                logger.error('Error on %s: %s', self.npipe_out, e)
                raise

            try:
                if self.npipe_out in r:
                    # read data from npipe_out
                    data = os.read(self.npipe_out.fileno(), 1024)
                    logger.info('read data: %s', data)
            except Exception as e:
                logger.error("Error while reading npipe while running %s:'%s'", self.npipe_out.name, e)

            # nothing to send, so continue
            # this might happen when select times out
            if not data:
                continue

            # forward data to client
            try:
                _send_response(self.sock, self.req_t, self.rid, data)
            except Exception as e:
                logger.error("failed to forward plugin output:'%s'", e)

        logger.debug("forwarding terminated for %s", self.npipe_out)


class ResendThread(threading.Thread):

    def __init__(self, sock, req_t, rid, fn_out):
        """ Constructor, setting initial variables """
        self.sock = sock
        self.req_t = req_t
        self.rid = rid
        self.buf_out = fn_out + '_buf'

        threading.Thread.__init__(self,
                                  name="resend_thread_for_plugin_output")

    def run(self):
        logger.debug("start resending output ..")

        sleep(0.5)

        with open(self.buf_out, 'r') as fd:
            for data in fd.readlines():
                logger.debug("sending '%s'", repr(data))
                _send_response(self.sock, self.req_t, self.rid, data)

        logger.debug("finished resending output ..")


def _send_response(sock, req_t, rid, data):
    resp_t = list(req_t)
    resp_t[0] = ccdlib.OP_SUCCESS
    resp_t[2] = rid
    resp_t[6] = ccdlib.MTH_OUTPUT
    resp_t[-1] = data

    # forward it to client
    ccdlib.send(sock, tuple(resp_t))

def stage_one(ccd, sid):
    """
    Perform a stage 1 check. This check verifies the session id.

    input:
        ccd     ccd instance
        sid     session id that is proposed by incoming packet

    output:
        valid   True if stage 1 is passed - otherwise False

    """
    valid = False

    try:
        if ccd.get_session(sid):
            valid = True
    except InvalidSessionID:
        pass

    logger.debug("stage one:%s", valid)
    return valid

def stage_two(ccd, sid, rid):
    """
    Perform a stage 2 check. This check verifies that the user
    presents a valid rid.

    input:
        ccd     ccd instance
        sid     session id that is proposed by incoming packet
        rid     request id that is proposed by incoming packet

    output:
        valid   True if stage 1 is passed - otherwise False

    """
    valid = False

    if validate_rid(ccd, sid, rid):
        valid = True

    logger.debug("stage two:%s", valid)
    return valid


def stage_three(ccd, sid):
    """
    Perform a stage 3 check. This verifies that the user selected
    a valid project. The superadmin is allowed to not select a project.

    input:
        ccd     ccd instance
        sid     session id that is proposed by incoming packet

    output:
        valid   True if stage 1 is passed - otherwise False

    """
    valid = False

    ses = ccd.get_session(sid)
    user, workgroup = ccd.get_user_and_workgroup(sid)

    if (ses.getproject() or
        ccd._superadmin(sid) or
        workgroup.is_allowed(
            ccd._db.conn,
            user=user,
            access=ccddb.ACCESS_READ | ccddb.ACCESS_ADD)):
        valid = True

    logger.debug("stage three:%s", valid)
    return valid

def verify_stages(ccd, sid, rid, op):
    """"
    There are three stages that a package must pass in order to get processed.
    First, it must has a valid session id(sid), second, it must has a valid
    request id(rid) and third, a project must be associated with the current
    session.
    There are exception. For instance it is allowed to not have a session id if
    the packet is a login packet.

    input:
        ccd     ccd instance
        sid     session id of the packet
        rid     request id of the packet
        op      operation of the packet

    output
        raises a database.ccdErrors.SessionError in case of error. otherwise
        returns True

    """

    # validate stage 1
    if not stage_one(ccd, sid):
        # There is only one case that allows an invalid
        # session id and request id. If a user wants to
        # login, the session id and the request id will be
        # ignored.
        #
        # allowed:
        #   OP_LOGIN
        if not op == ccdlib.OP_LOGIN:
            raise SessionError("Invalid Operation in stage 1!")

    # validate stage 2
    elif not stage_two(ccd, sid, rid):
        # There are only two operations that are allowed if
        # stage 2 is not passed. The user is allowed to
        # request a request id.
        #
        # allowed:
        #    OP_GETRID
        if not op in (ccdlib.OP_GETRID, ccdlib.OP_PLUGIN):
            raise SessionError("Invalid Operation in stage 2!")

    # validate stage 3
    elif not stage_three(ccd, sid):
        # There are only two operations that are allowed if
        # stage 2 is not passed. The user is allowed to
        # logout or to select a project.
        #
        # allowed:
        #    OP_LOGOUT
        #    operations to manipulate, add, remove projects
        if not op in (ccdlib.OP_LOGOUT,
                      ccdlib.OP_SETPROJ,
                      ccdlib.OP_SHOWPROJ,
                      ccdlib.OP_NEWPROJ,
                      ccdlib.OP_DELPROJ,
                      ccdlib.OP_UPDATEPROJ,
                      ccdlib.OP_ADDPROJMEMBER,
                      ccdlib.OP_DELPROJMEMBER,
                      ccdlib.OP_ADDPROJPLG,
                      ccdlib.OP_DELPROJPLG,
                      ccdlib.OP_SHOWWGROUP):
            raise SessionError("Invalid Operation in stage 3!")

    return True
