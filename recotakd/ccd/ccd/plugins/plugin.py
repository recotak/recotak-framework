""" handles plugin execution """
from connection.ccdProxyChain import _socks_resolveHost
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
from connection.ccdProxyChain import _socks_hostByAddr
from connection.ccdProxyChain import ProxyChainSocket
from plugins.setup import setup_plugin_conf_dir
from connection import ccdlib, ccdProxyChain
from database.project import db as projectdb
from plugins.setup import setup_plugin_fd
from files.open import open_shared
from files.open import open_home
from database.ccdErrors import *
from files.open import open_any
from datetime import datetime
from database import ccddb
from plugins import comm
from ctools import tee
from recotak import rLog
from argparse import ArgumentParser
import __builtin__
import traceback
import threading
import logging
import socket
from ctools import cMon
from ctools import cTuples
import signal
import errno
import sys
import os
import re
import time

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

#: length of the plugin id hex string
IDLEN = 32

def validate_id(plg_id):
    """ returns True if plugin id is a valid hash otherwise False """
    valid = re.compile("[a-fA-F0-9]{32,}")

    if (not len(plg_id) == IDLEN or
            valid.match(plg_id) is None):
        return False

    return True

def getplugin_byid(ccd, plg_id):
    """ searches plugin by id and returns it """
    logger.debug("getting plugin by id")
    res = None

    for plg in ccd.plugins:
        if plg.id == plg_id:
            res = plg

    return res

def kill(ccd, sid, plgid, mth, pld):
    """
    kills a plugin that was started using a passed request id (contained in
    payload)

    input:
        ccd     ccd instance to operate on
        sid     session id of the user
        plgid   plugin's id to kill
        mth     operation method to indicate additional options
        pld     payload of message which contains request id

    """
    logger.debug("plugin to kill %s", plgid)

    # parse payload
    try:
        rid = pld["rid"]
    except KeyError:
        logger.error("Failed to kill plugin: Unproper payload!")
        return

    # get uid
    uid = ccd.get_user_and_workgroup(sid)[0].uid

    # get fid
    entry = ccddb.getFdByRid(ccd._db.conn, rid, uid)
    if not entry:
        raise Exception("failed to find process in database!")

    # kill plugin
    logger.debug("entry:%s", entry)
    fid = entry[0]
    name = entry[1]
    #plg_id = entry[5]
    state = entry[8]
    pid = entry[9]

    # remove fd from database
    ccddb.removeFd(ccd._db.conn, fid)

    # check whether plugin is running
    if not state or state >= 0:
        logger.warning("plugin (%s) isn't running. nothing to kill.", name)
        return

    # kill plugin
    logger.debug("killing plugin %s, pid:%s", name, pid)

    #TODO validate mth (e.g. to indicate a --force option)
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGKILL)
    except OSError as oserr:
        if oserr.errno == errno.ESRCH:
            logger.warning("Failed to kill %s. No such process.", name)
        else:
            raise

def execute(ccd, project_id, sock, req_t):
    """
    Ccd executes plugin in a separate fork

    input:
        ccd     ccd instance to operate on
        sock    socket that receives the OP_EXEC message
        req_t   the message in form of the request tuple

    output:
        outputs a dictionary containing the fid, scan id and a flag that
        indicates whether the plugin is interactive (e.g. a shell)

    """
    op, sid, rid, cat, plg_id, gid, mth, args = req_t

    # get plugin
    plg = getplugin_byid(ccd, plg_id)

    logger.debug('plg.execute %s', plg.name)

    if not plg:
        raise Exception("Invalid plugin id!")

    # create ipc
    logger.debug("creating socket pair")
    parentuds, childuds = socket.socketpair()

    # setup plugin dir
    plg_root = setup_plugin_conf_dir(ccd, sid, plg)
    if not plg_root:
        raise Exception("Failed to set up plugin config directory.")

    # set currents
    ccd.current_plugin = plg

    # create new task db entry
    #TODO task should be created early and creation ought to be
    # triggered by client
    user, _ = ccd.get_user_and_workgroup(sid)
    tid = ccddb.insert_task(
        ccd._db.conn,
        start=datetime.now(),
        uid=user.uid,
        pid=ccd._get_project(sid).pid
    )

    # set up database handler to enable plugin's database usage
    dbh = projectdb.DatabaseHandler()
    scanid = projectdb.init_project_db(
        ccd._db.conn,
        dbh=dbh,
        pid=project_id,
        templates=plg.dbtemplate,
        psql_url=ccd.config.db_psql_url,
        psql_db=ccd.config.db_psql_db,
        tid=tid,
        plg_id=plg.id,
        extra=plg.extra,
        plgname=plg.name
    )

    # create file descriptor
    fd_out, fd_in, fid = setup_plugin_fd(ccd, sid, rid, args)

    # create new process
    pid = os.fork()
    ccd.process_id = pid

    # child process
    if ccd.process_id == 0:
        parentuds.close()
        _execute_plugin(ccd,
                        user, plg, fid, fd_out, fd_in, project_id,
                        dbh, args)

    # parent process
    else:
        childuds.close()
        with ccd.runningPlugins_lock:
            logger.debug("storing running plugin")
            ccd.runningPlugins[rid] = (pid, plg.id, plg.name,
                                       parentuds, fd_out)
            logger.debug("starting waiter-thread")

        os.setpgid(pid, pid)

        t = threading.Thread(target=wait,
                             args=(ccd, req_t,
                                   pid, fid, plg.name, sock, dbh))
        t.start()

    return dict(fid=fid, scanid=scanid, interactive=plg.interactive)

def wait(ccd, req_t, pid, fid, plg_name, sock, dbh):
    """
    waits for a plugin to terminate via os.waitpid. if a plugin terminates, the
    fd_state is updated and a MTH_TERMINATE is sent to the client.

    Note: this is not triggered, if ccd is killed via SIGKILL

    input:
        req_t   request tuple which triggered execution of plugin
        pid     id of the project in which context the plugin is executed
        fid     id of the fd database entry which holds data about the plugin's
                execution state
        plg_name    name of the plugin which is executed
        sock    socket that is used sent the MTH_TERMINATE message in order to
                inform the client about termination
        dbh     database handler in order to update plugin's execution state in
                database

    """
    # wait for plugin to terminate
    logger.debug("waiting for %d to terminate ..", pid)
    #WAIT = 1
    result = (0, 0)

    suc, sid, rid, cat, plg, gid, mth, result = req_t
    ccd._db.conn = ccddb.connect()

    try:
        result = os.waitpid(pid, 0)

    except OSError as e:
        # If no childprocess with corresponding pid is found
        # errno 10 is raised. This indicates that the child is
        # already dead.
        if e.errno == 10:
            pass
        else:
            raise e

    # get plugin state
    try:
        state = ccddb.get_fd_state(ccd._db.conn, fid)[0]
        logger.debug("plugin terminated with %s", state)
    except Exception as e:
        raise Exception("Failed to get fd status:'%s'." % str(e))

    # a plugin state -1 indicates that the fork was correctly started
    # Note: this does not cover SIGKILLs
    # of the ccd server, which lead the plugins to be killed, too.
    if state == -1:
        state = result[1]
        try:
            ccddb.set_fd_state(ccd._db.conn, fid, state)
        except Exception as e:
            logger.exception(e)

    # terminating forwarder
    try:
        logger.debug("stopping forwarder..")
        uid = ccd.get_user_and_workgroup(sid)[0].uid
        comm.close(ccd, ccd._db.conn, sid, fid, uid)
    except Exception:
        logger.error("Failed to stop forwarder thread!")

    # communicate plugin state to client
    suc = ccdlib.OP_SUCCESS
    mth = ccdlib.MTH_TERMINATE
    result = dict(code=state)
    resp_t = suc, sid, rid, cat, plg, gid, mth, result
    logger.debug("sending plugin's state to client=%s", resp_t)
    ccdlib.send(sock, resp_t)
    projectdb.close(dbh)
    ccddb.close(ccd._db.conn)

def _forward_stderr(self, message):
    sys.stdout.write(message)
    sys.stdout.flush()

def _execute_plugin(ccd, user, plg, fid, fd_out, fd_in, project_id, dbh, args):
    # get process id
    pid = os.getpid()

    logger.info("Executing plugin. pid:%d, plg:%s, fid:%d, fd:%s",
                pid, plg.name, fid, fd_out)

    # we need to redirect the plugin's stdout/stdin
    oldstdout = sys.stdout
    oldstdin = sys.stdin

    # execute
    try:
        sys.stdout = tee.tee(open(fd_out, "ab", 0), open(fd_out + '_buf', 'a+b', 0))
        sys.stdin = open(fd_in, "rb", 0)
        ArgumentParser.error = _forward_stderr
        logger.info('client fds opened')

        if not plg.runasroot:
            logger.info('Dropping root Privs')
            # drop privileges
            os.setgroups([])
            os.setgid(ccd.config.runAsGid)
            os.setuid(ccd.config.runAsUid)
        else:
            uid = os.getuid()
            gid = os.getgid()
            logger.info('Keeping root Privs, uid/gid: %d/%d', uid, gid)

        # get new db engine
        ccd._db.conn = ccddb.connect_to_database(ccd.config.db_url)

        # set plugin state
        ccddb.set_fd_state(ccd._db.conn, fid, -1)
        ccddb.set_fd_process_id(ccd._db.conn, fid, pid)

        # redirect socket connection via proxy chain
        ProxyChainSocket.chain_mode = ccdProxyChain.CHAIN_MODE_ROBIN
        socket.socket = ProxyChainSocket
        socket.gethostbyaddr = _socks_hostByAddr
        socket.gethostbyname = _socks_resolveHost

        cMon.activeted = ccd.config.monitoring

        if plg.direct:
            sys.stdout.write('-' * 80)
            sys.stdout.write('\n')
            sys.stdout.write('[!] WARNING: Plugin does not use proxies\n')
            sys.stdout.write('-' * 80)
            sys.stdout.write('\n')
            logger.info('Using direct connection for this plugin')
            ProxyChainSocket._use_socks = False
        else:
            logger.info('Using proxy connection for this plugin')
            ProxyChainSocket._use_socks = True

        # enable plugin access to home and shared directory
        open_shared.base_dir = ccd.config.shared_directory
        __builtin__.openshared = open_shared
        open_home.base_dir = os.path.join(user.home_dir, plg.id)
        __builtin__.openhome = open_home
        __builtin__.openany = open_any

        # check whether there is a connection group that is assigned to the
        # current plugin/project-combination. if so, get its chains. otherwise
        # use system's connection group
        try:
            grpid = ccddb.get_group_by_plugin_project(ccd._db.conn,
                                                      plg.id,
                                                      project_id)
            if grpid:
                from connection.ccdGroup import return_group_by_id
                group = return_group_by_id(ccd, grpid)
                ProxyChainSocket._current_connection_group = group
        except Exception as e:
            logger.warning("Failed to get connection group for given "
                           "plugin/project. Using system conn group "
                           "instead: '%s'", e)

        if hasattr(plg, 'parser'):

            if '-h' in args or '--help' in args:
                logger.info('help detected')
                #plg.parser.parse_args(args)
                plg.parser.print_help()
                sys.exit(1)

            if len(args) < 2:
                logger.info('no args detected')
                plg.parser.print_help()
                sys.exit(1)

            args = plg.parser.parse_args(args)
            for a in plg.cli.actions:
                try:
                    if getattr(args, a.dest) == a.default:
                        logger.info('Invoking action for default argument %s %s',
                                    plg.name, a.dest)
                        a.__call__(plg.parser, args, a.default)
                except AttributeError as e:
                    pass

            if not args:
                print 'ERROR: invalid input'
                plg.parser.print_help()
                sys.exit(1)

            vargs = vars(args)

            try:
                cTuples.cTuples.DELAY = vargs['delay']
            except KeyError:
                pass

            ch = rLog._create_consolehandler()
            rLog.log.addHandler(ch)

            try:
                cTuples.cTuples.MAXTHREADS = vargs['nthreads']
            except KeyError:
                pass

            plg.execute(dbh, **vargs)
        else:
            # execute plugin
            plg.execute(dbh, args)

        # set plugin state
        ccddb.set_fd_state(ccd._db.conn, fid, 0)

    except SystemExit as se:
        logger.debug("Plugin exited with %s", se)
        ccddb.set_fd_state(ccd._db.conn, fid, se.code)
    except Exception as err:
        traceback.print_exc(file=sys.stdout)
        logger.error("Failed to execute plugin:%s", str(err))
        ccddb.set_fd_state(ccd._db.conn, fid, 1)
    finally:
        # reset stdout/stdin
        try:
            # TODO wait for plugin to send data, remove sleep if possible
            time.sleep(1)
            sys.stdout.flush()
            logger.info('closing plugin stdout %s', sys.stdout)
            sys.stdout.close()
        except Exception as e:
            logger.warning('Couldn\'t close %s: %s', sys.stdout, e)
        sys.stdout = oldstdout
        sys.stdin = oldstdin
        ccddb.close(ccd._db.conn)

    #pgid = os.getpgid(pid)
    logger.info("Plugins finished. My work is done.. bye.")
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid)
    sys.exit(0)

def get_plugins(ccd):
    """ return currently registered plugins """
    plugins = [(plg.id, plg.name) for plg in ccd.plugins]

    return plugins
