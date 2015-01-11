#!/bin/sh
# -*- mode: Python -*-
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

""":"
# https://github.com/apache/cassandra/blob/trunk/bin/cqlsh
# bash code here; finds a suitable python interpreter and execs this file.
# prefer unqualified "python" if suitable:
python -c 'import sys; sys.exit(not (0x02070000 < sys.hexversion < \
    0x03000000))' 2>/dev/null && exec python "$0" "$@"
which python2.7 > /dev/null 2>&1 && exec python2.7 "$0" "$@"
echo "No appropriate python interpreter found." >&2
exit 1
":"""

""" ccd server """

__version__ = "0.0.6"


CONFIG = "config/productive.conf"


def test_connection(raddr, timeout=1):
    s = None
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect(raddr)
    except socket.timeout:
        return False
    except socket.error as e:
        if e.errno == 111:  # Connection refused
            return False
        logger.error(e)
        return False
    finally:
        if s:
            s.close()
    return True

def _check_permissions(filename, permissions):
    """
    check whether permission of file are correct. return True if so,
    otherwise return False

    input:
        filename    name of file to check
        permissions permissions that the file should have

    output:
        return True if file's permissions are as indicated by permissions
        parameter

    """

    # first check if file exists
    if not os.path.exists(filename):
        logger.error("%s does not exist", filename)
        return False

    # not check permissions
    st = os.stat(filename)
    perm_mask = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
    masked_p = permissions & perm_mask
    masked_s = st.st_mode & perm_mask
    if masked_p != masked_s:
        logger.error("%s has permissions %s, please set them to %s",
                     filename, oct(masked_s), oct(masked_p))
        return False

    return True


class Ccd(object):
    """
    Server class that handles the client's requests. It executes plugins.

    """
    def __init__(self, daemon, config_fn, addr=None):
        logger.info("Initialising ccd..")
        self.daemon = daemon
        self.pwd = os.getcwd()
        self.process_id = -1
        self.os_gpid = os.getpgrp()

        self.current_plugin = None
        self.categories = []
        self.plugins = []

        self.isAlive = True

        self.runningPlugins = {}
        self.runningPlugins_lock = threading.Lock()

        # read config
        self.config = read_config(config_fn)

        # check certificates
        if not (_check_permissions(self.config.cert,
                                   stat.S_IWUSR | stat.S_IRUSR) and
                _check_permissions(self.config.cert_key,
                                   stat.S_IWUSR | stat.S_IRUSR)):
            logger.error("Illegal cert permissions!")
            sys.exit(1)

        # set up logging file handler
        logdir = os.path.dirname(self.config.log_dest)
        if not os.path.exists(logdir):
            logger.error("Logging directory %s does not exist, please "
                         "create it", logdir)
            sys.exit(1)

        rh = cUtil.add_rotat_logger(self.config.log_dest,
                                    self.config.log_level)
        rh.propagate = False
        logging.getLogger("").addHandler(rh)

        # bind input socket to listen to
        self.sock_in = ccdSocket.get_server_sock(
            addr=addr if addr else self.config.addr,
            listen=self.config.listenmax
        )

        # setting user base dir and ccd uid information
        ccdUser.User.BASE_DIR = self.config.userdir
        ccdUser.User.SHARED_DIR = self.config.shared_directory
        ccdUser._valid_owner.CCD_UID = self.config.runAsUid

        # if we use socks, we need to redirect some
        # socket functionality to use the socket chain
        if self.config.useSocks:
            # check if socks server is up
            for s in self.config.socksserver:
                if not test_connection(s):
                    logger.error('Unable to connect to %s. Please make sure '
                                 'the socks server is running', s)
                    sys.exit(1)
            socket.gethostbyname = ccdProxyChain._socks_resolveHost
            socket.gethostbyaddr = ccdProxyChain._socks_hostByAddr

        else:
            print '[!] Warning: Proxies disabled'
            ccdProxyChain._use_socks = False

        # daemonise
        if self.daemon:
            pid = cdaemonise.daemonise(name="ccd",
                                       stderr=self.config.log_dest,
                                       stdin=self.config.log_dest,
                                       stdout=self.config.log_dest
                                       )
            logger.info("pid=%d", pid)

        # Setup database (user table, session tabla)
        try:
            self._db = threading.local()
            self._db.conn = ccddb.initdatabase(self.config.db_url)
        except sqlOperationalError as op:
            if "could not connect to server: Connection refused" in str(op):
                logger.error("Database server is not up. Failed to connect. "
                             "Please start postgresql daemon.")
            else:
                raise
            sys.exit(2)

        # load plugins
        logger.info("Initialising categories and plugins..")
        self.rootCategory = setup.new_category(self, "/")
        self.pluginCategory = setup.new_category(self, "Plugins")
        self.rootCategory.link(self.pluginCategory)
        setup.scan_plugin_directory(self)

        # load old sessions
        self.sessions = ccdSession.get_sessions(self._db.conn)

        # create initial user
        self.superadmin = self._create_superadmin()

        # proxy cache
        self.proxies = {}

        # initalise proxy chains dict and get chains from database
        self.proxychains = {}
        ccdProxyChain._update_proxy_chains(self)

        # initialise connection groups. To do so, get default group from
        # database. If no group is set, create a new proxy, chain and
        # connection group and set it as default. Before creating, load setup
        # from config file.
        self.connection_groups = {}
        grpid = ccddb.get_default_conngroup(self._db.conn)

        # default group already set
        if grpid:
            default_group = ccdGroup.return_group_by_id(self, grpid)

        # build from config
        else:
            default_group = self._create_configured_proxies()

        ProxyChainSocket._current_connection_group = default_group

        # dictionary to hold global default parameter values
        self.glob_defaults = {}

    def _create_configured_proxies(self):
        """ Create the proxies, that a configured in configuration file """
        # create proxy chain
        chain = ProxyChain.create(self._db.conn,
                                  "chain to contain proxies of config file")

        self.proxychains[chain.pcid] = chain

        # create proxy
        for ip, port in self.config.socksserver:
            try:
                proxy = Proxy.create(db=self._db.conn,
                                     ip=ip,
                                     port=port,
                                     protocol="s4",
                                     desc="proxy configured in config file")
            except ccddb.AlreadyExistingError:
                proxy = Proxy.get_by_addr(db=self._db.conn,
                                          ip=ip,
                                          port=port)
            except Exception as e:
                raise Exception("Failed to create configured proxy: '%s'" %
                                str(e))

            self.proxies[proxy.pxid] = proxy
            chain.add_proxy(self._db.conn, proxy)

        # create connection group
        group = ConnectionGroup.create(self._db.conn,
                                       "group containing config file proxies")
        self.connection_groups[group.grpid] = group
        group.set_default(self._db.conn)
        group.add_chain(self._db.conn, chain, 0)

        return group

    def _create_superadmin(self):
        """ Create superadmin user. If already in database, get existing
            superadmin.
        """
        sa = None
        sa = ccdUser.User.create_fromname(self._db.conn,
                                          self.config.sa_name,
                                          self.config.sa_pwd,
                                          self.config.sa_mail,
                                          return_user=True)

        # delete superadmin information
        del(self.config.sa_name)
        del(self.config.sa_pwd)
        del(self.config.sa_mail)

        return sa

################################################################################
#                          start
################################################################################

    def start(self):
        """ Starts the ccd. Processes requests in a new thread. To terminate
            main process it kills alls subprocesses.
        """
        logger.info("start, pid:%s", os.getpid())

        while self.isAlive:
            try:
                r, _, _ = select.select([self.sock_in], [], [])
            except KeyboardInterrupt:
                self.isAlive = False
                break

            try:
                for s in r:
                    conn, addr = s.accept()
                    logger.debug("request from %s", addr)

                    if s == self.sock_in:
                        try:
                            if self.config.ssl_enabled:
                                logger.debug("connecting to %s via ssl.", str(addr))
                                conn = ssl.wrap_socket(conn,
                                                       server_side=True,
                                                       certfile=self.config.cert,
                                                       keyfile=self.config.cert_key,
                                                       ssl_version=self.config.ssl_version)
                            else:
                                logger.debug('ssl disabled')

                            #FIXME verification fails since getpeercert always
                            #returns None
#                            if not ccdSocket.validate_client_cert(
#                                            sock=conn,
#                                            fp=self.config.client_fingerprint):
#                                raise ssl.SSLError("Invalid client cert!")

                        except (ssl.SSLError, socket.error) as se:
                            logger.warning("Failed to wrap accepting socket into"
                                           " ssl: '%s'", str(se))
                            continue

                        logger.debug("processing secure connection to %s:%d.. ",
                                     addr[0], addr[1])
                        worker = threading.Thread(target=self._process,
                                                  args=(conn, addr, ))
                        worker.setDaemon(True)
                        worker.start()
            except Exception as e:
                logger.exception(e)
                print 'Error: connection to client lost: %s' % str(e)

        logger.info("terminating ccd..")
        ccddb.close(self._db.conn)

        with self.runningPlugins_lock:
            for _, item in self.runningPlugins.items():
                pid, _, name, s, _ = item
                try:
                    pgid = os.getpgid(pid)
                except OSError:
                    logger.warning("Faild to get pgid for pid %d", pid)
                    continue

                logger.debug("killing process group %d (%s)", pgid, name)
                os.killpg(pgid, signal.SIGKILL)

    def _process(self, sock, raddr=('0.0.0.0', 0)):
        """ Process the ccd requests. """
        tid = ctypes.CDLL('libc.so.6').syscall(186)
        logger.debug("processing session.. tid:%d, sock:%s", tid, sock)
        sid = 0
        # every request has its own db connection, so first we
        # connection to db
        self._db.conn = ccddb.connect()

        while True:
            try:
                r, _, _ = select.select([sock], [], [], 2.0)
            except KeyboardInterrupt:
                break

            if r:
                suc = ccdlib.OP_SUCCESS
                resp_t = None
                result = ""

                try:
                    req_t = ccdlib.recv(sock)
                    logger.debug("request:%s", req_t)
                    req_str = ccdlib.pkt2str(req_t)
                    op, sid, rid, cat, plg, gid, mth, _ = req_t
                except (socket.timeout, socket.error,
                        ccdlib.InvalidPacketError, ccdlib.EmptyException) as e:
                    logger.info('Connection to client %s:%d terminated: %s',
                                raddr[0], raddr[1], e)
                    break

                try:
                    ccdSession.verify_stages(self, sid, rid, op)
                except ccdErrors.SessionError as se:
                    # We catch exceptions here since we do not want to send
                    # any exception to the client. Therefore, we send an empty
                    # payload.
                    logger.warning("Failed to verify request('%s'):'%s'!",
                                   req_str, se)
                    suc = ccdlib.OP_FAILURE
                    result = ""
                    resp_t = suc, sid, rid, cat, plg, gid, mth, result
                    ccdlib.send(sock, resp_t)
                    continue

                try:
                    # process operation
                    result = self._process_operation(req_t, sock)
                except ccdErrors.PermissionDenied as pd:
                    logger.warning(pd)
                    suc = ccdlib.OP_PERMISSION_DENIED
                    result = ""
                except ccdErrors.NotFoundError as e:
                    suc = ccdlib.OP_NOT_FOUND
                    result = ""
                except ccdErrors.InputError as e:
                    suc = ccdlib.OP_INVALID_INPUT
                    result = ""
                except ccddb.AlreadyExistingError as e:
                    suc = ccdlib.OP_ALREADY_EXISTS
                    result = ""
                except ccdErrors.SessionEnd:
                    logger.debug("user is leaving")
                    resp_t = ccdlib.OP_SUCCESS, sid, rid, cat, plg, gid, mth, result
                    try:
                        ccdlib.send(sock, resp_t)
                    except:
                        # doesn't really matter to us anyway
                        logger.warning('Failed to send termination confirm to %s:%d',
                                       raddr[0], raddr[1])
                    break
                except ccdErrors.CcdError as ce:
                    logger.warning(ce)
                    suc = ccdlib.OP_FAILURE
                    result = str(ce)
                except Exception as err:
                    logger.error("Error while processing request:'%s' (%s)", err, req_str)
                    logger.exception(err)
                    suc = ccdlib.OP_FAILURE
                    result = 'Error while processing request (%s): ' % req_str
                    result += str(e)

                resp_t = suc, sid, rid, cat, plg, gid, mth, result
                try:
                    ccdlib.send(sock, resp_t)
                except Exception as e:
                    logger.error("Error sending %s to %s:%d: %s",
                                 resp_t, raddr[0], raddr[1], e)

        # invalidate session
        try:
            if sid:
                uid = self.get_user_and_workgroup(sid)[0].uid
                ccddb.delete_session_by_uid(self._db.conn, uid)
                ccdSession.invalidate_session(self, sid)
        except ccdErrors.InvalidSessionID:
            # if user is not authenticate, there is no session to invalidate
            pass

        # close db connection if request is over
        ccddb.close(self._db.conn)
        logger.debug("bye bye session")

    def _process_operation(self, req_t, sock):
        """
        Execute the operation requested by the user and return the result.

        input:
            req_t       tuple that represents the request
            sock        socket of the conversation

        output:
            result

        """
        op, sid, rid, cat, plg, _, mth, pld = req_t
        result = ""

        # login
        if (op == ccdlib.OP_LOGIN):
            result = self._doLogin(pld)

        elif (op == ccdlib.OP_LOGOUT):
            raise ccdErrors.SessionEnd

        # return categories of cat
        elif (op == ccdlib.OP_GETCAT):
            result = self._getCategories(sid, cat)

        # execute plugin
        elif (op == ccdlib.OP_EXEC) and (mth == ccdlib.MTH_EXEC):
            result = ccdProject.execute_plugin(self, sock, req_t)

        # kill plugin
        #FIXME request id
        elif (op == ccdlib.OP_KILL):
            ccdProject.kill_plugin(self, sock, req_t)

        # upload file
        elif (op == ccdlib.OP_UPLOAD):
            upload.upload_file(self, sid, plg, pld, mth)

        # download file
        elif (op == ccdlib.OP_DOWNLOAD):
            result = download.download_file(self, sid, plg, pld)

        # reload plugins
        elif (op == ccdlib.OP_RELOAD):
            setup.reload_plugins(self)

        # get root category
        elif (op == ccdlib.OP_GETROOTCAT):
            result = self._getRootCategory()

        # new proxy
        elif (op == ccdlib.OP_NEWPROXY):
            result = ccdProxy.create_proxy(self, sid, pld)

        # delete proxy
        elif (op == ccdlib.OP_DELPROXY):
            ccdProxy.del_proxy(self, sid, pld)

        # show proxy
        elif (op == ccdlib.OP_SHOWPROXY):
            result = ccdProxy.show_proxy(self, sid)

        # new proxy chain
        elif (op == ccdlib.OP_NEWPCHAIN):
            result = ccdProxyChain.create_proxy_chain(self, sid, pld)

        # set proxy chain
        elif (op == ccdlib.OP_FLUSHPCHAIN):
            ccdProxyChain.flush(self, sid, pld)

        # del proxy chain
        elif (op == ccdlib.OP_DELPCHAIN):
            ccdProxyChain.del_chain(self, sid, pld)

        # show proxy chain
        elif (op == ccdlib.OP_SHOWPCHAIN):
            result = ccdProxyChain.show_chain(self, sid)

        # new group
        elif (op == ccdlib.OP_NEWGROUP):
            result = ccdGroup.create_group(self, sid, pld)

        # show group
        elif (op == ccdlib.OP_SHOWGROUP):
            result = ccdGroup.show_group(self, sid)

        # flush group
        elif (op == ccdlib.OP_FLUSHGROUP):
            ccdGroup.flush(self, sid, pld)

        # del group
        elif (op == ccdlib.OP_DELGROUP):
            ccdGroup.del_group(self, sid, pld)

        # del group
        elif (op == ccdlib.OP_USEGROUP):
            ccdGroup.use_group(self, sid, pld)

        # get state
        elif (op == ccdlib.OP_GETSTATE):
            result = comm.getstate(self, sid)

        # register
        elif (op == ccdlib.OP_REGISTER):
            result = comm.register(self, sock, req_t)

        # unregister
        elif (op == ccdlib.OP_UNREGISTER):
            #comm.suspend(self, sid)
            comm.unregister(self, sid)

        # forward plugin io
        elif (op == ccdlib.OP_PLUGIN):
            session = self.get_session(sid)
            try:
                session.write_plugin_input(rid, plg, mth, pld)
            except ccdSession.EClosed as e:
                logger.info(e)

        # request id
        elif (op == ccdlib.OP_GETRID):
            result = ccdSession.get_rid(self, sid)

        # get home directory
        elif (op == ccdlib.OP_GETHOME):
            result = self._get_user_home_dir(sid, pld)

        # new workgroup
        elif (op == ccdlib.OP_NEWWGROUP):
            result = ccdWorkgroup.new_workgroup(self, sid, pld)

        # delete workgroup
        elif (op == ccdlib.OP_DELWGROUP):
            ccdWorkgroup.delete_workgroup(self, sid, pld)

        # update workgroup
        elif (op == ccdlib.OP_UPDATEWGROUP):
            ccdWorkgroup.update_workgroup(self, sid, pld)

        # add member to workgroup
        elif (op == ccdlib.OP_ADDWGROUPMEMBER):
            ccdWorkgroup.add_member(self, sid, pld)

        # remove member from workgroup
        elif (op == ccdlib.OP_DELWGROUPMEMBER):
            ccdWorkgroup.remove_member(self, sid, pld)

        # add plugin to workgroup
        elif (op == ccdlib.OP_ADDWGROUPPLG):
            ccdWorkgroup.add_plugin(self, sid, pld)

        # remove plugin from workgroup
        elif (op == ccdlib.OP_DELWGROUPPLG):
            ccdWorkgroup.remove_plugin(self, sid, pld)

        # show workgroups
        elif (op == ccdlib.OP_SHOWWGROUP):
            result = ccdWorkgroup.show_workgroups(self, sid, pld)

        # new project
        elif (op == ccdlib.OP_NEWPROJ):
            result = ccdProject.new_project(self, sid, pld)

        # delete project
        elif (op == ccdlib.OP_DELPROJ):
            ccdProject.delete_project(self, sid, pld)

        # update project
        elif (op == ccdlib.OP_UPDATEPROJ):
            ccdProject.update_project(self, sid, pld)

        # add member to project
        elif (op == ccdlib.OP_ADDPROJMEMBER):
            ccdProject.add_member(self, sid, pld)

        # remove member from project
        elif (op == ccdlib.OP_DELPROJMEMBER):
            ccdProject.remove_member(self, sid, pld)

        # select project
        elif (op == ccdlib.OP_SETPROJ):
            ccdProject.select(self, sid, pld)

        # get projects
        elif (op == ccdlib.OP_SHOWPROJ):
            result = ccdProject.show_projects(self, sid, pld)

        # add plugin to project
        elif (op == ccdlib.OP_ADDPROJPLG):
            ccdProject.add_plugin(self, sid, pld)

        # remove plugin from project
        elif (op == ccdlib.OP_DELPROJPLG):
            ccdProject.remove_plugin(self, sid, pld)

        # new user
        elif (op == ccdlib.OP_NEWUSER):
            result = ccdUser.new_user(self, sid, pld)

        # get user
        elif (op == ccdlib.OP_SHOWUSER):
            result = ccdUser.show_user(self, sid, pld)

        # del user
        elif (op == ccdlib.OP_DELUSER):
            ccdUser.delete_user(self, sid, pld)

        # update user
        elif (op == ccdlib.OP_UPDATEUSER):
            ccdUser.update_user(self, sid, pld)

        # update user password
        elif (op == ccdlib.OP_UPDATEUSERPWD):
            ccdUser.update_user_passwd(self, sid, pld)

        # data
        elif (op == ccdlib.OP_REPORT):
            result = ccdProject.data(self, sid, pld, mth)

        ## report
        #elif (op == ccdlib.OP_REPORT):
        #    result = ccdProject.data(self, sid, pld, ccdlib.MTH_SAVE)

        else:
            logger.warning("Unkown command: %x", op)

        return result

################################################################################
#                              User
################################################################################
    def _assign_user_a_session(self, user):
        """ returns a new session object and adds it to cache """
        s = ccdSession.Session.from_user(self._db.conn, user)
        self.sessions[s.sid] = s
        return s

    def _doLogin(self, pld):
        """
        communication flow for login process. Create session id and link it
        to user id. If an old session id existed, replace it.

        input:
            pld     payload of the ccd message

         """
        logger.debug("executing login")
        try:
            user_req = pld["user"]
            pwd_req = pld["pwd"]
        except KeyError:
            raise Exception("Unproper payload format.")

        logger.debug("checking database for user %s", user_req)
        users = ccddb.getusers(self._db.conn, user_req, pwd_req)
        logger.debug("found users:%s", str(users))

        if len(users) < 1:
            raise ccdErrors.PermissionDenied("Unknown user")
        elif len(users) > 1:
            raise Exception("Multiple users found with that "
                            "username-password-combination. This should not "
                            "happen!")

        # from here on, the user is authenticated
        user = users[0]
        userid = user[0]
        username = user[1]
        try:
            self._createUserDir(username)
        except Exception as e:
            logger.debug("creating user dir failed:'%s'", e)

        u = ccdUser.User.by_uid(self._db.conn, uid=userid)

        # remove old session from cache
        #for sid, s in self.sessions.items():
        #    if s.user.name == username:
        #        self.sessions[sid].stop_forwarding()
        #        del(self.sessions[sid])
        #        break

        # create new session and store it
        s = self._assign_user_a_session(u)

        try:
            gid = ProxyChainSocket._current_connection_group.grpid
        except:
            gid = "0"

        # build response
        response = dict(
            uid=userid,
            #TODO role id of user within current wgroup
            sid=s.sid,
            gid=gid
        )

        logger.info("User '%s' successfully authenticated. sid:%s",
                    u.name, s.sid)

        return response

    def _get_user_home_dir(self, sid, pld):
        """
        return the users home directory. if the user provided a plugin id, just
        return content of the corresponding plugin directory.

        input:
            sid     session id
            pld     payload

        output
            directory content

        """
        logger.debug("returning users home dir:%s", pld)
        result = dict()

        # do return subdirectories too
        try:
            recursive = pld["recursive"]
        except KeyError:
            recursive = False

        # do not resolve to names
        try:
            no_names = pld["no_names"]
        except KeyError:
            no_names = False

        # get only content of specified plugins
        try:
            plugins = pld["plugins"]
        except KeyError:
            plugins = []

        session = self.get_session(sid)
        content = session.user.get_home_directory(
            self._db.conn,
            no_names=no_names,
            recursive=recursive
        )
        logger.debug("plugins:%s", plugins)

        # if a list of plugin ids provided, only return content
        # only return content of the corresponding directories
        if plugins:
            user_content = content[session.user.name]["content"]
            for directory, infos in user_content.items():
                if directory in plugins:
                    result[directory] = infos
        else:
            result = content

        return result

    def _create_dir(self, path):
        """ Function creates user directory. """
        logger.debug("creating dir %s", path)
        if os.path.exists(path):
            raise Exception("'%s' already exists" % path)

        os.mkdir(path)
        os.chown(path, self.config.runAsUid, self.config.runAsGid)

    def _createUserDir(self, user):
        """
        creates the user directory and links the shared directory

        input:
            user    name of the user to create the dir for

        """
        logger.debug("creating user directory for user %s", user)
        path = os.path.join(self.config.userdir, user)

        # create directory
        try:
            self._create_dir(path)
        except Exception as e:
            logger.warning("Error while creating user dir:%s", e)

        # link shared dir
        logger.debug("creating symlink")
        source = self.config.shared_directory
        name_of_shared_dir = os.path.split(source)[-1]
        name = os.path.join(path, name_of_shared_dir)
        os.symlink(source, name)
        logger.debug("changing owner of %s", name)
        os.lchown(name, self.config.runAsUid, self.config.runAsGid)

        logger.debug("done")

################################################################################
#                          Plugin
################################################################################

    def validate_pluginid(self, plg_id):
        return plugin.validate_id(plg_id)

    def _getCategories(self, sid, cat_id):
        """ return all subcategories of a category
            with the given id. Return plugins only if the are
            linked to the current project.

            input:
                sid     session id
                cat_id  category identifier

            output:
                content the category's content

        """
        content = []
        subcats = []
        proj = self._get_project(sid)
        db = self._db.conn

        for category in self.categories:
            if category.id == cat_id:
                subcats = category.listContent()
                break
        else:
            raise Exception("Got invalid category id!")

        # get user and workgroup

        user, workgroup = self.get_user_and_workgroup(sid)
#        workgroup = user.get_workgroup(db)
        for sc in subcats:
            is_plugin = isinstance(sc, ccdClasses.Plugin)

            if not self._superadmin(sid):
                logger.debug("user is not superadmin")

                if is_plugin:
                    logger.debug("element is plugin")

                    if proj and proj.has_plugin(db, sc.id):
                        # plugin is added to project, hence access allowed
                        pass
                    elif (workgroup.is_allowed(
                        db,
                        user=user,
                        access=ccddb.ACCESS_READ | ccddb.ACCESS_ADD)
                            and workgroup.has_plugin(db, sc.id)):
                        # admin is allowed to see id, although it is not
                        # added to any project. hence access allowed.
                        pass
                    else:
                        logger.debug("plugin is not accessible")
                        continue

            # get connection group associated with the plugin
            if is_plugin and proj:
                grpid = ccddb.get_group_by_projectplugin(db,
                                                         plg_id=sc.id,
                                                         pid=proj.pid)
            else:
                grpid = None

            # add subcat/plugin
            content.append(dict(
                id=sc.id,
                help=getattr(sc, "help", None),
                name=sc.name,
                isplugin=is_plugin,
                conngroup=grpid
            ))

        return content

    def _getRootCategory(self):
        """ return root category """
        logger.debug("getRootCategory")
        return dict(id=self.rootCategory.id, name=self.rootCategory.name)

    def _superadmin(self, sid):
        """
        return True if the current session id is owned
        by the superadmin
        """
        sa = False
        if (self.get_user_and_workgroup(sid)[0].uid == self.superadmin.uid):
            sa = True
        return sa
################################################################################
#                          Session
################################################################################

    def _get_project(self, sid):
        """ return the associated project """
        proj = None

        s = self.get_session(sid)
        if s:
            proj = s.project
        else:
            raise Exception("Invalid session!")

        return proj

    def get_user_and_workgroup(self, sid):
        """ return a user and the workgroup that is associated with the sid """

        # get user we work with
        user = self.get_session(sid).user

        # if the user is superadmin, there is no workgroup to grep. if user is
        # classical user, get his workgroup
        if not user.uid == self.superadmin.uid:
            wg = user.get_workgroup(self._db.conn)

        # for workgroups return none
        else:
            wg = None

        return user, wg

    def get_session(self, sid):
        """ return session object from cache """
        try:
            return self.sessions[sid]
        except KeyError:
            raise InvalidSessionID(sid)


def activate_venv(venv_dir):

    if not os.path.exists(venv_dir):
        print "%s does not exists" % venv_dir
        return

    activate_this_file = os.path.join(venv_dir, "bin/activate_this.py")
    print 'activating virtual environment %s' % activate_this_file
    execfile(activate_this_file, dict(__file__=activate_this_file))
    if hasattr(sys, 'real_prefix'):
        print 'Virtual environment activated'

if __name__ == "__main__":

    import os
    import sys
    if not os.getuid() == 0:
        print("ccd needs to be executed as root!")
        sys.exit(2)

    import argparse
    parser = argparse.ArgumentParser(description="ccd server application")
    parser.add_argument("--bind",
                        help="address to bind server to")
    parser.add_argument("--daemon",
                        action="store_true",
                        help="start server as daemon")
    parser.add_argument("--config",
                        default=CONFIG,
                        help="path to the configuration file to load")
    parser.add_argument("--plugin",
                        help="folder that contains the plugins")
    parser.add_argument("--userdir",
                        help="folger that contains the user directory")
    parser.add_argument("--venv",
                        help="overwrite virtual environment folder from config")

    args = parser.parse_args()

    if args.venv:
        activate_venv(args.venv)
    else:
        import ConfigParser
        try:
            config = ConfigParser.RawConfigParser()
            config.read(args.config)
            venv_dir = config.get("Virtualenv", "Path")
            activate_venv(venv_dir)
        except:
            pass

    import logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # channel that prints to console
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    logging.getLogger("connection.ccdSession").setLevel(logging.DEBUG)
    logging.getLogger("connection.ccdProxy").setLevel(logging.WARNING)
    logging.getLogger("ccd.connection.ccdlib").setLevel(logging.WARNING)
    logging.getLogger("connection.ccdProxyChain").setLevel(logging.DEBUG)
    logging.getLogger("connection.ccdGroup").setLevel(logging.DEBUG)

    logging.getLogger("plugins.comm").setLevel(logging.DEBUG)
    logging.getLogger("plugins.plugin").setLevel(logging.DEBUG)
    logging.getLogger("plugins.setup").setLevel(logging.DEBUG)
    logging.getLogger("plugins.fdForwarder").setLevel(logging.DEBUG)

    logging.getLogger("database.ccddb").setLevel(logging.INFO)
    logging.getLogger("database.ccdProject").setLevel(logging.DEBUG)
    logging.getLogger("database.ccdWorkgroup").setLevel(logging.DEBUG)
    logging.getLogger("database.ccdUser").setLevel(logging.DEBUG)

    logging.getLogger("ctools.csockslib").setLevel(logging.DEBUG)
    logging.getLogger("files.upload").setLevel(logging.DEBUG)
    logging.getLogger("files.download").setLevel(logging.DEBUG)

    from sqlalchemy.exc import OperationalError as sqlOperationalError
    from connection.ccdProxyChain import ProxyChainSocket
    from connection.ccdProxyChain import ProxyChain
    from connection.ccdGroup import ConnectionGroup
    from database.ccdErrors import InvalidSessionID
    from connection.ccdProxy import Proxy
    from connection import ccdProxyChain
    from config.read import read_config
    from connection import ccdSession
    from database import ccdWorkgroup
    from connection import ccdSocket
    from connection import ccdProxy
    from connection import ccdGroup
    from database import ccdProject
    from database import ccdErrors
    from connection import ccdlib
    from ctools import cdaemonise
    from database import ccdUser
    from database import ccddb
    from files import download
    from plugins import plugin
    from plugins import setup
    from plugins import comm
    from ctools import cUtil
    from files import upload
    import logging.handlers
    import ccdClasses
    import threading
    import logging
    import os.path
    import signal
    import socket
    import ctypes
    import select
    import stat
    import ssl

    if args.bind:
        args.bind = args.bind.split(":")
        if len(args.bind) == 2:
            args.bind = (args.bind[0], int(args.bind))
        else:
            sys.stderr.write("Invalid address to bind to.")

    ccd = Ccd(daemon=args.daemon, addr=args.bind, config_fn=args.config)
    ccd.start()
