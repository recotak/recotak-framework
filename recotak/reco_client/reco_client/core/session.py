""" contains a session object that represents a connection to the ccd """

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

import reco_client.connection as conn
import reco_client.connection.comm as comm
import reco_client.remote.category as category
import reco_client.remote.workgroup as workgroup
import reco_client.remote.proxy as pxy
import reco_client.remote.group as pxygrp
import reco_client.remote.proxychain as pxychain
#import reco_client.core.errors as errors
from validate import *
import window
import errors
import cli

from getpass import getpass
from socket import socket
import readline
import ConfigParser
import os.path
import logging
import base64
import types
import sys
import os
import re

# logging
logger = logging.getLogger("client.%s" % __name__)
logger.setLevel(logging.DEBUG)

def die(msg, e=None, code=1):
    if e is not None:
        logger.exception(e)
    print 'fatal: %s' % msg
    sys.exit(code)

def _get_user_creds():
    uname = raw_input("username: ")
    pword = conn.ccdCrypto.hashPassword(getpass("password: "))
    return uname, pword

class Session(object):
    """ A session is bound to a session id. Each session caches
        its plugins.
    """

    def __init__(self, addr, account=None, config="./config/client.conf"):

        logger.info('Starting session: addr %s, config %s', addr, config)

        self.changedir = category.changedir
        self.raddr = addr

        self.account = account
        self.sid = "0"
        self.project = None

        # connection groups
        self.connection_groups = {}
        self.current_group_gid = "0"

        # proxy chains
        self.proxychains = {}

        self.current_category = category.RemoteCategory(0, "dummy category", self)
        self.root_category = None
        self.history = []

        # get config options
        self._readConfig(config)

        # pass the server's cert fingerprint to out socket initialisation
        # function
        window._get_socket.cert_fingerprint = self._cert_fingerprint

        # the dictionary to hold windows as values. accessable via
        # rid as keys. a window's output and input buffers are stored
        # in the connections dict on creation
        self._win_by_wid = {}
        self._win_by_rid = {}
        self._win_used = None

        try:
            self.sock = window._get_socket(self, self.raddr, secure=self._ssl_enabled)
        except Exception as e:
            die('connection to ccd at %s:%d failed' % self.raddr, e=e, code=2)

        # proxy cache
        self.proxies = {}

        # add commandline interface
        self.cli = cli.Cli(self)
        readline.set_completer(self.cli.completer.complete)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" ")

    def _readConfig(self, config):
        """ read configuration file """
        c = ConfigParser.RawConfigParser()
        c.read(config)

        self._cert_fingerprint = c.get("Connection", "ccd_cert_fingerprint")
        self._cert = c.get("Connection", "cert")
        self._cert_key = c.get("Connection", "key")
        self._ssl_version = c.getint("Connection", "ssl_version")
        self._ssl_enabled = c.getboolean("Connection", "ssl_enabled")

    def toRootDir(self):
        """ sends a request to get the id of root category. sets root cat. """

        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_GETROOTCAT)

        _id = resp_t[-1]["id"]
        _name = resp_t[-1]["name"]
        self.root_category = category.RemoteCategory(id=_id, name=_name, session=self)
        self.current_category = self.root_category
        self.history = []

    def resume(self):

        """ request current state of plugins and create windows """

        logger.debug("getting state of plugins that I once started")

        # get current running plugins and fds
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_GETSTATE)

        # delete cached windows
        window.reset_all_win(self)

        # recreate all windows
        for running in resp_t[-1]:
            try:
                op = conn.ccdlib.OP_PLUGIN
                sid = self.sid
                rid = running["rid"]
                cat = 0
                plg_id = running["plg_id"]
                gid = self.current_group_gid
                mth = conn.ccdlib.MTH_OUTPUT

                req_t = (op, sid, rid, cat, plg_id, gid, mth, resp_t[-1])

                win = window.createWindow(self,
                                          winname=running["command"],
                                          req_t=req_t)

                if not running["state"]:
                    win.set_state(2)
                else:
                    win.set_state(running["state"])

            except KeyError:
                raise Exception("Got invalid response from server!")

    def authenticateUser(self):
        """ authenticate user. If no creds are passed via command line param,
            request user input. Returns true in case of success.
        """
        authenticated = False

        while True:
            try:
                if not self.account:
                    username, password = _get_user_creds()
                else:
                    username = self.account[0]
                    password = self.account[1]

            except (EOFError, KeyboardInterrupt):
                logger.debug("KeyboardInterrupt occured while "
                             "authentication.")
                sys.exit(2)

            if username and password:
                try:
                    resp = self._dologin(username, password)
                except:
                    resp = False

                if resp:
                    try:
                        self.sid = resp["sid"]
                        self.current_group_gid = resp["gid"]
                    except KeyError:
                        logger.error("Invalid json format!")
                        raise Exception("Invalid json format!")

                    authenticated = True
                    break

                else:
                    print("Authentication failed.")
                    break

        self.account = username,
        return authenticated

    def _dologin(self, username, password):
        pld = {"user": username, "pwd": password}
        resp_t = comm.sendpacket(self,
                                 op=conn.ccdlib.OP_LOGIN,
                                 pld=pld)
        return resp_t[-1]

    def _get_users_home_dir(self, r, n, plugins):
        """
        print the users home directory content

        input:
            r       also print content of subdirs
            n       do not resolve dir's ids to names
            plugins a list of plugin names to get the content from

        output:
            a string containing the subdirectory

        """
        str_home_dir = ""

        try:
            plugins = self._get_plugin_ids(plugins)
        except:
            raise Exception("passed invalid plugin!")

        pld = dict(recursive=r,
                   no_names=n,
                   plugins=self._get_plugin_ids(plugins))

        logger.debug("pld:%s", pld)
        home_dir = comm.sendpacket(self,
                                   op=conn.ccdlib.OP_GETHOME,
                                   pld=pld)[-1]

        def _print_content(name, content):
            output = []
            line = ""
            COLOR_BLUE = "\033[94m"
            COLOR_END = "\033[0m"

            if not isinstance(content, types.DictType):
                return []

            try:
                # do we have a directory or not
                is_dir = content["d"]
            except KeyError:
                is_dir = False

            try:
                # the name might be given in a special
                # value.
                alt_name = content["name"]
            except KeyError:
                alt_name = ""

            # if have a dir, colour the directory name
            if is_dir:
                line += COLOR_BLUE

            if alt_name:
                line += "%s (%s)" % (name, alt_name)
            else:
                line += name

            # stop coloring
            if is_dir:
                line += COLOR_END

            line += "\n"

            # add name to output
            output.append(line)

            # print the content of the directory
            subcontent = []

            if is_dir:
                try:
                    for k, v in content["content"].items():
                        subcontent.extend(_print_content(k, v))
                except KeyError:
                    pass

            # now we indent the directory's content
            for line in subcontent:
                output.append("\t%s" % line)

            return output

        for key, value in home_dir.items():
            for line in _print_content(key, value):
                str_home_dir += line

        print(str_home_dir)

    def new_project(self, name, ptype, description=""):
        """ create a new project """
        validate_name(name)
        validate_description(description)

        pld = dict(name=name, tid=ptype, description=description)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_NEWPROJ, pld=pld)
        return resp_t[-1]

    def delete_project(self, projectid):
        """ delete a project """
        pld = dict(pid=projectid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_DELPROJ, pld=pld)
        return resp_t[-1]

    def update_project(self, projectid, name):
        """ update an existing project """
        pld = dict(pid=projectid, name=name)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_UPDATEPROJ, pld=pld)
        return resp_t[-1]

    def project_add_member(self, projectid, userid, roleid):
        """ add a member to project """
        pld = dict(pid=projectid, uid=userid, role_id=roleid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_ADDPROJMEMBER, pld=pld)
        return resp_t[-1]

    def project_remove_member(self, projectid, userid):
        """ remove a member from project """
        pld = dict(pid=projectid, uid=userid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_DELPROJMEMBER, pld=pld)
        return resp_t[-1]

    def project_add_plugin(self, projectid, pluginid):
        """ add a plugin to project """
        validate_pluginid(pluginid)
        pld = dict(pid=projectid, plg_id=pluginid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_ADDPROJPLG, pld=pld)
        return resp_t[-1]

    def project_remove_plugin(self, projectid, pluginid):
        """ remove a plugin from project """
        validate_pluginid(pluginid)
        pld = dict(pid=projectid, plg_id=pluginid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_DELPROJPLG, pld=pld)
        return resp_t[-1]

    def new_user(self, name, mail, password, description=""):
        """ create a new user """
        MAX_LEN_PASSWORD = 255

        enc_password = conn.ccdCrypto.hashPassword(password)
        if len(enc_password) > MAX_LEN_PASSWORD:
            raise errors.InputError("Password exceeds limit of %d chars." %
                                    MAX_LEN_PASSWORD)

        validate_name(name)
        validate_mail(mail)
        validate_description(description)

        pld = dict(name=name,
                   mail=mail,
                   password=enc_password,
                   description=description)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_NEWUSER, pld=pld)
        return resp_t[-1]

    def show_user(self, userid=None):
        """ get user information """
        p = ""

        pld = dict(uid=userid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_SHOWUSER, pld=pld)

        for u in resp_t[-1]:
            p += "user %d:\n" % u["uid"]
            for k, v in u.items():
                p += "\t%s:%s\n" % (k, v)
        return p

    def show_user_in_project(self, projectid):
        """ get user information """
        p = ""
        pld = dict(pid=projectid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_SHOWUSER, pld=pld)

        for u in resp_t[-1]:
            p += "user %d:\n" % u["uid"]
            for k, v in u.items():
                p += "\t%s:%s\n" % (k, v)
        return p

    def del_user(self, userid):
        """ create a new user """
        pld = dict(uid=userid)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_DELUSER, pld=pld)
        return resp_t[-1]

    def update_user(self, userid, name, mail):
        """ create a new user """
        pld = dict(uid=userid, name=name, mail=mail)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_UPDATEUSER, pld=pld)
        return resp_t[-1]

    def update_user_pwd(self, userid, old, new):
        """ create a new user """
        old = conn.ccdCrypto.hashPassword(old)
        new = conn.ccdCrypto.hashPassword(new)
        pld = dict(uid=userid, old=old, new=new)
        resp_t = comm.sendpacket(self, op=conn.ccdlib.OP_UPDATEUSERPWD, pld=pld)
        return resp_t[-1]

    def reloadPlugins(self):
        """ requests a server plugin reload """
        comm.sendpacket(self, op=conn.ccdlib.OP_RELOAD)
        self.toRootDir()
        return "Plugins successfully reloaded."

    def get_all_plugin_ids(self):
        if not self.root_category:
            return []
        content = category.listdir(self,
                                   cat=self.root_category,
                                   showCat=False,
                                   r=True,
                                   l=True)
        plgs = [p for p in content if p.endswith(".plg")]
        return [p.split()[0] for p in plgs]

    def get_all_plugin_names(self):
        if not self.root_category:
            return []
        content = category.listdir(self,
                                   cat=self.root_category,
                                   showCat=False,
                                   r=True,
                                   l=True)
        plgs = [p for p in content if p.endswith(".plg")]
        return [p.split()[1] for p in plgs]

    def showPlugins(self, l=False):
        """ return all plugins """
        if not self.root_category:
            return "In order to show plugins, a project must be set!"

        plgs = category.listdir(self,
                                cat=self.root_category,
                                showCat=False,
                                r=True,
                                l=l)
        return "\n".join(sorted(p for p in plgs if p.endswith(".plg")))

    def _validFilename(self, fn):
        """ Function checks whether file name contains allowed chars. """
        valid = re.compile("^[a-zA-Z0-9_]*$")
        return True if valid.match(fn) is not None else False

    def download_from_ccd(self, filename, dst, force):
        """
        download file from ccd

        input:
            filename        path of the file to download
            dst             destination, where to store file at

        """
        SYM_SHARED = "$shared"
        SYM_HOME = "$home"

        if not validate_filename(dst):
            raise errors.InputError(message='Invalid path %s' % dst)

        if self.project:
            proj_dir = './outdir/project_%d/' % self.project
        else:
            proj_dir = '/tmp/'

        logger.info('Using project dir %s', proj_dir)

        # source, aka file to upload
        path = filename.split("/")
        root = path[0]
        logger.info('Path: %s', path)

        # location where to download from
        if root == SYM_SHARED:
            logger.info('From shared dir')
            subpath = "/".join(path[1:])
            name = os.path.join(SYM_SHARED, subpath)
            plg_id = "0"

        elif root == SYM_HOME:
            logger.info('From home dir')
            subpath = "/".join(path[1:])
            name = os.path.join(SYM_HOME, subpath)
            plg_id = "0"

        else:
            logger.info('From plg dir')
            plg = self._findPlugin(root)
            if not plg:
                raise errors.InvalidServerPath(message=root)
            logger.info('Found Plugin: %s', plg)
            plg_id = plg.id

            name = "/".join(path[1:])

        logger.info('Dwlnd src: %s', name)

        # get file
        pld = dict(fn=name)
        resp = comm.sendpacket(self,
                               op=conn.ccdlib.OP_DOWNLOAD,
                               plg=plg_id,
                               pld=pld)[-1]

        try:
            string = resp["content"]
            blob = base64.decodestring(string)
        except KeyError:
            raise Exception("Invalid payload format!")

        # store file
        if not os.path.exists(proj_dir):
            os.makedirs(proj_dir)
        # dst = "/tmp/%s" % fn
        dst = os.path.join(proj_dir, dst)
        with open(dst, "w+b") as f:
            f.write(blob)

        print("File successfully download to %s" % dst)

    def upload_to_ccd(self, filename, dst, force):
        """
        Function uploads file to ccd

        input:
            filename        path of the file to upload
            dst             destination, where to upload file to
            force           force overwriting of existing files

        """
        SYM_SHARED = "$shared"
        SYM_HOME = "$home"

        logger.debug("filename=%s, dst=%s, force=%s", filename, dst, force)

        # source, aka file to upload
        if not os.path.exists(filename):
            print("No such file.")
            return

        name = os.path.split(filename)[1]
        logger.debug('filename: %s', name)

        # destination, aka location to upload to
        if dst == SYM_SHARED:
            logger.debug('Uploading to shared')
            name = os.path.join(SYM_SHARED, name)
            plg_id = "0"

        elif dst == SYM_HOME:
            logger.debug('Uploading to home')
            name = os.path.join(SYM_HOME, name)
            plg_id = "0"

        else:
            logger.debug('Uploading to plugin')
            plg = self._findPlugin(dst)
            if not plg:
                raise errors.InvalidServerPath(message=dst)
                #raise Exception("No such plugin. Either user '$shared' "
                #                "or a valid plugin name.")
            logger.debug('Located plugin: %s', plg)
            plg_id = plg.id

        logger.debug('filename: %s', name)

        try:
            blob = open(filename, "r+b").read()
            pld = dict(fn=name, content=base64.encodestring(blob))

            #resp_t = comm.sendpacket(
            comm.sendpacket(
                self,
                op=conn.ccdlib.OP_UPLOAD,
                mth=conn.ccdlib.MTH_FORCE if force else conn.ccdlib.MTH_NOP,
                plg=plg_id,
                pld=pld
            )

        except Exception as e:
            print(str(e))
            return

        print("File successfully uploaded.")

    def _get_plugin_ids(self, names):
        """
        returns a list of ids to the corresponding plugins

        input:
            names   list of plugin names

        output
            ids     list of corresponding ids

        """
        ids = set()

        for name in names:
            plg = self._findPlugin(name)
            ids.add(plg.id)

        return list(ids)

    def _findPlugin(self, name):

        """
        find plugin by name
        """

        found = None

        if not self.current_category:
            logger.warning('Category not set')
            return

        for plg in category.listplugins(self, cat=self.current_category):
            if name == plg.name or name + '.plg' == plg.name or name == plg.id:
                found = plg
                break

        return found

###############################################################################
#                          save_data
###############################################################################

    def save_data(self, columns=[], tables=[], filename='', output='', group_by='', lang=''):
        """ view information from project database """

        if (tables or columns) and output == 'pdf':
            print('Warning: pdf format does currently not support table/column'
                  'selection')

        tables_str = ",".join(tables)
        columns_str = ",".join(columns)

        resp = comm.sendpacket(self, op=conn.ccdlib.OP_REPORT, mth=conn.ccdlib.MTH_SAVE, pld={
            'pid': self.project,
            'columns': columns_str,
            'tables': tables_str,
            'filename': filename,
            'group_by': group_by,
            'fmt': output
        })
        print repr(resp)
        if resp[0] != conn.ccdlib.OP_SUCCESS:
            print('Error while saving information from database')
        else:
            print('data saved as %s' % resp[-1])

###############################################################################
#                          show_data
###############################################################################

    def show_data(self, columns=[], tables=[]):
        """ show available information from project database """
        logger.debug("showing columns=%s, tables=%s", columns, tables)

        tables_str = ",".join(tables)
        columns_str = ",".join(columns)

        resp = comm.sendpacket(self, op=conn.ccdlib.OP_REPORT, mth=conn.ccdlib.MTH_INFO, pld={
            'pid': self.project,
            'columns': columns_str,
            'tables': tables_str,
        })
        if resp[0] != conn.ccdlib.OP_SUCCESS:
            print('Error while viewing information from database')
        else:
            return resp[-1]

###############################################################################
#                          view_data
###############################################################################

    def view_data(self, columns=[], tables=[]):
        """ view information from project database """
        logger.debug("viewing columns=%s, tables=%s", columns, tables)

        tables_str = ",".join(tables)
        columns_str = ",".join(columns)

        resp = comm.sendpacket(self, op=conn.ccdlib.OP_REPORT, mth=conn.ccdlib.MTH_VIEW, pld={
            'pid': self.project,
            'columns': columns_str,
            'tables': tables_str,
        })
        if resp[0] != conn.ccdlib.OP_SUCCESS:
            print('Error while viewing information from database')
        else:
            return resp[-1]

###############################################################################
#                           report
###############################################################################

    def getReport(self, fmt, filename, template):
        """ get database report in specified format [pdf, tex, csv] """

        resp = comm.sendpacket(self, op=conn.ccdlib.OP_REPORT, mth=conn.ccdlib.MTH_NOP, pld={
            'fmt': fmt,
            'filename': filename,
            'template': template,
            'pid': self.project,
            'uid': 2
        })
        if resp[0] == conn.ccdlib.OP_SUCCESS:
            print('Report saved as %s' % resp[-1])
        else:
            print('Error while generating Report')

###############################################################################
#                           projects
###############################################################################

    def show_projects(self, projectid="0"):
        """
        return a list of projects, the user is in. If pid is 0, we get the
        projects the user is joined currently. Though the ccd response is a
        list of projects.

        input:
            pid         project id to get information from

        output:
            result    returns a string containg the information

        """
        result = ""

        if projectid == "all":
            pld = dict(pid="")
        elif projectid:
            pld = dict(pid=projectid)
        else:
            pld = ""

        resp_t  = comm.sendpacket(self, op=conn.ccdlib.OP_SHOWPROJ, pld=pld)
        for project in resp_t[-1]:
            result += "project %d:\n" % project["pid"]
            for k, v in project.items():
                result += "\t%s:%s\n" % (k, v)

        return result

    def set_project(self, projectid):
        """ the user must select a project """
        logger.debug('Setting project %d' % projectid)
        pld = dict(pid=projectid)
        comm.sendpacket(self, op=conn.ccdlib.OP_SETPROJ, pld=pld)

        self.project = projectid
        self.toRootDir()
        self.resume()

    def getCurrentGroup(self):
        """ return a string that represents the current working group """
        return self.current_group_gid

    def close(self):
        """ close session """

        comm.sendpacket(self, op=conn.ccdlib.OP_LOGOUT)

        if isinstance(self.sock, socket):
            self.sock.close()

    #################################################################
    # window
    #################################################################

    def get_win_by_rid(self, rid):
        """
        returns a window that is associated with the corresponding request id.
        If not window found, raises a NotFoundError

        input:
            rid     request id

        output:
            win     returns the window

        """
        try:
            win = self._win_by_rid[rid]
        except KeyError:
            raise errors.NotFoundError(message="No window for request id %s!" % str(rid))
        return win

    #################################################################
    # completer
    #################################################################

    def userid_complete(self, prefix, **kwargs):
        pld = dict(uid=None)
        users = comm.sendpacket(self, op=conn.ccdlib.OP_SHOWUSER, pld=pld)[-1]
        return (str(v['uid']) for v in users if str(v['uid']).startswith(prefix))

    def wgroupid_complete(self, prefix, **kwargs):
        wgroups = workgroup.get_workgroups(self, "")
        wids = []
        if wgroups:
            for wg in wgroups:
                try:
                    wids.append(str(wg['wid']))
                except KeyError:
                    pass
        return (v for v in wids if v.startswith(prefix))

    def proxyid_complete(self, prefix, **kwargs):
        pxy.updateProxyList(self)
        return (v for v in map(str, self.proxies.keys()) if v.startswith(prefix))

    def chainid_complete(self, prefix, **kwargs):
        pxychain.updateProxyChainList(self)
        return (v for v in map(str, self.proxychains.keys()) if v.startswith(prefix))

    def groupid_complete(self, prefix, **kwargs):
        pxygrp.updateConnGroupList(self)
        return (v for v in map(str, self.connection_groups.keys()) if v.startswith(prefix))

    def pluginid_complete(self, prefix, **kwargs):
        ids = self.get_all_plugin_ids()
        return (v for v in ids if v.startswith(prefix))

    def winid_complete(self, prefix, **kwargs):
        return (v for v in map(str, self._win_by_wid.keys()) if v.startswith(prefix))

    def fs_listdir(self, root):
        res = []
        for name in os.category.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def filename_complete(self, prefix, **kwargs):
        path = prefix
        if not path:
            return self.fs_category.listdir('.')
        dirname, rest = os.path.split(path)
        #print 'dirname %s' % repr(dirname)
        #print 'rest %s' % repr(rest)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
               for p in self.fs_category.listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            #print '\nres: %s' % repr(res)
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self.fs_category.listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def execute_complete(self, prefix, **kwargs):
        content = category.listdir(self, cat=self.current_category, showCat=False)
        return (v for v in content if v.startswith(prefix))

    def changedir_complete(self, prefix, **kwargs):
        content = category.listdir(self, cat=self.current_category, showPlg=False)
        return (v for v in content if v.startswith(prefix))

    #################################################################

    def start(self, projectid=None, interactive=True):
        """ get user input and build package """

        if not self.authenticateUser():
            sys.exit(2)

        print("You're authenticated.")

        if projectid:
            try:
                self.set_project(projectid)
            except errors.PermissionDenied as e:
                #logger.exception(e)
                print 'Permission denied to set project %d' % projectid
                sys.exit(1)
            except Exception as e:
                #logger.exception(e)
                print 'Can not init project %d' % projectid
                sys.exit(1)

        pxy.updateProxyList(self)
        pxygrp.updateConnGroupList(self)
        pxychain.updateProxyChainList(self)

        if not interactive:
            return

        while True:
            try:
                cwd = "/".join(c.name for c in self.history)
                userinput = raw_input("{cwd}> ".format(cwd=cwd))

                if not userinput:
                    continue

                # exit
                if userinput == cli.EXIT:
                    break

                # shell commands
                elif userinput.startswith(cli.SHELL):
                    os.system(userinput[1:])
                    continue

                # parse other commands
                res = self.cli.process(userinput.split())
                if res:
                    print(res)
                continue

            except (EOFError, KeyboardInterrupt):
                break
            except ClientError as e:
                print str(e)
            except Exception as e:
                print(e)
                continue

        print("shutting down..")
        self.close()
