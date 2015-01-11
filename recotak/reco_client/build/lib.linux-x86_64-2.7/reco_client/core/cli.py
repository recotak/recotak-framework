""" implements the client's command line interface """

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

import reco_client.remote.category as category
import reco_client.remote.workgroup as wg
import reco_client.remote.plugin as plg
import reco_client.remote.proxy as pxy
import reco_client.remote.group as conn_group
import reco_client.remote.proxychain as proxychain
import reco_client.connection.ccdlib as ccdlib
from window import showWindows
from window import killWindow
import errors
import argcomplete_patched as argcomplete
import argparse
import readline
import sys
import shlex
import logging
logger = logging.getLogger("client.%s" % __name__)


###PROXY##########################
###PXORYGROUP#####################
###PROXYCHAIN#####################

###WORKGROUP######################
###PROJECT########################
###USER###########################

###CATEGORY#######################
###FILE###########################
###PLUGIN#########################
###WINDOW#########################

# local commands
EXPORT = "export"
DATA = "data"
FILE = "file"
APPEND = "append"
REMOVE = "remove"
EXIT = "exit"
CHANGEDIR = "cd"
LIST = "list"
LISTDIR = "ls"
HOME = "home"
EXEC = "exec"
SHOW = "show"
USE = "use"
WIN = "win"
UPLOAD = "upload"
DOWNLOAD = "download"
KILL = "kill"
RELOAD = "reload"
SHELL = "!"
FIND = "find"
PLG = "plgs"
NETWORK = "network"
CHAIN = "chain"
NEW = "new"
ADD = "add"
GROUP = "group"
DEL = "del"
WGROUP = "wgroup"
MEMBER = "member"
MOD = "mod"
PROJECT = "project"
USER = "user"
SET = "set"
ADDPLG = "addplg"
DELPLG = "delplg"
PWD = "password"
PLUGIN = "plugin"
REPORT = "report"
VIEW = "view"
SAVE = "save"
PROXY = "proxy"
FLUSH = "flush"
HELP = "help"

FORCE_t = ("-f", "--force")
COMMANDS = {}

def _unpack_(args):
    # get all member attributes and pass to func
    arguments = args.__dict__
    del(arguments["func"])
    return arguments


class MyCompleter(argcomplete.CompletionFinder):
    """ a voodoo class doing magic things """

    def __init__(self,
                 argument_parser=None,
                 always_complete_options=True,
                 exclude=None,
                 validator=None):
        super(MyCompleter, self).__init__(
            argument_parser=argument_parser,
            always_complete_options=always_complete_options,
            exclude=exclude,
            validator=validator
        )

    def complete(self, text, state):
        lb = readline.get_line_buffer()
        text = lb

        if state == 0:
            cword_prequote, cword_prefix, cword_suffix, comp_words, first_colon_pos = \
                argcomplete.split_line(text)
            comp_words.insert(0, sys.argv[0])
            self.matches = super(MyCompleter, self)._get_completions(
                comp_words,
                cword_prefix,
                cword_prequote,
                first_colon_pos
            )
            self.matches.append(None)
        if state < len(self.matches):
            return self.matches[state]
        else:
            return None


class Cli(object):
    """
    Represents the command line interface of the client. The cli works with
    subparsers and subsubparsers.

    """

    def __init__(self, client):

        # the argument parser used for processing ccd cli commands
        # most of the commands have sub commands and arguments. all
        # commands have in common, that they have a function
        # 'process_input' that is passed the user's input:
        # https://docs.python.org/2/library/argparse.html#sub-commands
        parser = argparse.ArgumentParser(prog="", add_help=False)
        self._parser = parser
        self.init_parser(parser, client)

        dummy_parser = argparse.ArgumentParser(prog="")
        self.init_parser(dummy_parser, client)
        self.completer = MyCompleter(argument_parser=dummy_parser)
        #self.completer = argcomplete.CompletionFinder(argument_parser=self._parser)

    def init_parser(self, parser, client):
        subparsers = parser.add_subparsers(help="sub-command help")

        ############################ help ###############################
        helparg = subparsers.add_parser(HELP,
                                        help="print this help. if a plugin "
                                             "name is passed, print the "
                                             "plugin's help.")
        helparg.add_argument("plugin",
                             help="name of the plugin to get help of",
                             nargs="?",
                             default=None)
        helparg.set_defaults(func=lambda plugin:
                             plg.print_help(client,
                                            plugin,
                                            parser.format_help()))

        ######################## change dir #############################
        cd = subparsers.add_parser(CHANGEDIR,
                                   help="Change directory")
        cd.add_argument("dst",
                        help="relative pathname of the directory to change to"
                        ).completer = client.changedir_complete
        cd.set_defaults(func=lambda dst: category.changedir(client, dst))

        ######################### list dir ##############################
        ls = subparsers.add_parser(LISTDIR,
                                   help="list plugins and sub directories")
        ls.add_argument("-l",
                        action="store_true",
                        help="show content in list format")
        ls.add_argument("-r",
                        action="store_true",
                        help="load content recursively")
        ls.set_defaults(func=lambda r, l: category.listdirToStr(client, r=r, l=l))

        ######################## execute plg #############################
        class ExecArgAction(argparse.Action):
            def __init__(self, option_strings, dest, nargs=None, **kwargs):
                #if nargs is not None:
                #    raise ValueError("nargs not allowed")
                super(ExecArgAction, self).__init__(option_strings, dest, nargs, **kwargs)

            def __call__(self, parser, namespace, values, option_string=None):
                args = shlex.split(' '.join(values))
                setattr(namespace, self.dest, args)

        exc = subparsers.add_parser(EXEC,
                                    help="execute plugin")
        exc.add_argument("plugin",
                         help="name of the plugin to execute"
                         ).completer = client.execute_complete
        exc.add_argument("args",
                         help="the plugin's arguments",
                         action=ExecArgAction,
                         nargs=argparse.REMAINDER)
        exc.set_defaults(func=lambda plugin, args:
                         plg.execute(client, plugin, args))

        ######################## window parser############################
        win = subparsers.add_parser(WIN,
                                    help="window management")
        win_subparsers = win.add_subparsers(
            title="window management",
            description="A windows is some kind of local representation "
                        "of a remote plugin. It show the current state "
                        "of a plugin (whether it's running or not) and "
                        "prints its output to stdio.",
            help="sub command help")
        win_show = win_subparsers.add_parser(SHOW,
                                             help="Shows all windows.")
        win_show.add_argument("wid", type=int, nargs='?', help="window id")
        win_show.set_defaults(func=lambda wid: showWindows(client, wid))

        win_kill = win_subparsers.add_parser(
            KILL,
            help="Terminates a remote plugin and closes the "
                 "window. If the window is closed, there is "
                 "no way to access the plugin anymore.")
        win_kill.add_argument("wid", type=int, help="window id"
                              ).completer = client.winid_complete
        win_kill.add_argument("-f", "--force",
                              action="store_true",
                              help="kill remote plugin (sends a SIGKILL)")
        win_kill.set_defaults(func=lambda wid, force: killWindow(client,
                                                                 wid,
                                                                 force))

        ######################## file parser ############################
        fil = subparsers.add_parser(FILE,
                                    help="file management")
        fil_subparsers = fil.add_subparsers(
            title="file management",
            description="A file can be uploaded/downloaded to/from "
                        "ccd. An uploaded file might be referenced "
                        "in other contexts (e.g. during execution "
                        "of a plugin). Files are located in the users "
                        "home directory or in a shared directory that "
                        "is accessible for all users.",
            help="sub command help")

        # upload
        fil_upload = fil_subparsers.add_parser(UPLOAD,
                                               help="upload a file")
        fil_upload.add_argument("filename",
                                help="local path to the file to upload"
                                ).completer = client.filename_complete
        fil_upload.add_argument("dst",
                                help="Destination where to put the file. "
                                     "There "
                                     "are three destinations: a) '$shared' "
                                     "to upload sth into the shared dir b) "
                                     "'$home' to upload sth into the home "
                                     "dir or c) a plugin id to upload the "
                                     "file into a plugin's directory."
                                )
        fil_upload.add_argument("-f", "--force",
                                help="Force overwriting of existing files.",
                                action="store_true")
        fil_upload.set_defaults(func=client.upload_to_ccd)

        # download
        fil_download = fil_subparsers.add_parser(
            DOWNLOAD,
            help="download a file")
        fil_download.add_argument("filename",
                                  help="file to download"
                                  ).completer = client.filename_complete
        fil_download.add_argument("dst",
                                  help="destination where to put file")
        fil_download.add_argument("-f", "--force",
                                  help="Force overwriting of existing files.",
                                  action="store_true")
        fil_download.set_defaults(func=client.download_from_ccd)

        # list
        fil_show = fil_subparsers.add_parser(SHOW,
                                             help="list all files")
        fil_show.add_argument("-r",
                              help="show files recursively",
                              action="store_true")
        fil_show.add_argument("-n",
                              help="show plugin ids instead of names",
                              action="store_true")
        fil_show.add_argument("plugins",
                              help="a list of plugins to get the content from",
                              default=set(),
                              nargs="?")
        fil_show.set_defaults(func=client._get_users_home_dir)

        ######################## proxy parser ############################
        proxy = subparsers.add_parser(PROXY,
                                      help="proxy configuration")
        proxy_subparsers = proxy.add_subparsers(
            title="proxy management",
            description="A proxy consists of a address and a description "
                        "(or alias). Proxies can be linked to chains "
                        "(see chain help).",
            help="sub command help")
        # show
        proxy_show = proxy_subparsers.add_parser(SHOW,
                                                 help="show all proxies")
        proxy_show.set_defaults(func=lambda: pxy.print_proxies(client))

        # add
        proxy_add = proxy_subparsers.add_parser(ADD,
                                                help="add a new proxy")
        proxy_add.add_argument("protocol",
                               nargs="?",
                               default="s4",
                               choices=["s4"],
                               help="addressable via protocol. For now, only "
                                    "socks 4 is working."
                               )
        proxy_add.add_argument("ip", help="the ip of the proxy")
        proxy_add.add_argument("port", help="the port the proxy listens on",
                               type=int)
        proxy_add.add_argument("description",
                               help="an alternative name or short description"
                               " of the proxy")
        proxy_add.set_defaults(func=lambda protocol, ip, port, description:
                               pxy.new_proxy(client,
                                             protocol, ip, port,
                                             description))

        # del
        proxy_del = proxy_subparsers.add_parser(DEL,
                                                help="delete a proxy")
        proxy_del.add_argument("proxyid",
                               type=int,
                               help="id of the proxy to delete"
                               ).completer = client.proxyid_complete
        proxy_del.set_defaults(func=lambda proxyid: pxy.del_proxy(client,
                                                                  proxyid))

        ######################## chain parser ############################
        chain = subparsers.add_parser(CHAIN,
                                      help="chain configuration")
        chain_subparsers = chain.add_subparsers(
            title="chain management",
            description="A proxy chain consists of one or more proxies. "
                        "The plugins' traffic is routed transparently over"
                        " proxy chains. Multiple chains from a connection "
                        " group (see group help).",
            help="sub command help")
        # show
        chain_show = chain_subparsers.add_parser(SHOW,
                                                 help="show all chains")
        chain_show.set_defaults(func=lambda: proxychain.print_chains(client))

        # add
        chain_add = chain_subparsers.add_parser(ADD,
                                                help="add a new proxy chain")
        chain_add.add_argument("description",
                               help="an alternative name or short description")
        chain_add.set_defaults(func=lambda description:
                               proxychain.new_chain(client, description))

        # del
        chain_del = chain_subparsers.add_parser(DEL,
                                                help="delete a proxy chain")
        chain_del.add_argument("chainid",
                               help="the id of the chain to delete"
                               ).completer = client.chainid_complete
        chain_del.set_defaults(func=lambda chainid:
                               proxychain.del_chain(client, chainid))

        # add proxy
        chain_append = chain_subparsers.add_parser(
            APPEND,
            help="append a new proxy to chain"
        )
        chain_append.add_argument("chainid",
                                  help="id of the chain to append to"
                                  ).completer = client.chainid_complete
        chain_append.add_argument("proxyid",
                                  help="id of the proxy to append",
                                  type=int
                                  ).completer = client.proxyid_complete
        chain_append.set_defaults(func=lambda chainid, proxyid:
                                  proxychain.add_proxy_to_chain(client,
                                                                chainid,
                                                                proxyid))

        # remove proxy
        chain_remove = chain_subparsers.add_parser(
            REMOVE,
            help="remove a proxy from a proxy chain"
        )
        chain_remove.add_argument("chainid",
                                  help="id of the chain to remove from"
                                  ).completer = client.chainid_complete
        chain_remove.add_argument("proxyid",
                                  help="id of the proxy to remove",
                                  type=int
                                  ).completer = client.proxyid_complete
        chain_remove.set_defaults(func=lambda chainid, proxyid:
                                  proxychain.del_proxy_from_chain(client,
                                                                  chainid,
                                                                  proxyid))

        ######################## group parser ############################
        cgroup = subparsers.add_parser(GROUP,
                                       help="connection group configuration")
        cgroup_subparsers = cgroup.add_subparsers(
            title="connection group management",
            description="A connection group consists of one or more proxy "
                        "chains, assigned with a priority."
                        "The plugins' traffic is routed transparently over"
                        " proxy chains. Which chain is chosen depends on "
                        "the scheduling algorithm (random, round robin, "
                        "priority).",
            help="sub command help")
        # show
        cgroup_show = cgroup_subparsers.add_parser(
            SHOW,
            help="show all connection grups")
        cgroup_show.set_defaults(func=lambda: conn_group.print_groups(client))

        # add
        cgroup_add = cgroup_subparsers.add_parser(
            ADD,
            help="add a new connection group.")
        cgroup_add.add_argument("description",
                                help="an alternative name or short description")
        cgroup_add.set_defaults(func=lambda description:
                                conn_group.new_group(client, description))

        # del
        cgroup_del = cgroup_subparsers.add_parser(DEL,
                                                  help="delete a connection group")
        cgroup_del.add_argument("groupid",
                                help="the id of the connection group to delete"
                                ).completer = client.groupid_complete
        cgroup_del.set_defaults(func=lambda groupid:
                                conn_group.del_group(client, groupid))

        # add chain
        cgroup_append = cgroup_subparsers.add_parser(
            APPEND,
            help="append a new chain to a connection group"
        )
        cgroup_append.add_argument("groupid",
                                   help="id of the connection group to append to"
                                   ).completer = client.groupid_complete
        cgroup_append.add_argument("chainid",
                                   help="id of the chain to append"
                                   ).completer = client.chainid_complete
        cgroup_append.add_argument("priority",
                                   help="priority of the chain",
                                   type=int)
        cgroup_append.set_defaults(func=lambda groupid, chainid, priority:
                                   conn_group.add_chain_to_group(client,
                                                                 groupid,
                                                                 chainid,
                                                                 priority))

        # remove chain
        cgroup_remove = cgroup_subparsers.add_parser(
            REMOVE,
            help="remove a chain from a connection group"
        )
        cgroup_remove.add_argument("groupid",
                                   help="id of the connection group to remove "
                                   "from"
                                   ).completer = client.groupid_complete
        cgroup_remove.add_argument("chainid",
                                   help="id of the chain to remove"
                                   ).completer = client.chainid_complete
        cgroup_remove.set_defaults(func=lambda groupid, chainid:
                                   conn_group.del_chain_from_group(client,
                                                                   groupid,
                                                                   chainid))

        # use connection group
        cgroup_use = cgroup_subparsers.add_parser(
            USE,
            help="Activate a connection group. There are "
                 "basically two types of group usage: 1) "
                 "groups act as default group for the hole"
                 " ccd and 2) a group is assigned to a "
                 "plugin/project combination. The project "
                 "id is a member variable of the client, "
                 "so no arguments are needed here."
        )
        cgroup_use.add_argument("groupid",
                                help="id of the connection group to activate"
                                ).completer = client.groupid_complete

        cgroup_use.add_argument("pluginid",
                                nargs="?",
                                default=None,
                                help="id of the plugin to activate"
                                ).completer = client.pluginid_complete

        def _use_group(groupid, pluginid):
            conn_group.use_group(client, groupid, pluginid)
            category.listdir.update_happened = True

        cgroup_use.set_defaults(func=_use_group)

        ######################## data parser ############################
        data = subparsers.add_parser(DATA,
                                     help="data export functionality")
        data_subparsers = data.add_subparsers(
            title="data export foo",
            description="data export description",
            help="sub command help")

        # data view --fields=<fieldname> --tables=<tablename>
        # <fieldname> = <tablename> = all
        data_view = data_subparsers.add_parser(
            VIEW,
            help="view plugin results")
        data_view.add_argument("--tables", nargs="*", default=[],
                               help="tables to get information from")
        data_view.add_argument("--columns", nargs="*", default=[],
                               help="table columns to be included")
        data_view.set_defaults(func=client.view_data)

        data_show = data_subparsers.add_parser(
            SHOW,
            help="show meta information about "
                 "plugin results")
        data_show.add_argument("--tables", nargs="*", default=[],
                               help="show fields of these tables")
        data_show.add_argument("--columns", nargs="*", default=[],
                               help="show table names containing these fields")
        data_show.set_defaults(func=client.show_data)

        # data view --tables
        # data view --tables table1 table2 -> []

        # data export --fields=<fieldname> --tables=<tablename>
        data_export = data_subparsers.add_parser(
            EXPORT,
            help="save results to file")
        data_export.add_argument("--tables", nargs="*", default=[],
                                 help="names of tables to export")
        data_export.add_argument("--columns", nargs="*", default=[],
                                 help="names of table columns to export (csv only)")
        data_export.add_argument("--filename",
                                 default="$home/report",
                                 help="filename to save data to")
        data_export.add_argument("--output",
                                 default="csv",
                                 #choices=["pdf", "csv", "odt"],
                                 choices=["pdf", "csv"],
                                 help="the report's output format")
        data_export.add_argument("-l",
                                 default="de",
                                 choices=["de", "en"],
                                 help="language to generate the report in (pdf only)",
                                 dest="lang")
        data_export.add_argument("--group_by",
                                 default="",
                                 help="names the column to group by. format is "
                                      "of type tablename:column,"
                                      "tablename2:column (pdf only)")
        data_export.set_defaults(func=client.save_data)

        # data export all (export csv)
        # data export all --pdf (export pdf)

        ######################## wgroup parser ############################
        wgroup = subparsers.add_parser(WGROUP,
                                       help="workgroup management")
        wgroup_subparsers = wgroup.add_subparsers(
            title="workgroup management",
            description="Workgroups are some kind set with users as "
                        "elements. Every user must be member of at least "
                        "one workgroup.",
            help="sub command help")

        # add
        wgroup_add = wgroup_subparsers.add_parser(ADD,
                                                  help="add a new workgroup")
        wgroup_add.add_argument("name", help="name of the workgroup")
        wgroup_add.add_argument("--description",
                                default="workgroup",
                                help="description of the workgroup")
        wgroup_add.set_defaults(func=lambda name, description: wg.new_workgroup(client,
                                name, description=description))

        # del
        wgroup_del = wgroup_subparsers.add_parser(DEL,
                                                  help="delete a new workgroup")
        wgroup_del.add_argument("workgroupid",
                                type=int,
                                help="id of the workgroup"
                                ).completer = client.wgroupid_complete
        wgroup_del.set_defaults(func=lambda workgroupid:
                                wg.delete_workgroup(client, workgroupid))

        # show
        wgroup_show = wgroup_subparsers.add_parser(SHOW,
                                                   help="show all workgroups")
        wgroup_show.add_argument("workgroupid",
                                 type=int,
                                 nargs="?",
                                 default=-1,
                                 help="id of the workgroup")
        wgroup_show.set_defaults(func=lambda workgroupid:
                                 wg.show_workgroups(client, workgroupid))

        # MOD
        wgroup_mod = wgroup_subparsers.add_parser(MOD,
                                                  help="manipulate properties of an existing "
                                                       "workgroup")

        wgroup_mod.add_argument("workgroupid",
                                type=int,
                                help="id of the workgroup to manipulate"
                                ).completer = client.wgroupid_complete

        wgroup_mod.add_argument("--name",
                                help="the name to change to")
        wgroup_mod.set_defaults(func=lambda workgroupid, name:
                                wg.update_workgroup(client, workgroupid, name))

        # add user to workgroup
        wgroup_user = wgroup_subparsers.add_parser(
            USER,
            help="manage users for a given workgroup")
        wgroup_user_subparser = wgroup_user.add_subparsers(
            title="workgroup-user-management",
            description="Every user must be in at least one"
                        " workgroup.",
            help="manage users of a given workgroup")

        wgroup_user_add = wgroup_user_subparser.add_parser(
            ADD,
            help="add users to a workgroup")
        wgroup_user_add.add_argument("workgroupid", type=int,
                                     help="id of the workgroup"
                                     ).completer = client.wgroupid_complete
        wgroup_user_add.add_argument("userid",
                                     type=int,
                                     help="id of the user to add"
                                     ).completer = client.userid_complete
        wgroup_user_add.add_argument("roleid",
                                     choices=[1, 2, 3],
                                     type=int,
                                     default=2,
                                     nargs="?",
                                     help="id of the user's role")
        wgroup_user_add.set_defaults(func=lambda workgroupid,
                                     userid,
                                     roleid:
                                     wg.workgroup_add_member(client,
                                                             workgroupid,
                                                             userid,
                                                             roleid))
        # del user from workgroup
        wgroup_user_del = wgroup_user_subparser.add_parser(
            DEL,
            help="delete a user from workgroup")
        wgroup_user_del.add_argument("workgroupid",
                                     type=int,
                                     help="id of the workgroup"
                                     ).completer = client.wgroupid_complete
        wgroup_user_del.add_argument("userid",
                                     type=int,
                                     help="id of the user to add"
                                     ).completer = client.userid_complete
        wgroup_user_del.set_defaults(func=lambda workgroupid,
                                     userid:
                                     wg.workgroup_remove_member(client,
                                                                workgroupid,
                                                                userid))

        # show users of workgroup
        wgroup_user_show = wgroup_user_subparser.add_parser(
            SHOW,
            help="show all users that are member of a workgroup")
        wgroup_user_show.add_argument("workgroupid",
                                      type=int,
                                      help="id of the workgroup"
                                      ).completer = client.wgroupid_complete
        wgroup_user_show.set_defaults(func=lambda workgroupid:
                                      wg.show_user_in_workgroup(client,
                                                                workgroupid))

        # add plugin to workgroup
        wgroup_plugin = wgroup_subparsers.add_parser(
            PLUGIN,
            help="manage plugins for a given workgroup")
        wgroup_plugin_subparser = wgroup_plugin.add_subparsers(
            title="workgroup-plugin-management",
            description="Users are only able to interact "
                        "with plugins that are assigned to"
                        " their workgroups.",
            help="manage plugins of a given workgroup")

        wgroup_plugin_add = wgroup_plugin_subparser.add_parser(
            ADD,
            help="add plugin to a workgroup")
        wgroup_plugin_add.add_argument("workgroupid",
                                       type=int,
                                       help="id of the workgroup"
                                       ).completer = client.wgroupid_complete
        wgroup_plugin_add.add_argument("pluginid",
                                       help="id of the plugin"
                                       ).completer = client.pluginid_complete
        wgroup_plugin_add.set_defaults(func=lambda workgroupid, pluginid:
                                       wg.workgroup_add_plugin(client,
                                                               workgroupid,
                                                               pluginid))

        # del plugin from workgroup
        wgroup_plugin_del = wgroup_plugin_subparser.add_parser(
            DEL,
            help="delete a plugin from a workgroup")
        wgroup_plugin_del.add_argument(
            "workgroupid",
            type=int,
            help="id of the workgroup"
        ).completer = client.wgroupid_complete
        wgroup_plugin_del.add_argument("pluginid",
                                       help="id of the plugin to delete"
                                       ).completer = client.pluginid_complete
        wgroup_plugin_del.set_defaults(func=lambda workgroupid, pluginid:
                                       wg.workgroup_remove_plugin(client,
                                                                  workgroupid,
                                                                  pluginid))

        ######################## project parser ############################
        project = subparsers.add_parser(PROJECT,
                                        help="project management")
        project_subparsers = project.add_subparsers(
            title="project management",
            description="Projects are the context in which plugins are "
                        "executed. Users from different workgroups might "
                        "work together in one project. Though, users and "
                        "plugins can be added to a project.",
            help="sub command help")

        # add
        project_add = project_subparsers.add_parser(ADD,
                                                    help="add a new project")
        project_add.add_argument("name", help="name of the project")
        project_add.add_argument("--ptype", help="type of the project",
                                 choices=[1, 2, 3], default=2, type=int)
        project_add.add_argument("--description",
                                 default="",
                                 help="description of the project")
        project_add.set_defaults(func=client.new_project)

        # del
        project_del = project_subparsers.add_parser(DEL,
                                                    help="delete a project")
        project_del.add_argument("projectid",
                                 help="id of the project to delete")
        project_del.set_defaults(func=client.delete_project)

        # mod
        project_mod = project_subparsers.add_parser(
            MOD,
            help="manipulate properties of an existing project")
        project_mod.add_argument("projectid",
                                 help="id of the project to manipulate")
        project_mod.add_argument("--name",
                                 help="the name to change to")
        project_mod.set_defaults(func=client.update_project)

        # set
        project_set = project_subparsers.add_parser(
            SET,
            help="set project to working in")
        project_set.add_argument("projectid",
                                 type=int,
                                 help="id of the project to work in ")
        project_set.set_defaults(func=client.set_project)

        # show
        project_show = project_subparsers.add_parser(
            SHOW,
            help="set project information")
        project_show.add_argument("projectid",
                                  nargs="?",
                                  type=int,
                                  default=0,
                                  help="id of the project")
        project_show.set_defaults(func=client.show_projects)

        # add user to project
        project_user = project_subparsers.add_parser(
            USER,
            help="manage users for a given project")
        project_user_subparser = project_user.add_subparsers(
            title="project-user-management",
            description="Users of different workgroups "
                        "might work together in one "
                        "project. ",
            help="manage users of a given project")

        project_user_add = project_user_subparser.add_parser(
            ADD,
            help="add users to a project")
        project_user_add.add_argument("projectid",
                                      help="id of the project")
        project_user_add.add_argument("userid", type=int,
                                      help="id of the user to add")
        project_user_add.add_argument("roleid", choices=[1, 2, 3], type=int,
                                      default=2, nargs="?",
                                      help="id of the user's role")
        project_user_add.set_defaults(func=client.project_add_member)

        # del user from project
        project_user_del = project_user_subparser.add_parser(
            DEL,
            help="delete a user from project")
        project_user_del.add_argument("projectid", type=int,
                                      help="id of the project")
        project_user_del.add_argument("userid", type=int,
                                      help="id of the user to add")
        project_user_del.set_defaults(func=client.project_remove_member)

        # show user from project
        project_user_show = project_user_subparser.add_parser(
            SHOW,
            help="show users from project")
        project_user_show.add_argument("projectid", type=int,
                                       help="id of the project")
        project_user_show.set_defaults(func=client.show_user_in_project)

        # add plugin to project
        project_plugin = project_subparsers.add_parser(
            PLUGIN,
            help="manage plugins for a given project")
        project_plugin_subparser = project_plugin.add_subparsers(
            title="project-plugin-management",
            description="Users are only able to interact "
                        "with plugins that are assigned to"
                        " their project.",
            help="manage plugins of a given project")

        project_plugin_add = project_plugin_subparser.add_parser(
            ADD,
            help="add plugin to a project")
        project_plugin_add.add_argument("projectid",
                                        help="id of the project")
        project_plugin_add.add_argument("pluginid",
                                        help="id of the plugin")
        project_plugin_add.set_defaults(func=client.project_add_plugin)

        # del plugin from workgroup
        project_plugin_del = project_plugin_subparser.add_parser(
            DEL,
            help="delete a plugin from a project")
        project_plugin_del.add_argument("projectid",
                                        help="id of the project")
        project_plugin_del.add_argument("pluginid",
                                        help="id of the plugin to delete")
        project_plugin_del.set_defaults(func=client.project_remove_plugin)

        ######################## user parser ############################
        user = subparsers.add_parser(USER, help="user management")
        user_subparsers = user.add_subparsers(
            title="user management",
            description="tba ",
            help="sub command help")

        # add
        user_add = user_subparsers.add_parser(ADD, help="add a new user")
        user_add.add_argument("name", help="name of the user")
        user_add.add_argument("mail", help="mail address of the user")
        user_add.add_argument("--description",
                              help="some descriptive words about the user",
                              default="")
        user_add.add_argument("password", help="login password for the user")
        user_add.set_defaults(func=client.new_user)

        # del
        user_del = user_subparsers.add_parser(DEL,
                                              help="delete an existing user")
        user_del.add_argument("userid",
                              type=int,
                              help="id of the user to delete").completer = client.userid_complete
        user_del.set_defaults(func=client.del_user)

        # show
        user_show = user_subparsers.add_parser(SHOW,
                                               help="show existing user")
        user_show.add_argument("userid",
                               nargs="?",
                               type=int,
                               default=None,
                               help="id of the user to delete")
        user_show.set_defaults(func=client.show_user)

        # modify
        user_mod = user_subparsers.add_parser(MOD,
                                              help="modify an existing user")
        user_mod.add_argument("userid",
                              type=int,
                              help="id of the user to delete")
        user_mod.add_argument("--name", help="name of the user")
        user_mod.add_argument("--mail", help="mail address of the user")
        user_mod.set_defaults(func=client.update_user)

        # change password
        user_password = user_subparsers.add_parser(PWD,
                                                   help="change a user's password")
        user_password.add_argument("userid",
                                   type=int,
                                   help="id of the user to delete")
        user_password.add_argument("old", help="the user's old password")
        user_password.add_argument("new", help="the user's new password")
        user_password.set_defaults(func=client.update_user_pwd)

        ######################## plugin parser ############################
        plugin = subparsers.add_parser(PLUGIN,
                                       help="plugin management")
        plugin_subparsers = plugin.add_subparsers(
            title="plugin management",
            help="sub command help")

        # show
        plugin_show = plugin_subparsers.add_parser(SHOW,
                                                   help="show all plugins")
        plugin_show.add_argument("-l",
                                 action="store_true",
                                 help="show content in list format")

        plugin_show.set_defaults(func=client.showPlugins)

    def _unpack_(self, args):
        """ get all member attributes and pass to func """
        arguments = args.__dict__
        del(arguments["func"])
        return arguments

    def process(self, argv):
        """
        process the actual user input. it determines the corresponding
        subparser and calls the defined method that was given during
        initialisation.

        input:
            argv    array of user provided arguments

        """

        try:
            args, extra = self._parser.parse_known_args(argv)
            return args.func(**self._unpack_(args))

        except SystemExit:
            # on '-h' the argparser makes a sys.exit. so prevent that here
            # raise InputError()
            pass
        #except (InputError, PermissionDenied) as e:
        #    logger.exception(e)
        except errors.ClientError as e:
            logger.exception(e)
            if e.request:
                logger.warning('Request: %s', ccdlib.pkt2str(e.request))
            if e.response:
                logger.warning('Response: %s', ccdlib.pkt2str(e.response))
            print str(e)
        except Exception as e:
            logger.exception(e)
            print 'something went wrong ...'
