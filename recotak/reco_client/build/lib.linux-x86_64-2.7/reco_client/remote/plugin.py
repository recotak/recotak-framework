"""
plugin stub
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

A RemotePlugin is the stub of the ccd plugin. The stub basically provides a
container to send OP_EXEC commands to ccd.

"""

import reco_client.connection.comm as comm
import reco_client.core as core

#from reco_client.connection.comm import comm.sendpacket
#from reco_client.connection.comm import comm.ccdlib
#from reco_client.core import core.window

class RemotePlugin(object):
    """
    the plugin container that handles plugin operations

    a remote plugin has the following attributes:

        id          id of the plugin
        name        name of the plugin. usually ends with .plg
        grpid       every plugin can be associated with a separate connection
                    group. as a consequence, the portscan.plg might use another
                    connection group that subdns.plg
        categories  every plugin is associated with a list of plugins
        interactive a flag, that indicates whether the plugin accepts user
                    input
        session     client session object
        help        string to contain plugin help. is printed in case of
                    '> help <plugin name>'

    """
    EXTENSION = ".plg"

    def __init__(self,
                 id,
                 name,
                 session,
                 grpid=None,
                 help="",
                 categories=[]):
        self.id = id
        self.name = name
        self.grpid = grpid
        self.categories = categories
        self.interactive = False
        self.session = session
        self.help = help

    def execute(self, args):
        """
        execute plugin

        input:
            args    plugin arguments sent to ccd

        output:
            rid, pld    request id and response payload

        """
        resp_t = comm.sendpacket(self.session,
                                 op=comm.ccdlib.OP_EXEC,
                                 mth=comm.ccdlib.MTH_EXEC,
                                 plg=self.id,
                                 pld=args)

        rid = resp_t[2]
        pld = resp_t[-1]

        return rid, pld

def execute(ses, plugin, args):
    """
    Function searches plugin and executes it. It also opens core.window to print
    plugin output.

    input:
        plugin      name of the plugin to execute
        args        list of arguments to pass to plugin

    output:
        returns id of newly created core.window

    """
    if len(ses._win_by_wid) >= core.window.MAX_WINDOWS:
        msg = "There are already max (%d) windows." % core.window.MAX_WINDOWS
        return msg

    plg = ses._findPlugin(plugin)
    if not plg:
        return "No such plugin, my friend!"

    # send request
    rid, pld = plg.execute(args)

    op = comm.ccdlib.OP_PLUGIN
    sid = ses.sid
    cat = 0
    gid = ses.current_group_gid
    mth = comm.ccdlib.MTH_OUTPUT
    plg_id = plg.id

    req_t = (op, sid, rid, cat, plg_id, gid, mth, pld)

    # create core.window to recv plugins result
    name = "%s %s" % (plg.name, " ".join(args))
    win = core.window.createWindow(ses, name, req_t)
    win.use()

    return win.wid

def print_help(ses, plugin, alt=""):
    """
    prints the plugins name on stdout

    input:
        ses         ccd sesion
        plugin      name of the plugin to print out
        alt         if no plugin provided, print alt text

    """
    if not plugin:
        print(alt)
        return

    plg = ses._findPlugin(plugin)
    if not plg:
        return "No such plugin, my friend!"

    print(plg.help)
