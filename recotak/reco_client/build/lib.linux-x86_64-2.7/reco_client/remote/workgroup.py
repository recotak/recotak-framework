"""
contains everything that has to do with workgroups (like creating, editing,
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
deleting). mostly works via sending network packets to ccd and evaluating
response.

"""

import reco_client.core.validate as validate
import reco_client.connection.comm as comm
import logging
logger = logging.getLogger("client.%s" % __name__)

def new_workgroup(session, name, description=""):
    """
    create a new workgroup

    input:
        session     client session
        name        name of the workgroup
        description descriptive words

    output:
        payload of server response. in case of success workgroup id

    """
    validate.validate_name(name)
    validate.validate_description(description)

    pld = dict(name=name, description=description)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_NEWWGROUP, pld=pld)
    return resp_t[-1]

def delete_workgroup(session, workgroupid):
    """
    delete a workgroup

    input:
        session         client session
        workgroupid     id of the workgroup to delete

    output:
        payload of server response

    """
    # verify that workgroup exists

    pld = dict(wid=workgroupid)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_DELWGROUP, pld=pld)
    return resp_t[-1]

def get_workgroups(session, workgroupid):
    """
    return the list of existing workgroups

    input:
        session     client session
        workgroupid workgroup

    output:
        result  string to contain the requested information

    """

    if workgroupid == "all":
        pld = ""
    elif workgroupid:
        pld = dict(wid=workgroupid)
    else:
        pld = ""

    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_SHOWWGROUP, pld=pld)

    return resp_t[-1]

def show_workgroups(session, workgroupid):
    """
    print a list of existing workgroups

    input:
        session client session
        wid     workgroup

    output:
        string that contains workgroup information

    """

    if workgroupid < 0:
        workgroupid = 'all'

    workgrps = get_workgroups(session, workgroupid)
    result = ''

    for wg in workgrps:
        for k, v in wg.items():
            result += "\t%s:%s" % (k, v)
        result += "\n"

    return result

def update_workgroup(session, workgroupid, name):
    """
    update an existing workgroup

    input:
        session         client session
        workgroupid     id of the workgroup to update
        name            new name to set

    output:
        server response payload

    """
    validate.validate_name(name)
    pld = dict(wid=workgroupid, name=name)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_UPDATEWGROUP, pld=pld)
    return resp_t[-1]

def workgroup_add_plugin(session, workgroupid, pluginid):
    """
    add a plugin to workgroup

    input:
        session         client session
        workgroupid     id of the workgroup to update
        pluginid        id of the plugin to add

    output:
        payload of server response

    """
    validate.validate_pluginid(pluginid)
    pld = dict(wid=workgroupid, plg_id=pluginid)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_ADDWGROUPPLG, pld=pld)
    return resp_t[-1]

def workgroup_remove_plugin(session, workgroupid, pluginid):
    """
    remove a plugin from workgroup

    input:
        session         client session
        workgroupid     id of the workgroup to update
        pluginid        id of the plugin to remove

    output:
        payload of server response

    """
    validate.validate_pluginid(pluginid)
    pld = dict(wid=workgroupid, plg_id=pluginid)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_DELWGROUPPLG, pld=pld)
    return resp_t[-1]

def workgroup_add_member(session, workgroupid, userid, roleid):
    """
    add a member to workgroup

    input:
        session         client session
        workgroupid     id of the workgroup to update
        userid          id of the plugin to add
        roleid          id of the user's role.

    output:
        payload of server response

    """
    logger.debug("adding member(uid:%s) to workgroup(wid:%s)", userid,
                 workgroupid)
    pld = dict(wid=workgroupid, uid=userid, role_id=roleid)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_ADDWGROUPMEMBER, pld=pld)
    return resp_t[-1]

def workgroup_remove_member(session, workgroupid, userid):
    """
    remove a member from workgroup

    input:
        session         client session
        workgroupid     id of the workgroup to update
        userid          id of the plugin to remove

    output:
        payload of server response

    """
    pld = dict(wid=workgroupid, uid=userid)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_DELWGROUPMEMBER, pld=pld)
    return resp_t[-1]

def show_user_in_workgroup(session, workgroupid):
    """
    get user information

    input:
        session         client session
        workgroupid     id of the workgroup to show members of

    output:
        users information of workgroup members

    """
    p = ""
    pld = dict(wid=workgroupid)
    resp_t = comm.sendpacket(session, op=comm.ccdlib.OP_SHOWUSER, pld=pld)

    for u in resp_t[-1]:
        p += "user %d:\n" % u["uid"]
        for k, v in u.items():
            p += "\t%s:%s\n" % (k, v)
    return p
