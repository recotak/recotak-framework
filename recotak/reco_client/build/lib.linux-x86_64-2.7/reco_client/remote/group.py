"""
stub of the connection group.
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

A connection group is list of proxy chains, ordered by priority. The traffic of
a plugin is forwared through a connection group transparently.

"""

import reco_client.remote.proxychain as pxychain
import reco_client.connection.comm as comm
import logging
logger = logging.getLogger("client.%s" % __name__)

class ConnectionGroup():
    """
    stub for the remote connection group.

    a connection group has the following attributes:

        grpid       an id
        description a descriptive string
        chains      a list of chains. the chains are ordered by priority. the
                    index encodes the priority. high priority number -> high
                    index and vice versa
        default     flag, which indicates whether the group is system default
                    group

    """

    def __init__(self, grpid, description, default=False):
        """ init a new socket chain """
        self.grpid = grpid
        self.description = description
        self.chains = []
        self.default = default

    def set_chains(self, chains):
        """ set chain list """
        self.chains = chains

    def get_chains(self):
        """ return chain list """
        return self.chains

    def add_chain(self, pcid, prio):
        """ add proxy to chain """
        if not pcid in self.chains:
            # add chain to local chain cache, the priority states the position
            # of the chain in our list. this results in a list that is sorted
            # by priority
            self.chains.insert(prio, pcid)

    def del_chain(self, pcid):
        """ remove proxy from chain """
        if pcid in self.chains:
            self.chains.remove(pcid)

    def __str__(self):
        default = "   --> " if self.default else ""
        res = "%s\t%s (%s): " % (default, self.grpid, self.description)

        for pcid in self.chains:
            res += " %s," % pcid

        # remove comma
        res = res[:-1]
        return res

    def as_dict(self):
        """ returns a dictionary of the group """
        return dict(grpid=self.grpid,
                    description=self.description,
                    chains=[dict(prio=i, pcid=p) for i, p in
                            enumerate(self.chains)])


def new_group(client, description):
    """
    parse input parameters and create a new connection group.
    return group's id

    inpu:
        description     short notes stored along with the conn group

    """
    pld = dict(description=description)
    resp = comm.sendpacket(client, op=comm.ccdlib.OP_NEWGROUP, pld=pld)[-1]

    try:
        grpid = resp["grpid"]
    except KeyError:
        raise Exception("Invalid json format!")

    group = ConnectionGroup(grpid, description)
    client.connection_groups[group.grpid] = group
    print(group.grpid)

def del_group(client, groupid):
    """
    delete connection group

    input:
        groupid     id of the connection group to delete

    """
    if not groupid in client.connection_groups:
        raise Exception("Invalid group id!")

    # send request
    pld = dict(grpid=groupid)
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_DELGROUP, pld=pld)

    # delete from cache
    del client.connection_groups[pld["grpid"]]

    print(resp_t[-1])

def use_group(client, groupid, pluginid=None):
    """
    parse input parameters and switch to new connection group. There a
    basically two types of group usage: 1) groups act as default group for the
    hole ccd and 2) a group is assigned to a plugin/project combination. The
    project id is a member variable of the client, so no arguments are needed
    here.

    input:
        client      the client instance
        groupid     id of the group to use/active
        pluginid    id of the plugin that might be associated with the group

    """
    updateConnGroupList(client)

    # group id
    if not groupid in client.connection_groups:
        raise Exception("Invalid group id!")

    pld = dict(grpid=groupid)

    # plugin and project
    if pluginid and not client.project:
        raise Exception("No project set! Please execute 'set project <pid>'"
                        " before!")
        pld["plg_id"] = pluginid
        pld["pid"] = client.project

    # send request
    comm.sendpacket(client, op=comm.ccdlib.OP_USEGROUP, pld=pld)


def add_chain_to_group(client, groupid, chainid, priority=None):
    """
    add chain to group

    input:
        groupid     id of the connection group to append to
        chainid     id of the chain to append
        priority    chains with a higher priority are scheduled first

    output:
        returns connection group object

    """
    updateConnGroupList(client)
    pxychain.updateProxyChainList(client)

    # get conn group
    try:
        group = client.connection_groups[groupid]
    except (KeyError, IndexError):
        raise Exception("Invalid group id (%s)!" % groupid)

    # check whether chain id is valid
    if not chainid in client.proxychains:
        raise Exception("No such chain (%s)!" % chainid)

    # get prio
    if not priority:
        priority = len(group.get_chains())

    # add to chains
    try:
        group.add_chain(chainid, priority)
    except Exception as e:
        raise Exception("Failed to add to chains: '%s'" % str(e))

    flush(client, [groupid])

    return group

def del_chain_from_group(client, groupid, chainid):
    """
    del chain from group

    input:
        groupid     id of the connection group to delete from
        chainid     id of the chain to from

    output:
        returns connection group object

    """
    updateConnGroupList(client)
    pxychain.updateProxyChainList(client)

    # get conn group
    try:
        group = client.connection_groups[groupid]
    except (KeyError, IndexError):
        raise Exception("Invalid group id (%s)!" % groupid)

    # check whether chain id is valid
    if not chainid in client.proxychains:
        raise IndexError()

    try:
        group.del_chain(chainid)
    except Exception as e:
        raise Exception("Failed to delete chain from group: '%s'" % str(e))

    flush(client, [groupid])

    return group

def flush(client, args):
    """ send flush command to submit group to server """
    if not args:
        raise Exception("Not enough arguments!")

    try:
        group = client.connection_groups[args[0]]
        comm.sendpacket(client, op=comm.ccdlib.OP_FLUSHGROUP, pld=group.as_dict())

    except (KeyError, IndexError):
        raise Exception("Invalid group id (%s)!" % args[0])


def print_groups(client):
    """ show connection groups """
    #if not client.connection_groups.values():
    updateConnGroupList(client)

    for group in client.connection_groups.values():
        print(str(group))


def updateConnGroupList(client):
    """ ask server for configured connection groups """

    # reset
    client.connection_groups = {}

    # and get all information
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_SHOWGROUP)

    for p in resp_t[-1]:
        try:
            group = ConnectionGroup(grpid=p["grpid"],
                                    description=p["description"],
                                    default=p["default"])
            group.set_chains(p["chains"])
            client.connection_groups[group.grpid] = group
        except (KeyError, ValueError):
            logger.warning("Received invalid json packet!")
