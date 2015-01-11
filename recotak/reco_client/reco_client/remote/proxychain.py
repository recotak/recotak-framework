"""
proxy chain stub
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

A proxy chain is a list of proxies that are used to route plugins' traffic
through.

"""

import reco_client.remote.proxy as pxy
import reco_client.connection.comm as comm

#from reco_client.remote.proxy import pxy.updateProxyList
#from reco_client.connection.comm import comm.sendpacket
#from reco_client.connection.comm import comm.ccdlib
import logging

logger = logging.getLogger("client.%s" % __name__)


class ProxyChain():
    """
    A socket chain consists of different connections leading
    to a final address. Each connection might be of different
    type (SOCKS4, SOCKS5, TOR, direct, ..). All together form
    a chain.

    A proxy chain has the following attributes:

        pcid        chain id
        description a descriptive string
        proxies     a list of proxies to route plugins' traffic through

    """

    def __init__(self, pcid, description):
        """ init a new socket chain """
        self.pcid = pcid
        self.description = description
        self.proxies = []

    def set_proxies(self, proxies):
        self.proxies = proxies

    def add_proxy(self, pxid):
        """ add proxy to chain """
        if not pxid in self.proxies:
            self.proxies.append(pxid)

    def del_proxy(self, pxid):
        """ remove proxy from chain """
        if pxid in self.proxies:
            self.proxies.remove(pxid)

    def __str__(self):
        res = "\t%s (%s): -->" % (self.pcid, self.description)

        for pxid in self.proxies:
            res += " %s -->" % pxid

        return res

    def as_dict(self):
        """ returns a dictionary of chain """
        return dict(pcid=self.pcid,
                    description=self.description,
                    proxies=self.proxies)


def new_chain(client, description):
    """
    create a new proxy chain

    input:
        description     some short description of the proxy chain

    output:
        id of newly created chain

    """
    pld = dict(description=description)
    resp = comm.sendpacket(client, op=comm.ccdlib.OP_NEWPCHAIN, pld=pld)[-1]
    try:
        pcid = resp["pcid"]
    except KeyError:
        raise Exception("Invalid json format!")

    pc = ProxyChain(pcid, description)
    client.proxychains[pc.pcid] = pc
    return pc.pcid

def del_chain(client, chainid):
    """
    delete proxy chain

    input:
        chainid     the id of the chain to delete

    output:
        payload of server response

    """
    logger.debug("deleting chain %s", chainid)

    # build request
    if not chainid in client.proxychains:
        raise KeyError()

    pld = dict(pcid=chainid)

    # send request
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_DELPCHAIN, pld=pld)

    # delete from cache
    del client.proxychains[pld["pcid"]]

    return resp_t[-1]

def add_proxy_to_chain(client, chainid, proxyid):
    """
    add proxy to chain

    input.
        chainid     id of chain to append to
        proxyid     id of proxy to append

    output:
        chain object

    """
    updateProxyChainList(client)
    pxy.updateProxyList(client)

    # get proxy chain
    try:
        chain = client.proxychains[chainid]
    except (KeyError, IndexError):
        raise Exception("Invalid chain id!")

    # add proxy
    try:
        # check whether proxy id is valid
        if not proxyid in client.proxies:
            raise IndexError()

        chain.add_proxy(proxyid)
    except (KeyError, ValueError, IndexError):
        raise Exception("Invalid proxy id!")

    flush(client, [chainid])

    return chain

def del_proxy_from_chain(client, chainid, proxyid):
    """
    remove proxy from chain

    input:
        chainid     id of chain to remove from
        proxyid     id of proxy to remove

    output:
        chain object

    """
    updateProxyChainList(client)
    pxy.updateProxyList(client)

    # get proxy chain
    try:
        chain = client.proxychains[chainid]
    except (KeyError, IndexError):
        raise Exception("Invalid chain id!")

    # add proxy
    try:
        # check whether proxy id is valid
        if not proxyid in client.proxies:
            raise IndexError()

        chain.del_proxy(proxyid)
    except (KeyError, ValueError, IndexError):
        raise Exception("Invalid proxy id!")

    flush(client, [chainid])

    return chain

def flush(client, args):
    """ send flush command to submit chain to server """
    if not args:
        raise Exception("Not enough arguments!")

    try:
        chain = client.proxychains[args[0]]
        comm.sendpacket(client, op=comm.ccdlib.OP_FLUSHPCHAIN, pld=chain.as_dict())

    except (KeyError, IndexError):
        raise Exception("Invalid chain id (%s)!" % args[0])

def print_chains(client):
    """ show chains """
#    if not client.proxychains.values():
    updateProxyChainList(client)

    for chain in client.proxychains.values():
        print(str(chain))


def updateProxyChainList(client):
    """ ask server for configured proxies. first, flush all local chains """
    # reset
    client.proxychains = {}

    # and get all information
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_SHOWPCHAIN)

    for p in resp_t[-1]:
        try:
            chain = ProxyChain(pcid=p["pcid"],
                               description=p["description"])
            chain.set_proxies(proxies=p["proxies"])
            client.proxychains[chain.pcid] = chain
        except (KeyError, ValueError):
            logger.warning("Received invalid json packet!")
