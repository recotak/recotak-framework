"""
a stub for remote proxy
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

A proxy is used in order to forward plugins' traffic through it. They are
organised in chains, so the traffice flows through a list of proxies.

"""

import reco_client.connection.comm as comm
#from reco_client.connection.comm import comm.sendpacket
#from reco_client.connection.comm import comm.ccdlib

import logging
logger = logging.getLogger("client.%s" % __name__)

class Proxy():
    """
    A proxy is an object that is assigned to a proxy chain. Every proxy has an
    address and a protocol that is spoken.

    A proxy has the following attributes:

        pxid        id of the proxy
        ip          ip or domain of the proxy listens to
        port        port the proxy listens to
        protocol    the protocol the proxy is addressable with (at the moment
                    only s4 supported)
        description some descriptive words

    """

    def __init__(self, pxid, ip, port, protocol, description):
        """ create a new proxy object without adding it to database """
        self.pxid = pxid
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.description = description

    def __str__(self):
        res = "\t%s (%s) - " % (self.pxid, self.description)
        res += "%s://" % self.protocol
        res += "%s:%d" % (self.ip, self.port)

        return res

def new_proxy(client, protocol, ip, port, description):
    """
    create a new proxy

    input:
        protocol    protocol the proxy is addressable with
        ip          ip or domain of the proxy
        port        port the proxy listens to
        description short description of the proxy

    output:
        proxy id

    """
    try:
        pld = dict(ip=ip,
                   port=port,
                   protocol=protocol,
                   description=description)
    except (KeyError, ValueError):
        return ("Invalid input. Example: new proxy protocol://"
                "ip:port proxy_name")

    # send request
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_NEWPROXY, pld=pld)

    # create proxy object
    proxy = Proxy(pxid=resp_t[-1], **pld)

    # cache
    client.proxies[proxy.pxid] = proxy

    return proxy.pxid

def del_proxy(client, proxyid):
    """
    delete proxy

    input:
        proxyid     id of the proxy

    output:
        payload of server response

    """

    # build request
    if not proxyid in client.proxies:
        raise KeyError()
    pld = dict(pxid=proxyid)

    # send request
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_DELPROXY, pld=pld)

    # delete from cache
    del client.proxies[pld["pxid"]]

    return resp_t[-1]

def print_proxies(client):
    """ show proxies """

    updateProxyList(client)

    for proxy in client.proxies.values():
        print(str(proxy))

def updateProxyList(client):
    """ ask server for configured proxies """
    resp_t = comm.sendpacket(client, op=comm.ccdlib.OP_SHOWPROXY)

    for p in resp_t[-1]:
        try:
            proxy = Proxy(pxid=p["pxid"],
                          ip=p["ip"],
                          port=int(p["port"]),
                          protocol=p["protocol"],
                          description=p["description"])
            client.proxies[proxy.pxid] = proxy
        except (KeyError, ValueError):
            logger.warning("Received invalid json packet!")
