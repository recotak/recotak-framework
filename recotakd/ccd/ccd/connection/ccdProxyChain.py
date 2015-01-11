"""
provides a proxy chain object to redirect socket connections over proxy
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
chains

"""
from connection.ccdProxy import return_proxy_by_id
from connection.ccdCrypto import genSCID
from ctools.cUtil import validString
from ctools.ctools import csockslib
from database.ccdErrors import *
from database import ccddb
from random import shuffle
from copy import copy
import collections
import logging
import socket

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

# there a different modes of selecting a proxy chain. usually, the chains
# are ordered by priority. but they can also be selected at random or round
# robin.
CHAIN_MODE_PRIO = 1
CHAIN_MODE_RANDOM = 2
CHAIN_MODE_ROBIN = 3

_orig_socket = socket.socket

class ProxyChain(object):
    """
    A socket chain consists of different connections leading
    to a final address. Each connection might be of different
    type (SOCKS4, SOCKS5, TOR, direct, ..). All together form
    a chain.

        +--------------------------------+
        |        connection group        |
        +--------------------------------+
                        |
                        | consists of (ordered by priority)
                        |
                        v
        +--------------------------------+
        |          proxy chains          |
        +--------------------------------+
                        |
                        | consists of
                        |
                        v
        +--------------------------------+
        |            proxies             |
        +--------------------------------+

    A proxy chain object has the following attributes:

        pcid        the id of the connection group. an 8 byte hash
        description a string to contain some descriptive wordings
        proxies     a list of proxies ordered by connection setup order.
                    since everything is stored in database, too, this can be
                    seen as cache.

    """

    def __init__(self, pcid, description):
        """ init a new socket chain """
        self.pcid = pcid
        self.description = description
        self.proxies = []

    @classmethod
    def create(cls, db, description):
        """ create chain by passing a drescription. the id is set automatically """
        pcid = genSCID()
        ccddb.add_proxychain(db, pcid, description)
        return cls(pcid, description)

    def set_proxies(self, proxies):
        """ set a chain's proxies cache by passing a list of proxies """
        self.proxies = proxies

    def get_proxies(self):
        """ return the cached list of proxies """
        return self.proxies

    def add_proxy(self, db, proxy):
        """
        append a proxy to the chains. add the chain to database.

        note: the order of the proxies is represented by the order of
        appending them to the chain.

        input:
            db      database connection
            proxy   proxy chain object to add to chain

        """
        if proxy in self.proxies:
            return

        # add proxy to db
        try:
            ccddb.add_proxy_to_proxychain(db, self.pcid, proxy.pxid)
        except ccddb.AlreadyExistingError:
            pass
        except ccddb.InvalidQuery:
            raise Exception("tried to add invalid proxy id(%s) to chain(%s)!" %
                            (proxy.pxid, self.pcid))

        # add proxy to local chain cache
        self.proxies.append(proxy)

    def del_proxy(self, db, proxy):
        """ delete a proxy from chain from cache and database """
        if not proxy in self.proxies:
            return

        # add proxy to db
        ccddb.del_proxy_from_proxychain(db, self.pcid, proxy.pxid)

        # add proxy to local chain cache
        self.proxies.remove(proxy.pxid)

    def has_proxy(self, proxy):
        """ return True if the proxy is added to the chain """
        for p in self.proxies:
            if p.pxid == proxy.pxid:
                break
        else:
            return False

        return True

    def reset(self):
        """ delete proxy cache """
        self.proxies = []

    def as_dict(self):
        """ return a dict of sockey chain """
        return dict(pcid=self.pcid,
                    description=self.description,
                    proxies=[proxy.pxid for proxy in self.proxies])

class ProxyChainSocket(socket.socket):
    """
    A ProxyChainSocket is a replacement of the socket.socket. The
    ProxyChainSocket implements tunneling plugins' connection through proxy
    chains. To do so, socket.socket is overwritten by the ProxyChainSocket.

    Since a proxy chain might consists of multiple proxies, an order the
    proxies needs to be defined. The oder is defined by the class attribute

    chain_mode = {CHAIN_MODE_PRIO | CHAIN_MODE_RANDOM | CHAIN_MODE_ROBIN}

    The default value is CHAIN_MODE_PRIO. In addition to that, the following
    class attributes exist:

    _use_socks                  use socks server
    _current_connection_group   the configured connection group to use for
                                tunneling
    _chain_index                index of last chosen chain

    A ProxyChainSocket object has the following attributes:

        _chains             the chain that is used to route traffic through

    """
    _use_socks = True

    # the user is able to set the group it wants to use for a connection.
    _current_connection_group = None

    # the mode is set immediately before executing plugin and after forking
    # (see execute-method in plugin.plugin)
    #
    # valid values are
    #
    #       CHAIN_MODE_PRIO     connect to chain like are appended
    #       CHAIN_MODE_RANDOM   chose chain randomly. no specific order
    #       CHAIN_MODE_ROBIN    begin with the first chain. for the next
    #                           connection setup use the second chain and so on
    chain_mode = CHAIN_MODE_PRIO

    # on chain mode round robin, we need to store the index of the last chosen
    # chain
    _chain_index = 0

    def __init__(self, family=socket.AF_INET, socket_type=socket.SOCK_STREAM,
                 proto=0, _sock=None):
        logger.debug("creating proxy chain socket, family=%s, "
                     "type=%s, proto=%s, _sock=%s", family, socket_type,
                     proto, _sock)

        _orig_socket.__init__(self, family,
                                    socket_type,
                                    proto,
                                    _sock)

        # get all chains, that are part of the current connection group. by
        # default they are sorted by their priority
        self._chains = ProxyChainSocket._current_connection_group.get_chains()

        # on chain mode random, we shuffle the chain list
        if ProxyChainSocket.chain_mode == CHAIN_MODE_RANDOM:
            logger.debug("chain mode is random")
            shuffle(self._chains)
        # on chain mode round robin, we shift the list by index
        elif ProxyChainSocket.chain_mode == CHAIN_MODE_ROBIN:
            logger.debug("chain mode is round robin")
            d = collections.deque(self._chains)
            d.rotate(ProxyChainSocket._chain_index)
            self._chains = d
            ProxyChainSocket._chain_index -= 1
        else:
            logger.debug("chain mode is priority")

    def connect(self, addr):
        """ the connection request issued by the plugin """
        if (ProxyChainSocket._use_socks and
            self._sock.family == socket.AF_INET):
            logger.debug("connecting via proxy chain to %s", addr)

            # first, connect to the last proxy in the chain
            suc, _ = self._connect_to_proxy_chain()
            if not suc:
                raise Exception("fatal: Unable to connect to proxy chain!")

            # second, connect to the final addr
            established = self._socks_connect(addr)
            if (established != csockslib.SOCKS4_ESTABLISHED):
                logger.debug("Failed to establish connection to %s. So i am "\
                             "raising socket.timeout error", str(addr))
                raise socket.timeout

        else:
            logger.debug("connecting directly: use_socks: %s, family %s",
                         ProxyChainSocket._use_socks,
                         self._sock.family)
            _orig_socket.connect(self, addr)

    def _socks_connect(self, raddr):
        """
        Function builds the SOCKS4A connection request,
        sends the request and verifies the answer.

        """
        request = csockslib._socks4a_buildRequest(raddr)
        suc, _ = csockslib._socks4a_sendRequest(self, request)

        return suc

    def _connect_to_proxy_chain(self):
        """
        establish the proxy chain. To do so, we connect the
        first proxy with the second, the second with the third
        and so on.. the last one connects to the final interwebz

        """

        logger.debug("Connecting to proxy chain..")

        connected = False

        logger.debug("chains:%s", [c.pcid for c in self._chains])

        established = False
        while not established:
            try:
                chain = self._chains.pop()
            except IndexError:
                # no more chains to go through, so cancel here.
                # it failed to establish any connection.
                break

            logger.debug("first chain %s", chain)
            proxies = chain.get_proxies()
            logger.debug("connection to chain %s with proxies %s", chain.pcid,
                                                    [p.pxid for p in proxies])
            for proxy in proxies:
                raddr = (proxy.ip, proxy.port)
                prot = proxy.protocol
                logger.debug("connecting to proxy %s at %s (%s)..",
                             proxy.pxid, raddr, prot)

                try:
                    if not connected:
                        _orig_socket.connect(self, raddr)

                        logger.debug("tcp connection established to %s",
                                     self.getpeername())
                        connected = True
                        continue

                    # only connect until the last but one is reached
                    #TODO handle more protocols
                    #TODO no hard coded protocols
                    if (prot == "s4" and
                        self._socks_connect(raddr) != \
                                                 csockslib.SOCKS4_ESTABLISHED):
                        raise Exception("Failed to establish socks4 "
                                        "connection.")


                except Exception as err:
                    logger.error("Failed to connect to proxy at %s:'%s'",
                                 raddr, err)

                    if connected:
                        logger.debug("closing socket %s", self)
                        connected = False
                #        _orig_socket.close(self)

                    _orig_socket.__init__(self, self._sock.family,
                                                self._sock.type,
                                                self._sock.proto)
                    break

            else:
                logger.debug("i am connected now, so leaving for")
                established = True

        if not established:
            logger.error("Failed to connect to any proxy chain!")
            return False, None

        logger.debug("Connection now established to proxy chain. Returning "
                     "socket %s.", self)

        return True, self

def return_chain_by_id(ccd, pcid):
    """
    return chain. first look in cache. if chain is not found in cache, get it
    from database and add it to cache.

    """

    # get from cache
    try:
        return ccd.proxychains[pcid]

    # on error continue and get chain from db.
    except KeyError:
        pass

    db = ccd._db.conn

    res = ccddb.get_chain_by_id(db, pcid)
    if not res:
        raise Exception("Failed to get chain with id %s" % pcid)

    # create chain
    chain = ProxyChain(pcid=pcid,
                       description=res[1])

    # add proxies
    proxies = ccddb.get_proxies_of_chain(db, pcid)
    for proxy in proxies:
        pxid = proxy[0]
        if not pxid:
            continue

        proxy = return_proxy_by_id(ccd, pxid)
        chain.add_proxy(db, proxy)

    ccd.proxychains[pcid] = chain
    return chain


def create_proxy_chain(ccd, sid, pld):
    """ create a new proxy chain and return id """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        # validate description
        description = pld["description"]
        if not validString(description):
            raise InputError("Invalid characters is description!")

    except KeyError:
        raise InputError("Invalid json format!")

    # create proxy chain
    pc = ProxyChain.create(ccd._db.conn, description)

    # cache proxy chain
    ccd.proxychains[pc.pcid] = pc

    # return chain id
    return dict(pcid=pc.pcid)

def del_chain(ccd, sid, pld):
    """
    delete chain from database

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of request


    """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        pcid = pld["pcid"]
    except (KeyError, ValueError):
        raise InputError("Invalid json format!")

    # delete chain
    try:
        ccddb.del_proxychain(ccd._db.conn, pcid)
    except Exception as e:
        raise InputError("Failed to delete chain:'%s'!" % e)

    # remove from cache
    del ccd.proxychains[pcid]

def show_chain(ccd, sid):
    """
    show proxies in database

    input:
        ccd     ccd instance
        sid     session id

    """
    # get user
    user, wg = ccd.get_user_and_workgroup(sid)

    # authorise user.
    if (not user.uid == ccd.superadmin.uid and
        not wg.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
        raise PermissionDenied(user.name)

    # get all proxy chains
    pld = _update_proxy_chains(ccd)

    return pld

def _update_proxy_chains(ccd):
    # get proxies from database
    all_chains = ccddb.get_all_chains(ccd._db.conn)

    pld = []
    for pcid, _ in all_chains.items():
        chain = return_chain_by_id(ccd, pcid)
        pld.append(chain.as_dict())

    return pld

def flush(ccd, sid, pld):
    """
    stores a chain's proxies

    input:
        pld     payload of the ccd protocol message

    """

    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user.
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    try:
        pcid = pld["pcid"]
        proxies = pld["proxies"]
    except KeyError:
        raise InputError("Invalid json format!")


    try:
        pc = ccd.proxychains[pcid]
        old_chain = copy(pc.get_proxies())
        pc.reset()
    except KeyError:
        raise InputErro("No proxy chain with id %s" % pcid)

    try:
        for pxid in proxies:
            proxy = ccd.proxies[int(pxid)]
            pc.add_proxy(ccd._db.conn, proxy)
    except KeyError:
        raise InputError("Invalid proxy id!")

    except Exception as e:
        raise Exception("Error while adding proxy to chain:'%s'" % e)

    # for every old proxy that is not in new chain, delete it
    for proxy in old_chain:
        if not pc.has_proxy(proxy):
            ccddb.del_proxy_from_proxychain(ccd._db.conn, pc.pcid, proxy.pxid)


def _socks_hostByAddr(ip):
    """ get dns name of ip by connecting to proxy chain """
    logger.info("SOCKS4a gethostbyaddr of %s", ip)

    sock_fd = ProxyChainSocket()
    suc, sock_fd = sock_fd._connect_to_proxy_chain()
    if not suc:
        raise Exception("fatal: Failed to connect to proxy chain!")

    suc, dns = csockslib.socks4a_resolveHostByAddr(rip=ip, sock_fd=sock_fd)
    if suc != csockslib.SOCKS4_ESTABLISHED:
        raise socket.gaierror

    return (dns,)

def _socks_resolveHost(host):
    """ resolve host domain by connecting to proxy chain """

    logger.info("SOCKS4a resolve of %s", host)
    sock_fd = ProxyChainSocket()
    suc, sock_fd = sock_fd._connect_to_proxy_chain()
    if not suc:
        raise Exception("fatal: Failed to connect to proxy chain!")

    raddr = (host, 80)
    suc, ip = csockslib.socks4a_resolveHost(raddr=raddr, sock_fd=sock_fd)
    if suc != csockslib.SOCKS4_ESTABLISHED:
        raise socket.gaierror

    return ip



