""" create, delete and modify proxies """

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
from database.ccddb import MAX_LEN_DESC
from ctools.cUtil import validString
from database.ccdErrors import *
from ctools.dns import validate
from database import ccddb
import logging

logger = logging.getLogger("ccd.%s" % __name__)

class Proxy(object):
    """
    A proxy is an object that is assigned to a proxy chain. Every chain is
    assigned to a connection group:

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

    Every proxy has an address and a protocol that is used for connection
    setup.

    """

    def __init__(self, pxid, ip, port, protocol, desc):
        """ create a new proxy object without adding it to database """
        self.pxid = pxid
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.description = desc

    @classmethod
    def create(cls, db, ip, port, protocol, desc=""):
        """ create a new proxy in database and return proxy object """
        pxid = ccddb.add_proxy(db, ip, port, protocol, desc)
        proxy = cls(pxid=pxid,
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    desc=desc)
        return proxy


    @classmethod
    def get_by_addr(cls, db, ip, port):
        """ load proxy configuration from database for a given proxy address """
        res = ccddb.get_proxy_by_addr(db, ip, port)
        if not res:
            raise Exception("Failed to get proxy from db (%s:%s)" % (ip, port))

        proxy = cls(pxid=res[0],
                    ip=ip,
                    port=port,
                    protocol=res[3],
                    desc=res[4])
        return proxy

def return_proxy_by_id(ccd, pxid):
    """
    return proxy. first look in cache. if proxy is not found in cache, get it
    from database and add it to cache.

    """

    # get from cache
    try:
        return ccd.proxies[pxid]

    # on error continue and get chain from db.
    except KeyError:
        pass

    db = ccd._db.conn

    res = ccddb.get_proxy_by_id(db, pxid)
    if not res:
        raise Exception("Failed to get proxy with id %s" % pxid)

    proxy = Proxy(pxid=pxid,
                  ip=res[1],
                  port=res[2],
                  protocol=res[3],
                  desc=res[4])

    ccd.proxies[pxid] = proxy
    return proxy


def create_proxy(ccd, sid, pld):
    """
    create a new proxy object. Before doing so, verify user. Finally cache
    proxy.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of request

    output:
        pxid    proxy id

    """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user.
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        # validate ip
        ip = pld["ip"]
        if not validate.is_ip(ip) and not validate.is_domain(ip):
            raise InputError("Proxy address is neither ip nor domain.")

        # validate port
        port = int(pld["port"])
        if port < 0 or port > 65535:
            raise InputError("Invalid port %d!" % port)

        # validate protocol
        protocol = pld["protocol"]
        if not validString(protocol):
            raise InputError("Invalid characaters in protocol")
        elif len(protocol) > MAX_LEN_DESC:
            raise InputError("Protocol exceeds limit of %d characters" %
                             MAX_LEN_DESC)

        # validate description
        description = pld["description"]
        if not validString(description):
            raise InputError("Invalid characters is description")
        elif len(description) > MAX_LEN_DESC:
            raise InputError("Desc exceeds limit of %d characters" %
                             MAX_LEN_DESC)

    except (KeyError, ValueError):
        raise InputError("Invalid json format!")

    # create new proxy
    try:
        proxy = Proxy.create(db=ccd._db.conn,
                             ip=ip,
                             port=port,
                             protocol=protocol,
                             desc=description)
    except Exception as e:
        raise InputError("Failed to create proxy:'%s'!" % e)

    # cache proxy
    ccd.proxies[proxy.pxid] = proxy

    return proxy.pxid

def del_proxy(ccd, sid, pld):
    """
    delete proxy from database

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of request


    """
    empty_error = ccddb.DatabaseError()

    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        pxid = int(pld["pxid"])
    except (KeyError, ValueError):
        raise InputError("Invalid json format!")

    # delete proxy
    try:
        ccddb.delete_proxy(ccd._db.conn, pxid)
    except Exception as e:
        raise InputError("Failed to delete proxy:'%s'!" % e)

    # remove from cache
    del ccd.proxies[pxid]

def show_proxy(ccd, sid):
    """
    delete proxy from database

    input:
        ccd     ccd instance
        sid     session id

    """
    empty_error = ccddb.DatabaseError()

    # get user
    user, wg = ccd.get_user_and_workgroup(sid)

    # authorise user.
    if (not user.uid == ccd.superadmin.uid and
        not wg.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
        raise PermissionDenied(user.name)

    # get proxies from database
    all_proxies = ccddb.get_all_proxies(ccd._db.conn)

    # update cache and serialise proxy
    pld = []
    for db_entry in all_proxies:
        proxy = Proxy(pxid=db_entry[0],
                      ip=db_entry[1],
                      port=db_entry[2],
                      protocol=db_entry[3],
                      desc=db_entry[4])
        ccd.proxies[proxy.pxid] = proxy

        pld.append(dict(pxid=proxy.pxid,
                        ip=proxy.ip,
                        port=proxy.port,
                        protocol=proxy.protocol,
                        description=proxy.description))

    return pld





