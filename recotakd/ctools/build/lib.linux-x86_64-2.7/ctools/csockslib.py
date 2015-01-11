import binascii
import struct
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
import sys, traceback
import socket
import threading
import ssl
import sys
import binascii
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

SOCKS4_TCP_REQUEST = 0x01
SOCKS4_ESTABLISHED = 0x5A
SOCKS4_REFUSED = 0x5B
SOCKS4_ERR_CONNECT = 0x5C
SOCKS4_REMOTE_RESOLVE = 0xf0
SOCKS4_REMOTE_REVDNS = 0x0f1

def socks4a_answer(client, raddr, code, pld=None):
    # leading null byte with granted byte
    data = struct.pack(">H",code)

    if code != SOCKS4_REFUSED and raddr:
        # attach resolved ip
        if raddr:
            rip, rport = raddr
            data += struct.pack(">H",int(rport))

            if rip:
                try:
                    data += socket.inet_aton(rip)
                except Exception as err:
                    pass

        # optional: some additional data to send.
        # e.g. if we do reverse dns
        if pld:
            data += binascii.hexlify(pld)

    # send
    client.send(data)

def socks4a_neg(bind, allowedClients, deniedRemotes, psize=4096):
    remoteResolve = False

    # Receive information from client.
    client, caddr = bind.accept()

    # check whether connection is allowed from
    # that source
    remoteIp = caddr[0]

    if len(allowedClients)>0 and not remoteIp in allowedClients:
        method = SOCKS4_REFUSED
        conto = (None, None)
        return method,client,caddr,conto,remoteResolve

    data=client.recv(psize)
    if not data:
        raise Exception("Empty message.")

    # process sent data
    try:
        version, method =struct.unpack('BB',data[:2])
        port=struct.unpack('>H',data[2:4])
    except:
        raise Exception("Failed to unpack message!")

    # If first three bytes are zero, the Ip is invalid
    # and we have a SOCKS 4a request, including
    # a domain name to resolve.
    if (data[4] == "\x00") and (data[5] == "\x00")\
          and (data[6] == "\x00") and (data[7] != "\x00"):
        remoteResolve = True
        domain = ""

        # iterate over user, just ignore him
        i = 1
        for t in data[8:]:
            if t == "\x00":
                break
            else:
                i += 1

        # extract ip
        for t in data[8+i:len(data)]:
            domain += struct.unpack(">s",t)[0]

        # remove trailing null byte
        ip = domain[:-1]

    # We got an usual ip address within the SOCKS request.
    else:
        a1=struct.unpack('>B',data[4])
        a2=struct.unpack('>B',data[5])
        a3=struct.unpack('>B',data[6])
        a4=struct.unpack('>B',data[7])

        ip="%d.%d.%d.%d" % (a1[0],a2[0],a3[0],a4[0])

    # check whether connection is allowed to
    # that destination
    if len(deniedRemotes)>0 and ip in deniedRemotes:
        method = SOCKS4_REFUSED
        conto = (None, None)
        return method,client,caddr,conto,remoteResolve


    version=version
    port=port[0]
    conto=(ip,port)

    return method,client,caddr,conto,remoteResolve

def socks4a_connect(saddr, raddr, timeout=1.0):
    """ Function builds the SOCKS4A connection request,
        sends the request and verifies the answer.
    """
    socksip, socksport = saddr

    request = _socks4a_buildRequest(raddr)

    # send request
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(timeout)

    # set up connection and send request
    s.connect((socksip,int(socksport)))

    suc, data = _socks4a_sendRequest(s, request)
    if suc != SOCKS4_ESTABLISHED:
        logger.info('Could not establish sockst4a connection %s', repr(suc))
        s.close()
        s = None

    return suc, s

def _socks4a_buildRequest(raddr):

    """ Given a remote IP,Port tuple to connect to, function
        builds SOCKS4A connection request.

        From https://en.wikipedia.org/wiki/SOCKS#SOCKS4a
        Client to SOCKS server:
            field 1: SOCKS version number, 1 byte, must be 0x04 for this version
            field 2: command code, 1 byte:
                0x01 = establish a TCP/IP stream connection
                0x02 = establish a TCP/IP port binding
            field 3: network byte order port number, 2 bytes
            field 4: deliberate invalid IP address, 4 bytes, first three must be 0x00 and the last one must not be 0x00
            field 5: the user ID string, variable length, terminated with a null (0x00)
            field 6: the domain name of the host we want to contact, variable length, terminated with a null (0x00)
    """

    ip, port = raddr
    port = int(port)
    logger.debug('_socks4a_buildRequest %s:%d', ip, port)
    remoteResolve = False

    # Check if the destination address
    # provided is an IP address
    try:
        ipbin = socket.inet_aton(ip)

    # It's a DNS name.
    except socket.error:
        ipbin = "\x00\x00\x00\x01"
        remoteResolve = True

    # remote port
    portbin = struct.pack(">H",int(port))

    # build request
    request = "\x04\x01%s%s\x00" % (portbin,ipbin)

    # If we have no valid IP, we need to attach
    # the domain name.
    if remoteResolve:
        request = request.decode('latin-1') + ip + "\x00"
        request = request.encode('latin-1')

    return request

def _socks4a_sendRequest(s, request):
    """ Sends SOCKS4A request over s and checks whether request
        succeeded.
    """
    logger.debug('Sending %s to %s', binascii.hexlify(request), repr(s.getsockname()))
    s.send(request)

    try:
        res = s.recv(1024)
    except socket.timeout:
        logger.info('_socks4a_sendRequest timed out')
        return SOCKS4_ERR_CONNECT, None

    if len(res)<2 or (res[0] != "\x00") or (res[1] != "\x5A"):
        # field 2: status, 1 byte:
        # 0x5a = request granted
        # 0x5b = request rejected or failed
        # 0x5c = request failed because client is not running identd (or not
        #        reachable from the server)
        # 0x5d = request failed because client's identd could not confirm the
        #        user ID string in the request
        logger.info('_socks4a_sendRequest error on connect, received: %s',
                      binascii.hexlify(res), exc_info=1)
        return SOCKS4_ERR_CONNECT, None

    return SOCKS4_ESTABLISHED, res

def socks4a_resolveHost(raddr, saddr=None, sock_fd=None):
    host,rport = raddr

    request = _socks4a_buildResolveRequest(host, SOCKS4_REMOTE_RESOLVE)

    # connecting
    if not sock_fd and saddr:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(saddr)
    else:
        s = sock_fd

    # sending request
    suc, res = _socks4a_sendRequest(s, request)
    if suc != SOCKS4_ESTABLISHED:
        s.close()
        return suc, None

    # extract resolved ip
    remoteIP = socket.inet_ntoa(res[4:])
    remotePort = struct.unpack(">H",res[2:4])[0]

    if not sock_fd:
        s.close()

    return SOCKS4_ESTABLISHED, remoteIP

def socks4a_resolveHostByAddr(rip, saddr=None, sock_fd=None):
    request = _socks4a_buildResolveRequest(rip, SOCKS4_REMOTE_REVDNS)

    # connecting
    if not sock_fd and saddr:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(saddr)
    else:
        s = sock_fd

    # sending request
    suc, res = _socks4a_sendRequest(s, request)
    if suc != SOCKS4_ESTABLISHED:
        s.close()
        return suc, None

    # extract resolved ip
    dns = binascii.unhexlify(res[8:])

    if not sock_fd:
        s.close()

    return SOCKS4_ESTABLISHED, dns

def _socks4a_buildResolveRequest(host, req_type):
    # remote port
    portbin = "\x00\x00"

    # build request to resolve domain name
    if req_type == SOCKS4_REMOTE_RESOLVE:
        ipbin = "\x00\x00\x00\x01"
        request = "\x04\xF0%s%s\x00%s\x00" %\
                     (portbin,ipbin,host.encode("utf-8"))

    # build request do resolve dns reversely
    elif req_type == SOCKS4_REMOTE_REVDNS:
        ipbin = socket.inet_aton(host)
        request = "\x04\xF1%s%s\x00" % (portbin,ipbin)

    return request

def parse_socks(socks):
    parts = socks.split(':')
    return parts


