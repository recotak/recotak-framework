import thread
import sys
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
import re
import struct
import socket
import csockslib
import logging

def add_rotat_logger(fn,
                    level,
                    maxBytes=20000000,
                    backupCount=10,
                    formatter=None):
    """ returns a logging handler.

        input:
            fn              filename to log to
            level           logging level to log
            maxBytes(o)     bytes written to file before rotating
            backupCount(o)  amount of file rotations
            formatter(o)    formatter object to added to ratation logger

        output:
            handler         RotatingFileHandler

    """
    print("ctools.add_rotat_logger is depricated. Please user "
          "cUtil.add_rotot_logger")
    handler = logging.handlers.RotatingFileHandler(
                    fn,
                    maxBytes=maxBytes,
                    backupCount=backupCount)
    handler.setLevel(level)

    if not formatter:
        fmt_str = "%(asctime)s,p:%(process)s %(threadName)s, %(name)s"+\
                    "(%(funcName)s) [%(levelname)s]: %(message)s"
        formatter = logging.Formatter(fmt_str)

    handler.setFormatter(formatter)
    return handler

def getNetmask(prefix, bit):
    """ gets a prefix in dotted notation and a bit to indicated netmask.
        returns start and end ip of netrange as long(!)
    """
    prefix = struct.unpack(">I",socket.inet_aton(prefix))[0]

    shift = 32-bit
    start = prefix >> shift << shift

    mask = (1 << shift) - 1
    end = start | mask

    return start,end

def isIP(totest):
    """ returns whether input is an ip """
    print("ctools.isIP() is deprecated. Please use cUtil.isIP()!")
    m = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"\
                    "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",totest)
    return m

def isDomain(totest):
    """ returns whethter input is a domain """
    print("ctools.isDomain() is deprecated. Please use cUtil.isDomain()!")
    return True if not re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$",\
                        totest) == None else False

def printStatus(queue):
    """ prints queue progress in percentag style """

    def refresh():
        totalamount = queue.qsize()
        step = 100.0/float(totalamount)
        old = totalamount
        progress = 0.0

        while (queue.qsize()>0):
            new = queue.qsize()
            diff = old-new
            if (diff>0):
                progress += step*diff
                sys.stdout.write("\r%d%%" % round(progress))
                sys.stdout.flush()
                old = new

    thread.start_new_thread(refresh,())
    sys.stdout.write("\n")

def getRandomBytes(n):
    """ returns n randrom bytes """

    with open("/dev/urandom") as f:
        return f.read(n)

def resolveIP(useSocks, socksserver, ip):
    """ resolve an IP """
    dns = ""

    if useSocks:
        try:
            suc, dns = csockslib.socks4a_resolveHostByAddr(ip, saddr=socksserver)

            if not suc == csockslib.SOCKS4_ESTABLISHED:
                raise Exception("Socksserver failed to resolve ip!")

        except socket.error:
            raise Exception("Failed to connect to socksserver.")

    else:
        dns = socket.gethostbyaddr(ip)[0]

    return dns

def resolveDomain(useSocks, socksserver, dns):
    """ resolve domain to ip """
    ip = ""

    if useSocks:
        try:
            ip = csockslib.socks4a_resolveHost(socksserver, (dns, 80))

            if not suc == csockslib.SOCKS4_ESTABLISHED:
                raise Exception("Socksserver failed to resolve domain!")

        except socket.error:
            raise Exception("Failed to connect to socksserver.")

    else:
        ip = socket.gethostbyname(dns)

    return ip

