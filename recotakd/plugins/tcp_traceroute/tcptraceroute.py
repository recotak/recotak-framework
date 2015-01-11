#!/usr/bin/env python

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
# @version 0.1
# @date 28.01.2014
# @author curesec
# @email curesec

import argparse
import sys
import struct
import socket
import threading
import errno

# TODO write to database
__plgname__ = "tcp_traceroute"


class Sender():
    def __init__(self, target, port, n, timeout, maxhops, verbose):
        self.target = socket.gethostbyname(target)
        self.port = int(port)
        self.n = n
        self.timeout = int(timeout)
        self.maxhops = int(maxhops)
        self.verbose = verbose

    def run(self):
        for ttl in range(1, self.maxhops):
            #time.sleep(0.1)

            listener = None
            try:
                listener = Listener(self.timeout)
            except socket.error as e:
                if e.errno == errno.EPERM:
                    print 'Failed to create RAW socket (need root privs)'
                    break

            listener.start()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            s.settimeout(self.timeout)
            try:
                s.connect((self.target, self.port))
            except socket.timeout as e:
                print(" " + str(ttl) + " ***")
                if self.verbose:
                    print("    " + str(e))
                listener.join()
                continue
            except socket.error as e:
                if e.errno == socket.errno.ECONNREFUSED:
                    # Connection refused
                    self.output(ttl, self.target, " [closed]")
                    listener.join()
                    break
                # important: wait for listener
                listener.join()
                self.output(ttl, listener.host, "")
                if self.verbose:
                    print("    " + str(e))
                continue
            finally:
                s.close()
            self.output(ttl, self.target, " [open]")
            # is there a way to kill the listener thread instead of waiting for it to timeout?
            listener.join()
            break

    def getreversename(self, ip):
        try:
            name, alias, addresslist = socket.gethostbyaddr(ip)
            return name
        except:
            return ""

    def output(self, ttl, host, suffix):
        output = " " + str(ttl) + " " + host
        if not self.n:
            reversename = self.getreversename(host)
            output = output + " (" + reversename + ")"
        output = output + suffix
        print(output)


class Listener(threading.Thread):
    def __init__(self, timeout):
        threading.Thread.__init__(self)
        self.timeout = timeout
        self.host = ""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.sock.settimeout(self.timeout)

    def run(self):
        try:
            data, addr = self.sock.recvfrom(1024)
            self.host, ip = addr
        except:
            pass
        finally:
            self.sock.close()


def TcpTraceroute(argv):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="Run with root privileges")
    parser.add_argument("-t",
                        action="store",
                        dest="target",
                        required=True,
                        help="IP address or hostname")
    parser.add_argument("-p",
                        action="store",
                        dest="port",
                        required=False,
                        default="80",
                        help="default: 80")
    parser.add_argument("-n",
                        action="store_true",
                        dest="n",
                        required=False,
                        help="disable reverse DNS")
    parser.add_argument("-to",
                        action="store",
                        dest="timeout",
                        required=False,
                        default="3",
                        help="Socket timeout in seconds (default 3)")
    parser.add_argument("-mh",
                        action="store",
                        dest="maxhops",
                        required=False,
                        default="30",
                        help="default: 30")
    parser.add_argument("-v",
                        action="store_true",
                        dest="verbose",
                        help='verbose',
                        required=False)

    if not argv:
        parser.print_help()
        sys.exit(1)

    opt = parser.parse_args(argv)

    sender = Sender(opt.target, opt.port, opt.n, opt.timeout, opt.maxhops, opt.verbose)
    sender.run()


if __name__ == '__main__':
    TcpTraceroute(sys.argv[1:])
