import socket
import threading
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
import select
import time
import re
import ssl

__version = 0.661
__author__ = "Curesec GmbH"
__email__ = "curesec"

SOCKET_TIMEOUT = 7.0
SSL_PORTS = [443]


def build_server(lip, lport):
    bind=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    bind.bind((lip,lport))
    bind.listen(32)
    return bind


def remote_recv(remote, client, psize=4096):
    while True:
        try:

            r, w, e = select.select([remote,client],[],[],1)

            for s in r:
                    data = s.recv(psize)

                    if data:

                        if s == remote:
                            client.send(data)
                        elif s == client:
                            remote.send(data)

                    else:
                        client.shutdown(socket.SHUT_RDWR)
                        remote.shutdown(socket.SHUT_RDWR)

                        client.close()
                        remote.close()
                        break

        except (socket.error,KeyboardInterrupt) as e:
            remote.close()
            client.close()
            break


def validIP(string):
    ip = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    return ip.match(string) != None

def validDomainName(string):
    domain = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")
    return domain.match(string) != None
