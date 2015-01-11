#!/bin/sh
# -*- mode: Python -*-
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

""":"
# https://github.com/apache/cassandra/blob/trunk/bin/cqlsh
# bash code here; finds a suitable python interpreter and execs this file.
# prefer unqualified "python" if suitable:
python -c 'import sys; sys.exit(not (0x02070000 < sys.hexversion < 0x03000000))' 2>/dev/null \
    && exec python "$0" "$@"
which python2.7 > /dev/null 2>&1 && exec python2.7 "$0" "$@"
echo "No appropriate python interpreter found." >&2
exit 1
":"""

from pwd import getpwnam
from grp import getgrnam
import logging.handlers
import ConfigParser
import threading
import argparse
import resource
import logging
import select
import socket
import time
import sys
import os

CONFIG = "socksy.conf"

# logging
LOG = "socksy.log"
LOG_CON = "conn.log"

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
formatter = logging.Formatter(FORMAT)
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

from ctools import csockslib as socks
from ctools import cserverlib, ctools, cidr, cdaemonise

def readconfig(server, fn):
    global LOG,LOG_CON
    upstream = {}
    allowedClients = []
    deniedRemotes = []

    config = ConfigParser.RawConfigParser()
    config.read(fn)
    if not config:
        raise Exception("No such file %s!" % configFile)

    # general
    server.timeout = config.getfloat("General", "timeout")
    addr = config.get("General", "bind").split(":")
    server.bind_addr = (addr[0], int(addr[1]))
    server.max_fd = config.getint("General", "max_fd")
    server.uid = getpwnam(config.get("General", "user")).pw_uid
    server.gid = getgrnam(config.get("General", "group")).gr_gid

    # logging
    _log_level = config.getint("Logging", "level")
    _log_dest_d = config.get("Logging", "file") # directory
    LOG = os.path.join(_log_dest_d, LOG) # file
    LOG_CON = os.path.join(_log_dest_d, LOG_CON) # file
    roth = ctools.add_rotat_logger(LOG, _log_level, formatter=formatter)
    logging.getLogger("").addHandler(roth)

    # socks configuration
    server.useUpstream = config.getboolean("Socks", "useUpstreamSocks")
    if server.useUpstream:
        upstreamServer = config.get("Socks", "upstreamSocksServer").split(":")
        upstreamSocksServer = (upstreamServer[0], int(upstreamServer[1]))
    else:
        upstreamSocksServer = (None,None)
    server.upstreamServer = upstreamSocksServer

    # allowed and denied peers
    ac = config.get("Socks", "allowedClients")
    ac = ac.split(",") if ac else []
    allowedClients = []
    for netrange in ac:
        for client in cidr.printCIDR(netrange):
            if cserverlib.validDomainName(client):
                _, rip = server._resolveHost((client,80))
                logger.debug("allowedClients: resolved %s to %s" %
                                                        (str(client),str(rip)))
                allowedClients.append(rip)
            else:
                allowedClients.append(client)
    server.allowedClients = allowedClients

    dr = config.get("Socks", "deniedRemotes")
    dr = dr.split(",") if dr else []
    deniedRemotes = []
    for netrange in dr:
        deniedRemotes.extend(cidr.printCIDR(netrange))
    server.deniedRemotes = deniedRemotes

class Server():

    def __init__(self, bind_addr=None, config=CONFIG, daemon=False, timeout=None):
        logger.info("initialising server..")
        # read config
        try:
            config = CONFIG if not config else config
            readconfig(self, config)
        except Exception as e:
            logger.error("Failed to process config: '%s'", str(e))
            sys.exit(1)

        # daemon
        if daemon:
            pid = cdaemonise.daemonise(
                name="socksy",
                stderr=LOG,
                stdin=LOG,
                stdout=LOG)

        # check whether a valid bind address is set
        if bind_addr:
            self.bind_addr = bind_addr

        if not self.bind_addr:
            logger.error("Invalid address to bind on: %s!" % str(self.bind))
            return
        else:
            logger.debug("Listing on %s.." % str(self.bind_addr))

        # sockets
        self.bind = cserverlib.build_server(self.bind_addr[0],
                                            self.bind_addr[1])
        self.timeout = timeout

        # setup max open files
        resource.setrlimit(resource.RLIMIT_NOFILE, (self.max_fd, self.max_fd))
        nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
        if not (nofile[0] == self.max_fd and nofile[1] == self.max_fd):
            logger.error("Failed to incread open file limit!")
            sys.exit(2)
        logger.debug("increased open file limit %d" % self.max_fd)

        # drop privileges
        os.setgroups([])
        os.setgid(self.gid)
        os.setuid(self.uid)

        # locks
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

    def start(self):
        logger.info("ready for requests..")

        while True:
            try:
                read, write, excpt = select.select([self.bind],[],[],1)
            except KeyboardInterrupt:
                logger.debug("recognised keyboard interrupt, so stop listing..")
                break

            for s in read:
                if s == self.bind:
                    c = threading.Thread(target=self.__processRequest)
                    c.daemon = True
                    c.start()

                else:
                    logger.error("Socket validation failed. Socket = %s" % str(s))

        logger.info("Terminating socksy..")
        self.bind.close()


    def __processRequest(self):
        success, client, remote = self.__handshake()
        if success:
            cserverlib.remote_recv(client, remote)

    def __handshake(self):

        try:
            method, client, caddr, conto, rmtrslv = socks.socks4a_neg(
                                                                self.bind,
                                                                self.allowedClients,
                                                                self.deniedRemotes)
            logger.debug("method=%s" % method)
        except Exception as e:
            logger.warning("Failed to negotiate socks4:'%s'", e)
            return False, None, None

        # new tcp session
        if method == socks.SOCKS4_TCP_REQUEST:

            try:
                # use socks server
                if self.useUpstream:
                    logger.debug("I am connecting to an upstream SOCKS "
                                 "server at %s:%d",
                                 self.upstreamServer[0],
                                 int(self.upstreamServer[1]))
                    response, remote, raddr = self.__connectToUpstreamServer(conto)
                    ret = True

                # classical and direct connection
                else:
                    logger.debug("Using direct connection.. to %s", conto)

                    remote = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    if self.timeout:
                        logger.debug("setting timeout to %f", self.timeout)
                        remote.settimeout(self.timeout)
                    remote.connect((conto[0],conto[1]))

                #   remote, raddr = cserverlib.build_connect(conto[0],conto[1],rmtrslv)
                    response = socks.SOCKS4_ESTABLISHED
                    raddr = (conto[0], conto[1])
                    ret = True

            except (socket.timeout, socket.error):
                logger.warning("Remote server (%s:%d) not reachable. "
                                "Maybe a timeout.",
                                conto[0], conto[1])
                response = socks.SOCKS4_ERR_CONNECT
                ret = False
                raddr = None
                remote = None

            socks.socks4a_answer(client, raddr, response)

        # domain resolving request
        elif method == socks.SOCKS4_REMOTE_RESOLVE:
            logger.debug("Client wants me to resolve host %s", conto[0])

            # start new thread to resolve request
            c = threading.Thread(target=self.__sendResolvedHost, args=(client, caddr, conto))
            c.daemon = True
            c.start()

            ret = False
            remote = None
            client = None

        # reverse dns request
        elif method == socks.SOCKS4_REMOTE_REVDNS:
            logger.debug("Client wants me to execute reverse dns on %s" % conto[0])

            # start new thread to resolve request
            c = threading.Thread(target=self.__sendResolvedHost, args=(client,caddr, conto, True))
            c.daemon = True
            c.start()

            ret = False
            remote = None
            client = None

        # connection request needs to be denied
        elif method == socks.SOCKS4_REFUSED:
            raddr = (None, None)
            socks.socks4a_answer(client, raddr, method)

            ret = False
            remote = None
            client = None

        # bind request or bad
        else:
            raise Exception("Unknown method %s!" % str(method))

        return ret, client, remote

    def __connectToUpstreamServer(self, conto):
        conret, remote = socks.socks4a_connect(self.upstreamServer,
                                               conto,
                                               self.timeout)
        raddr = self.upstreamServer

        return conret, remote, raddr


    def _resolveHost(self, conto, reverse=False):
        try:
            if self.useUpstream:
                logger.debug("Resolving %s using upstream Server%s.",
                              conto[0],
                              self.upstreamServer)

                if reverse:
                    success, res = socks.socks4a_resolveHostByAddr(
                                                conto[0],
                                                self.upstreamServer)

                else:
                    success, res = socks.socks4a_resolveHost(
                                                conto[0],
                                                self.upstreamServer)

            else:

                if reverse:
                    res = socket.gethostbyaddr(conto[0])[0]
                else:
                    res = socket.gethostbyname(conto[0])

                logger.debug("Resolving %s directly to %s."%(repr(conto[0]),res))
                success = socks.SOCKS4_ESTABLISHED

        except (socket.timeout, socket.gaierror, socket.herror):
            success = socks.SOCKS4_ERR_CONNECT
            res = ""

        return success, res

    def __sendResolvedHost(self,client, caddr, conto, reverse=False):
        response, res = self._resolveHost(conto, reverse)
        logger.debug("res=%s, code=%s" % (res, repr(response)))
        if reverse:
            socks.socks4a_answer(client, (conto[0], conto[1]), response, res)
        else:
            socks.socks4a_answer(client, (res, conto[1]), response)


def activate_venv(venv_dir):

    if not os.path.exists(venv_dir):
        logger.error("%s does not exists" % venv_dir)
        print("ERROR: %s does not exists" % venv_dir)
        return

    activate_this_file = os.path.join(venv_dir, "bin/activate_this.py")
    execfile(activate_this_file, dict(__file__=activate_this_file))


def main():
    if not os.getuid() == 0:
        print("socksy needs to be executed as root!")
        sys.exit(2)

    parser = argparse.ArgumentParser()

    parser.add_argument("-c", help="path to config file")
    parser.add_argument("-d", help="run as daemon",
                        action="store_true")
    parser.add_argument("-t", help="set socket timeout in secs",
                        type=float)
    #parser.add_argument("-v", help="verbosity",
    #                    action="store_true")
    parser.add_argument("--venv",
                        help="use virtual environment")

    args, unknown = parser.parse_known_args()

    #if args.v:
    #    console.setLevel(logging.DEBUG)

    if args.venv:
        activate_venv(args.venv)

    if unknown:
        try:
            add = unknown[0].split(":")
            lip = add[0]
            lport = int(add[1])
            bind = (lip, lport)
        except:
            print("Failed to parse addr to listen on!")
            sys.exit(2)
    else:
        bind = None

    s = Server(bind, args.c, args.d, args.t)
    s.start()

if __name__ == "__main__":
    main()
