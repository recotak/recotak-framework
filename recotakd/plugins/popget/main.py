import ccdClasses as ccd
import logging
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
import poplib
import getopt
import socket
import time
import sys
import __builtin__
import os

__author__ = 'me'
__version__ = '0.0.1'


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def usage():
    print "-" * 80
    print "popget - download email via pop account"
    print "pop mails on server are not deleted"
    print
    print "-s <server>"
    print "-P <port> [default: SSL --  NOSSL = 110/ SSL = 995]"
    print "-u <user>"
    print "-p <password>"
    print "-e <cryptolayer> [default: SSL]"
    print
    print "Example:"
    print "exec popget.plg -s pop3.host.tld -u user@host.tld -p password"
    print "-" * 80
    print


def main(dbh, args):
    logger.debug("starting plugin %s" % __name__)

    config = "popget.conf"
    logger.debug("config:%s" % config)

    args = parseInput(args, logger)
    if args == -1:
        print "Error: parseInput return -1"
        return -1

    result = mainpop(args, logger)

    return result


def mainpop(args, logger):
    """ main pop, function gets emails from remote system """

    print args

    pop3server, pop3port, pop3user, pop3pass, pop3type, msg = args
    if pop3server is None or pop3user is None or pop3pass is None or pop3type is None:
        print "Missing argument"
        return -1

    buf = []

    pop3dir = "./%s/%s" % (pop3server, pop3user)
    try:
        pop3dir = "%s/%s/%s" % (__builtin__.openhome.base_dir, pop3server, pop3user)
    except:
        pass
    if not os.path.exists(pop3dir):
        os.makedirs(pop3dir)

    data = "[+] Connecting [%s] [%s/%s]\n" % (pop3server, pop3user, pop3pass)
    buf.append(data)
    if pop3type == "SSL":
        print "[+] SSL enabled"
        try:
            server = poplib.POP3_SSL(pop3server)
        except socket.error:
            print "[-] Timeout."
            sys.exit(1)
    elif pop3type == "NOSSL":
        server = poplib.POP3(pop3server)
    else:
        print "[-] Sorry. Unknown type"
        print "[-] Specify SSL/NOSSL"
        sys.exit(1)

    server.user(pop3user)

    try:
        server.pass_(pop3pass)
        data = "[+] Logged in!\n"
        buf.append(data)

    except poplib.error_proto:
        data = "[-] Wrong Password!\n"
        buf.append(data)
        sys.exit(1)
    try:
        print server.getwelcome()
        msgCount, msgBytes = server.stat()
        print "There are", msgCount, "mail messages in ", msgBytes, "bytes"
        print server.list()
        print "-" * 80
        print "[+] Retrieving Emails"

        for i in range(msgCount):
            email_name = "%s/%d-%s@%s" % (pop3dir, i, pop3user, pop3server)
            print email_name
            email = open(email_name, "w")
            hdr, message, octets = server.retr(i + 1)
            print "[+] Retreiving Email No. %d" % i
            for line in message:
                line = line + "\n"
                email.write(line)
            email.close()
            print "-" * 80

            if i < msgCount - 1:
                time.sleep(1)
    finally:
        server.quit()


def register():
    # returns plugin name and list of plugins category
    # the name must equal directory name of plugin
    plugin = ccd.Plugin("popget", ["get"])
    plugin.execute = main
    return plugin


def parseInput(args, logger):
    """ parse the input for the script """

    logger.debug("popget parseInput(args, logger)")

    # set variables to none
    server = None
    user = None
    password = None
    port = 995
    ssl = 'SSL'
    msg = 'MessageInABottle!'

    # now get command line args
    try:
        opts, rest = getopt.getopt(args, "s:u:p:e:hP:")
    except:
        logger.error("invalid argument")
        return usage()

    for opt, arg in opts:
        if opt == "-s":
            server = arg
        elif opt == "-u":
            user = arg
        elif opt == "-p":
            password = arg
        elif opt == "-P":
            port = arg
        elif opt == "-e":
            ssl = arg
        elif opt == "-h":
            usage()
            return -1

    if server is None or user is None or password is None:
        usage()
        print "Missing arguments"
        return -1

    return (server, port, user, password, ssl, msg)


if __name__ == '__main__':
    main(None, sys.argv[1:])
