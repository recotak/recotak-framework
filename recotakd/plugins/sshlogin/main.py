#from ccdClasses import Plugin, InvalidArgumentError
import ccdClasses as ccd
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

import interactive
import __builtin__
import logging
import termios
import getopt
import select
import time
import imp
import sys
import tty
import os
import socket

from ctools.sshlib import sshClass
#from ctools.sshlib import socketClass

LOG_IP = "127.0.0.1"
LOG_PORT = 3002

def main(dbh, args):
    #sh = logging.handlers.SocketHandler(LOG_IP, LOG_PORT)
    #sh.setLevel(logging.DEBUG)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    #logger.addHandler(sh)
    logger.debug("starting plugin %s" % __name__)

    parsed_args = parseInput(args, logger)
    if parsed_args == -1:
        return -1

    logger.debug("parsed_args:%s", parsed_args)
    try:
        sshlogin(parsed_args, logger)
    except Exception as e:
        print 'Error: %s' % str(e)
        sys.exit(1)

    return True

def sshlogin(args, logger):
    """ sshlogin function """

    #is ccd calling us? if so put it to 1
    #callback = 1

    logger.debug("creating sshClass..")
    sshC = sshClass()

    logger.debug("creating socketClass..")
#    socC = socketClass()

    server, port, sshC.user, sshC.password, sshC.method, sshC.keyfile = args
#    socC.tHost = (server,port)

    #test line -- comment out
    #socC.tSocks = tuple(('127.0.0.1',9090))

    if sshC.method=='key':
        sshC.keyfile = __builtin__.openany(sshC.keyfile)

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.connect((server, port))
    except Exception as e:
        print 'Connection to %s:%d failed: %s' % (server, port, str(e))
        sys.exit(1)

    logger.debug("assigning socket to sshC")
    sshC.s = s

    print "Connecting %s@%s:%d " % (sshC.user,server,port)

    logger.debug("creating ssh..")
    sshC.createSSH()

    logger.debug("authenticate ssh..")
    r = sshC.authSSH()
    if not r == sshC.LOGIN_SUCCESSFUL:
        print 'Authentication failed!'
        sys.exit(1)

    sess = sshC.pm.open_channel('session')
    sess.get_pty()
    sess.invoke_shell()
    #after calling everything is fucked up obviously a fd problem
    #please FIXME
    interactive.interactive_shell(sess)

    logging.debug("close")
    sess.close()

    return -1

def usage():
    """ my awesome usage """
    print "-"*80
    print "ssh client for ccd"
    print
    print "-s <server>"
    print "-P <port> [default: 22]"
    print "-u <user>"
    print "-p <password>"
    print "-e <method> [default: password]"
    print "   supportet: password, key"
    print "-k keyfile"
    print "-h help"
    print "-"*80

def register():
    # returns plugin name and list of plugins category
    # the name must equal directory name of plugin
    plugin = ccd.Plugin("sshlogin", ["connect"])
    plugin.execute = main
    plugin.interactive = True
    return plugin

def parseInput(args, logger):
    """ parse the input for the script """

    logger.debug("parsing input")

    #set variables to none
    server = None
    user = None
    password = None
    port = 22
    method = 'password'
    key = None
    helpme = 0

    # now get command line args
    try:
        opts, rest = getopt.getopt(args, "s:u:p:e:k:hP:")
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
            port = int(arg)
        elif opt == "-e":
            method = arg
        elif opt == "-k":
            key = arg
        elif opt == "-h":
            helpme == 1
        else:
            logger.debug(usage())
            return None

    if helpme == 1:
        usage()
        return -1

    if method == 'key' and key == None:
        print "Error: Define path to key!"
        usage()

    if server == None or user == None:
        usage()
        return -1

    logger.debug(server)
    logger.debug(port)
    logger.debug(user)

    return (server,port,user,password,method,key)

if __name__ == '__main__':
    import sys
    main(None, sys.argv[1:])
