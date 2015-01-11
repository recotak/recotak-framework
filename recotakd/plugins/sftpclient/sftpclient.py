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
#from IPython import embed
from ctools import csockslib
import paramiko
import socket
import sys
import os
import re
import logging
import select

gllogger = logging.getLogger(__name__)

#import own paramiko abstraction library
from ctools.sshlib import socketClass
from ctools.sshlib import sshClass
from ctools.sshlib import sftpClass


OK = 0
ERROR = 1
EXIT = 10

class sftpClient():
    """ sftpclient plugin for ccd """

    def sclient(self,args,
                logger=gllogger):
        """ the main loop, yay! """

        self.logger = logger
        server,port,user,password,method,key = args
#       print args

        socC = socketClass()
        sshC = sshClass()
        sftpC = sftpClass()


        # add user, password or key to the auth
        sshC.user, sshC.password = user, password
        if key !=None:
            sshC.keyfile = os.path.join(key)
        #using this key in this path
        host, port = server, port
        socC.tHost = (server,port)

        #for testing purpose only -- comment out
#       socC.tSocks = ('127.0.0.1',9090)

        #default setting, putting it anyway
        sshC.method = method

        # change logger level
#        log = csockslib.logger
#        log.setLevel('INFO')

        # establish socks4a connection
        # here comes the callback socket
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            s.connect((server, port))
        except Exception as e:
            print 'Connection to %s:%d failed: %s' % (server, int(port), str(e))
            sys.exit(1)

        self.logger.debug("assigning socket to sshC")
        sshC.s = s

        #print("new socket:%s" % str(sshC.s))

        #for testing purpose only   -- comment out
#       sshC.s = socC.connectSocks()

        # create ssh transport
        #print("sshC.createSSH")
        sshC.createSSH()

        # authenticate
        #print("sshC.authSSH")
        r = sshC.authSSH()

        if not r == sshC.LOGIN_SUCCESSFUL:
            print 'Authentication failed!'
            sys.exit(1)

        #open sftp session and go into while loop
        print("sftp = sshC.pm.open_sftp_client")
        sftp = sshC.pm.open_sftp_client()
        sftpC.sftp = sftp


        while 1:
            """ endless loop """
            sftp.chdir('.')
            cwd = sftp.getcwd()

            shell = "\r%s:%d %s > " % (host,int(port),cwd)
            #shell = "%s:%d %s > " % (host,int(port),cwd)

#                self.logger.debug("waiting for user input..")
            sys.stdout.write(shell)
            sys.stdout.flush()
            while True:
                try:
                    inp = sys.stdin.readline().rstrip()
                    if inp:
                        break
                except KeyboardInterrupt:
                    inp = ""


#            except Exception as e:
#                logger.error("error while waiting for input:%s", e)
#                continue

            inp = inp.split(' ')
            cmd = inp[0]
            params = inp[1:]

            if cmd == "exit" or cmd == "q":
                sshC.exitSession()

            elif cmd == "la" or cmd == "ll":
                sftpC.listDir()

            elif cmd == "ls" or cmd == "l":
                sftpC.listDirAttr()

            elif cmd == "lcwd":
                p = os.getcwd()
                print p

            elif cmd == "lls":
                p = os.listdir('.')
                for ele in p:
                    print ele

            elif cmd == "help":
                sftpC.sftpHelp()

            elif cmd == "get":
                sftpC.sftpGet(params)

            elif cmd == "put":
                sftpC.sftpPut(params)

            elif cmd == "open" or cmd == "cat":
                sftpC.sftpOpen(params)

            elif cmd == "cp" or cmd == "copy":
                sftpC.sftpCopy(params)

            elif cmd == "mkdir" or cmd == "mk":
                sftpC.sftpMkdir(params)

            elif cmd == "rmdir" or cmd == "rmd":
                sftpC.sftpRmdir(params)

            elif cmd == "rm" or cmd == "remove" or cmd == "delete":
                sftpC.sftpRmfile(params)

            elif cmd == "mv" or cmd == "rename":
                sftpC.sftpRename(params)

            elif cmd == "unlink":
                sftpC.sftpUnlink(params)

            elif cmd == "stat":
                sftpC.sftpStat(params)

            elif cmd == "lstat":
                sftpC.sftpLstat(params)

            elif cmd == "symlink":
                sftpC.sftpSymlink(params)

            elif cmd == "cd":
                sftpC.sftpChdir(params)

            else:
                print "unknown command"

if __name__ == "__main__":
    sftpClient.sclient()
    #main()

