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
import getopt
import sys
import logging
from sftpclient import sftpClient


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def main(dbh, args):
    logger.debug("starting plugin %s" % __name__)


    sftpC = sftpClient()

    args = parseInput(args, logger)
    if args == -1:
        return -1

    sftpC.sclient(args, logger)

    return True
    #return result


def usage():
    """ our awesome usage """
    print "-" * 80
    print "sftp client for ccd"
    print
    print "-s <server>"
    print "-P <port> [default: 22]"
    print "-u <user>"
    print "-p <password>"
    print "-e <method> [default: password]"
    print "   supportet: password, key"
    print "-k keyfile"
    print "-h help"
    print
    print "-" * 80


def register():
    # returns plugin name and list of plugins category
    # the name must equal directory name of plugin
    plugin = ccd.Plugin("sftpclient", ["connect"])
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

    if method == 'key' and not key:
        print "Error: Define path to key!"
        usage()

    #elif method == 'key' and key:
    #    try:
    #        print "Joining rootpath and key"
    #        #keypath = os.path.join(rootpath, key)
    #        #kstat = os.stat(keypath)
    #    except:
    #        print "Error: Key does not exist/Wrong file perms!"
    #        print "Did you upload the key with upload command?"
    #        key = None
    #        return -1

    if not server or not user:
        usage()
        return -1

    logger.debug(server)
    logger.debug(user)
    return (server, port, user, password, method, key)


if __name__ == "__main__":
    main(None, sys.argv[1:])
