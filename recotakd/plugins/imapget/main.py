import ccdClasses as ccd
from imapget import ImapGet
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
import logging
import getopt
import os
import __builtin__

__author__ = 'me'
__version__ = '0.0.1'


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def usage():
    print "-" * 80
    print "imapget - download email via imap account"
    print
    print "-s <server>"
    print "-P <port> [default: SSL -- NOSSL = 143/ SSL = 995]"
    print "-u <user>"
    print "-p <password>"
    print "-e <cryptolayer> [default: SSL] [SSL/NOSSL]"
    #print "-a <access mode> [default: RO] [RO/RW]"
    print
    print "Example:"
    print "exec imapget.plg -s imap.host.tld -u user@host.tld -p password"
    print "-" * 80
    print


def main(dbh, args):
    logger.debug("starting plugin %s" % __name__)

    config = "imapget.conf"
    logger.debug("config:%s" % config)

    args = parseInput(args, logger)
    if args == -1:
        print "Error: parseInput return -1"
        return -1

    result = mainimap(args, logger)

    return result


def saveMail(ic, data, num, mbox):
    """ function to save the downloaded mail """
    path = "./%s/%s/%s" % (ic.server, ic.user, mbox)
    try:
        path = "%s/%s/%s/%s" % (__builtin__.openhome.base_dir, ic.server, ic.user, mbox)
    except:
        pass
    if not os.path.exists(path):
        os.makedirs(path)

    fname = "%s" % (str(num))

    mPath = os.path.join(path, fname)
    print 'Saving Email to ' + mPath
    fw = open(mPath, 'w')
    fw.write(data.encode('utf-8'))
    fw.flush()
    fw.close()

    return 0


def mainimap(args, logger):
    """ main function for downloading imap mails """

    (server, user, password, ssl, port) = args
    iget = ImapGet(server, port, user, password, ssl)

    i = 0
    for data in iter(iget):
        print "Found message in %s" % (iget.mailbox)
        saveMail(iget, data, i, iget.mailbox)
        i += 1

    iget.logout()


def register():
        # returns plugin name and list of plugins category
        # the name must equal directory name of plugin
    plugin = ccd.Plugin("imapget", ["get"])
    plugin.execute = main
    return plugin


def parseInput(args, logger):
    """ parse the input for the script """

    logger.debug("imapget parseInput(args, logger)")

    if not args or not args[0]:
        usage()
        print "Missing arguments"
        return -1

    # set variables to none
    server = None
    user = None
    password = None
    port = 993
    ssl = 'SSL'
    #ro = 'RO'

    # now get command line args
    try:
        opts, rest = getopt.getopt(args, "s:u:p:e:hP:a:")
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
#        elif opt == "-a":
#            ro = arg
        elif opt == "-h":
            usage()
            return -1

    if not server or not user or not password:
        usage()
        print "Missing arguments"
        return -1

    return (server, user, password, ssl, port)

if __name__ == '__main__':
    import sys
    main(None, sys.argv[1:])
