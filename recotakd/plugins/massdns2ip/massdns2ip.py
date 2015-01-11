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
import argparse
import sys
import socket
import logging
from datetime import datetime
from ctools import cUtil
from ctools import cTuples
import ccdClasses as ccd

__version__ = 0.1
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "massdns2ip"

# logging
LOG = "/tmp/" + __plgname__ + ".log"
FORMAT = '%(asctime)s - %(name)s - %(levelname)s' + \
    '- %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# default list of all tlds to try
ALL_TLDS = ['com', 'org', 'de', 'net']


def resolve(word, tld):

    """
    resolve callback.
    Concatenates a word with a list of top level domains.
    The concatenated hostname is tried to be resolved.

    input:
        word        domain part
        tld         tld part

    output:
        (success, hostname, ip)
        success         indicates wether resolve was successful
        hostname        word.tld attempted to resolve
        ip              resolved ip for word.tld or '' on failure
    """

    # get argument from tuple (word, )
    word = word.strip()
    tld = tld.strip()

    hostname = word + '.' + tld
    ip4 = ""
    # reset success flag
    success = False
    try:
        ip4 = socket.gethostbyname(hostname)
        if ip4:
            # it worked, we got an ip
            success = True
    except (socket.gaierror, socket.timeout):
        # could not resolve
        logger.warning("Failed to resolve domain name %s", hostname)
    except Exception as err:
        # sth else went wrong
        logger.warning(err)
    yield (success, hostname, ip4)


class Dns2Ip():
    def __init__(self,
                 args,
                 dbhandler=None):

        """
        Dns2IP concatenates words from a wordlist file with top level domains
        and tries to resove the resulting hostnames.

        input:
            args            cmdline arguments without argv[0]
            dbhandler       database handler
        """

        logger.info("Initialising Dns2Ip ...")
        opt = parse(args)
        resolve.tlds = opt.tld

        self.dbh = dbhandler
        try:
            ig_words = cTuples.cInputGenerator(filename=opt.wordlist_fn,
                                               data=opt.wordlist,
                                               maxthreads=opt.nthreads,
                                               circle=False,
                                               )
            ig_words.start()
        except cTuples.ENoInput:
            print 'Please specify a set of words or a filename containing a wordlist'
            sys.exit(1)

        try:
            ig_tlds = cTuples.cInputGenerator(filename=opt.tld_fn,
                                              data=opt.tld,
                                              maxthreads=opt.nthreads,
                                              circle=True,
                                              )
            ig_tlds.start()
        except cTuples.ENoInput:
            print 'Please specify a set of tlds or a filename containing a tldlist'
            sys.exit(1)

        self.tuples = cTuples.cTuples(inputs=[ig_words, ig_tlds],
                                      prep_callback=resolve,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def resolve(self):

        """ start resolve """

        logger.info("Starting %s", __plgname__)

        print 'Starting mass dns resolve'
        start_time = datetime.now()

        fmt = "{:60}{:20}"
        for success, hostname, ip in self.tuples.tuple_q:
            if success:
                print fmt.format(hostname, ip)
                if self.dbh:
                    self.dbh.add(ccd.DnsscanResult(
                        ip=ip,
                        fqdn=hostname)
                    )

        self.tuples.join()
        print("\nfinished in %fs" % cUtil.secs(start_time))


def parse(args):

    """ parse cmd line options sys.argv[1:].

        Input:
            args        cmd line without argv[0]

        Output:
            parsed args
    """

    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description=
        """
        mass dns resolve %f
        This plugin combines a wordlist with a set of top level domains and tries to revolve the
        thereby concatenated hostnames.
        """ % __version__,
        epilog=
        """  Examples:
            massdns2ip.plg -t blubb -l com -nt 1
            massdns2ip.plg -T e_wordlist -L tlds-alpha-by-domain.txt -nt 400
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t",
                        dest='wordlist',
                        nargs='+',
                        default=[],
                        help="wordlist")
    parser.add_argument("-T",
                        dest='wordlist_fn',
                        default='',
                        help="wordlist file")
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument("-l",
                        dest='tld',
                        nargs='+',
                        default=[],
                        help="List of top level domain names (without the dot)." +
                             "Keyword \'ALL\' defaults to: %s" % ', '.join(ALL_TLDS))
    parser.add_argument("-L",
                        dest='tld_fn',
                        default='',
                        help="Path to file containing list of top level domain names (without the dot)")
    parser.add_argument("-nt",
                        dest='nthreads',
                        help="number of threads (default 100)",
                        type=int,
                        default=100)

    # print help if no cmd line parameters are provided
    if not args or not args[0]:
        parser.print_help()
        sys.exit(0)

    # parse arguments
    opt = parser.parse_args(args)

    if 'ALL' in opt.tld:
        opt.tld = ALL_TLDS

    return opt
