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
import logging
import logging.handlers
from ctools import cTuples
from datetime import datetime
import ccdClasses as ccd
from ctools.cBing.bing import BingQuery
from ctools import cUtil

__version__ = 0.35
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "ip2dns_bing"

# logging
LOG = "/tmp/" + __plgname__ + ".log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def resolve(ip):
    try:
        ip = ip[0]
    except:
        pass
    try:
        bing_q = BingQuery()
        bing_q.set_count(resolve.max_results)
        query = "ip:%s" % ip
        logger.info('Query: %s', query)
        bing_q.set_query(query)
        bing_q.search()
        for link in bing_q.links:
            yield (ip, link.encode('utf-8'))
    except Exception, e:
        logger.warning(e)
    raise StopIteration


class Ip2Dns_Bing():
    """

    input:
        socketserver   socks proxy server
        nthreads       numer of threads
        dbhandler      database handler
    """
    def __init__(self,
                 args,
                 dbhandler=None):

        """
        Ip2Dns_Bing class gets dns records by searching
        Bing for ip:<ip>.

        input:
            args            cmdline arguments without argv[0]
            dbhandler       database handler
        """

        logger.info("Initialising Dns2Ip ...")
        self.dbh = dbhandler

        opt = parse(args)

        self.nthreads = opt.nthreads
        resolve.max_results = opt.max_results

        try:
            ig_targets = cTuples.cInputGenerator(filename=opt.target_fn,
                                                 data=opt.targets,
                                                 maxthreads=opt.nthreads,
                                                 circle=False,
                                                 expand_cb=lambda t: cUtil.mkIP2(t, noResolve=True)
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        ig_targets.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets],
                                      prep_callback=resolve,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def resolve(self):

        """ Create threads, set up task queue and start resolving. """

        logger.debug("Starting resolve")

        start_time = datetime.now()

        fmt = '{:20}{:60}'
        for ip, hostname in self.tuples.tuple_q:
            print fmt.format(ip, hostname)
            if self.dbh:
                self.dbh.add(ccd.DnsscanResult(
                    ip=ip,
                    fqdn=hostname)
                )

        self.tuples.join()
        print("\nfinished in %fs" % cUtil.secs(start_time))


def parse(args):

    """ parse cmd line options sys.argv[1:].
        Also checks if provided options are valid.

        Input:
            args        cmd line without argv[0]

        Output:
            parsed args
    """

    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="reverse dns lookup v%f" % __version__,
        epilog=
        """  Examples:
            ip2dns_bing.plg -T ips.txt -tr 91.250.101.170 -nt 3
            ip2dns_bing.plg -t 91.250.101.170 -mr 100 -nt 1
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-T",
                        dest='target_fn',
                        default='',
                        help="path to file with a newline seperated list of ips (or ranges or masks)," +
                             " e.g -i targets.txt")
    parser.add_argument("-t",
                        dest='targets',
                        default=[],
                        nargs='+',
                        help="list of IPs or IP ranges to resolve, e.g. -t 8.8.8.0/24 82.165.197.1")
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument("-nt",
                        dest='nthreads',
                        help="number of threads to scan with (default 1)",
                        type=int,
                        default=1)
    parser.add_argument("-mr",
                        dest='max_results',
                        help="max number of search results per IP (default 5)",
                        type=int,
                        default=5)

    # print help if no cmd line parameters are provided
    if not args or not args[0]:
        parser.print_help()
        sys.exit(1)

    # parse arguments
    opt = parser.parse_args(args)

    return opt
