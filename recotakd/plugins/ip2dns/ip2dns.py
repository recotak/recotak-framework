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
import __builtin__
import argparse
import sys
import socket
import logging
import time
from datetime import datetime
import ccdClasses as ccd
from ctools import cUtil
from ctools import cTuples

__version__ = 0.1
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "ip2dns"

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


def resolveIP(ip):

    """
    Performs a reverse dns lookup.
    ATTENTION: does not work via tor proxy.

    input:
        ip             IP address to  resolve
    """

    try:
        ip = ip[0]
    except:
        pass
    hostname = ""
    success = False
    try:
        hostname = socket.gethostbyaddr(ip)
        if hostname:
            if isinstance(hostname, tuple):
                # the socksyfied resolve returns a tuple,
                # where the std. python socket resolve hust returns a
                # string
                hostname = hostname[0]
            success = True
    except (socket.gaierror, socket.timeout):
        logger.warning("Failed to resolve domain ip %s", ip)
    except Exception as err:
        logger.error(str(err))
    yield (success, ip, hostname)
    raise StopIteration


class Ip2Dns():
    def __init__(self,
                 args,
                 dbhandler=None):

        """
        Ip2Dns class gets dns records for one or more ip addresses in parrallel.

        input:
            args            cmdline arguments without argv[0]
            dbhandler       database handler
        """

        logger.info("Initialising Dns2Ip ...")
        opt = parse(args)

        self.dbh = dbhandler

        try:
            ig_targets = cTuples.cInputGenerator(filename=opt.target_fn,
                                                 data=opt.targets,
                                                 maxthreads=opt.nthreads,
                                                 circle=False,
                                                 expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                 noResolve=True
                                                                                 ),
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        ig_targets.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets],
                                      prep_callback=resolveIP,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def resolve(self):

        """ start resolve """

        logger.info("Starting %s", __plgname__)
        start_time = datetime.now()

        print "Starting reverse lookup"
        print '-' * 80

        fmt = '{:20}{:>60}'
        nresolved = 0
        nfailed = 0
        ips_failed = []
        for success, ip, hostname in self.tuples.tuple_q:
            if success:
                nresolved += 1
                print fmt.format(ip, hostname)
                if self.dbh:
                    self.dbh.add(ccd.DnsscanResult(
                        ip=ip,
                        fqdn=hostname)
                    )
            else:
                nfailed += 1
                ips_failed.append(ip)

        self.tuples.join()

        print '-' * 80
        print "finished in %fs" % cUtil.secs(start_time)
        print
        print "resolved %d ips" % nresolved
        print "failed to resolve %d ips" % nfailed
        if ips_failed:
            out_failed_fn = 'failed_resolve_' + time.strftime("%Y_%m_%d_%H_%M_%S")

            if not hasattr(__builtin__, 'openhome'):
                __builtin__.openhome = open
            with __builtin__.openhome(out_failed_fn, 'w') as out_failed_fd:
                out_failed_fd.write('\n'.join(ips_failed))
                out_failed_fd.flush()
                print "\tsee %s" % out_failed_fd.name
        print


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
            ip2dns.plg -t 91.250.101.170
            ip2dns.plg -T ips.txt -nt 300
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
                        help="number of threads to scan with (default 50)",
                        type=int,
                        default=50)

    # print help if no cmd line parameters are provided
    if not args or not args[0]:
        parser.print_help()
        sys.exit(1)

    # parse arguments
    opt = parser.parse_args(args)

    # we need at least one targetname to work with
    if not (opt.target_fn or opt.targets or opt.range_targets):
        parser.print_help()
        print '----> Please specify at least one targetname via -T or -t'
        sys.exit(1)

    return opt
