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
import logging.handlers
import time
from datetime import datetime
import ccdClasses as ccd
from ctools import cTuples
from ctools import cUtil
from ctools import cDns

__version__ = 0.35
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "dns2ip"

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


def resolve(hostname):
    """
    resolve callback.

    input:
        hostname        (hostname to be resolved, )

    output:
        (success, hostname, ip)
        success         indicates wether resolve was successful
        hostname        given hostname to resolve
        ip              resolved ip for hostname or '' on failure
    """

    # get argument from tuple (hostname, )
    logger.info('resolving: ' + repr(hostname))
    hostname = hostname.strip()
    ip4 = ""
    success = False
    try:
        answer = cDns.gethostbyname(hostname)
        for record in answer:
            if record['rtype'] == 'A':
                yield (True, record['domainame'].strip('.'), record['rdata'])
                success = True
            elif record['rtype'] == 'MX':
                mx_answer = cDns.gethostbyname(record['rdata'].split()[-1])
                for record in mx_answer:
                    if record['rtype'] == 'A':
                        yield (True, record['domainame'].strip('.'), record['rdata'])
            #yield(True, record['rtype'], record['rdata'])
        #ip4 = socket.gethostbyname(hostname)
        # ip == hostname happens if hostname is actually already an ip address,
        # in which case we mark the resolve as failed
    except (socket.gaierror, socket.timeout):
        # could not resolve
        logger.warning("Failed to resolve domain name %s", hostname)
    except Exception as err:
        # sth else went wrong
        logger.warning(err)

    if not success:
        yield (False, hostname, ip4)
    raise StopIteration


class Dns2Ip():
    def __init__(self,
                 args,
                 dbhandler=None):

        """
        Dns2IP class resolves hostnames.

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

        """ start resolve """

        logger.info("Starting %s", __plgname__)
        start_time = datetime.now()

        print "Starting resolve"
        print '-' * 80

        fmt = "{:65}{:>15}"
        nresolved = 0
        nfailed = 0
        hn_failed = []
        for success, hostname, ip in self.tuples.tuple_q:
            if success:
                nresolved += 1
                print fmt.format(hostname, ip)
                if self.dbh:
                    self.dbh.add(ccd.DnsscanResult(
                        ip=ip,
                        fqdn=hostname)
                    )
            else:
                nfailed += 1
                hn_failed.append(hostname)

        self.tuples.join()

        print '-' * 80
        print "finished in %fs" % cUtil.secs(start_time)
        print
        print "resolved %d hostnames" % nresolved
        print "failed to resolve %d hostnames" % nfailed
        if hn_failed:
            out_failed_fn = 'failed_resolve_' + time.strftime("%Y_%m_%d_%H_%M_%S")

            with __builtin__.openhome(out_failed_fn, 'w') as out_failed_fd:
                out_failed_fd.write('\n'.join(hn_failed))
                out_failed_fd.flush()
                print "\tsee %s" % out_failed_fd.name
        print


def parse(args):

    """ parse cmd line options sys.argv[1:].

        Input:
            args        cmd line without argv[0]

        Output:
            parsed args
    """

    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="dns resolve v%f" % __version__,
        epilog=
        """  Examples:
            dns2ip.plg -t recotak.org
            dns2ip.plg -T hosts.txt -nt 100
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-T",
                        dest='target_fn',
                        default='',
                        help="path to file with a newline seperated list of targets," +
                             " e.g -i targets1.txt")
    parser.add_argument("-t",
                        dest='targets',
                        default=[],
                        nargs='+',
                        help="host name(s) to resolve, e.g. -t google.com")
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

    # print help if no cmd line parameters are provided
    if not args or not args[0]:
        parser.print_help()
        sys.exit(0)

    # parse arguments
    opt = parser.parse_args(args)

    return opt


def test():
    import os
    import time
    import sys
    import __builtin__
    if not hasattr(__builtin__, 'openany'):
        __builtin__.openany = open
        __builtin__.openhome = open
        __builtin__.openshared = open

    testdir = 'testdir'
    if not os.path.exists(testdir):
        os.mkdir(testdir)

    timestamp = time.strftime("%Y-%m-%d_%H:%M:%S")
    out_path = '%s/%s_%s' % (testdir, 'out', timestamp)
    fd_out = open(out_path, 'w')
    sys.stdout = fd_out

    args = [
        ['-t', 'www.google.com'],
        ['-T', 'config/hostnames.txt', '-nt', '100'],
        [],
    ]
    for a in args:

        timestamp = time.strftime("%Y-%m-%d_%H:%M:%S")

        log_name = 'log_' + '_'.join(a)
        log_name = log_name.replace('/', '.')
        log_path = '%s/%s_%s' % (testdir, log_name, timestamp)
        global logger
        logger = logging.getLogger(log_path)
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.RotatingFileHandler(log_path)
        logger.addHandler(handler)

        print '-' * 80
        print repr(a)
        print '-' * 80
        print
        dns2ip = Dns2Ip(
            a,
        )
        dns2ip.resolve()
        logger.removeHandler(handler)
        handler.close()

    fd_out.close()


if __name__ == "__main__":
    test()
