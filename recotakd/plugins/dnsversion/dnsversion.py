#!/usr/bin/python

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
import argparse
import sys
from ctools import cDns
import ccdClasses as ccd
from ctools import cUtil
from ctools import cTuples
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


__plgname__ = 'dnsversion'

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


def bversion(target):
    nameserver, hostname = target
    logger.info('Nameserver: %s', nameserver)
    dnsv = 'error'
    try:
        ip, port = nameserver
        try:
            dns = cDns.DNSQuery(server=ip, port=port)
            tr = dns.version()[0]
            dnsv = tr['rdata']
            yield(ip, hostname, port, dnsv)
        except Exception as e:
            logger.error('Error while getting dns version from %s -> %s', hostname, e)
    except Exception, e:
        logger.error('Error while processing %s on %s', hostname, nameserver)
    raise StopIteration


class DnsVersion(object):
    def __init__(self, args, dbh=None):
        opts = parse(args)
        self.dbh = dbh
        self.port = opts.port

        try:
            ig_targets = cTuples.cInputGenerator(filename=opts.T,
                                                 data=opts.t,
                                                 maxthreads=opts.nthreads,
                                                 circle=False,
                                                 expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                 ports=[opts.port],
                                                                                 noSplit=True,
                                                                                 ),
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        ig_targets.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets],
                                      prep_callback=bversion,
                                      maxthreads=opts.nthreads,
                                      delay=opts.delay)
        self.tuples.start()

    def getversion(self):
        start = datetime.now()
        print 'Getting Bind versions ...'

        for ip, hostname, port, bindversion in self.tuples.tuple_q:
            print '%s\t%s' % (hostname or ip, bindversion)
            if self.dbh:
                r = ccd.DnsVersionResult(
                    ip=ip,
                    fqdn=hostname,
                    port=port,
                    bindversion=bindversion
                )
                self.dbh.add(r)

        self.tuples.join()
        print
        print 'Plugin finished in %f seconds' % cUtil.secs(start)


def parse(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('-t',
                        help='nameserver',
                        nargs='+',
                        default=[],
                        )
    parser.add_argument('-T',
                        help='nameserver file',
                        default='',
                        )
    parser.add_argument('-port',
                        help='port (default 53)',
                        type=int,
                        default=53
                        )
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument("-nt",
                        dest='nthreads',
                        help="number of threads (default 50)",
                        type=int,
                        default=50)
    if not args:
        parser.print_help()
        sys.exit(1)

    opts = parser.parse_args(args)

    return opts


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
        ['-T', 'config/ns5.txt', '-nt', '100'],
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
        dnsversion = DnsVersion(
            a,
        )
        dnsversion.getversion()
        logger.removeHandler(handler)
        handler.close()

    fd_out.close()


if __name__ == "__main__":
    test()
