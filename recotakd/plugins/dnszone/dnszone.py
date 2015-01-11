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
import __builtin__
import argparse
import sys
import time
from ctools import cDns
from ctools import cUtil
from ctools import cTuples
from datetime import datetime
import ccdClasses as ccd
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


__version__ = 0.1
__plgname__ = 'dnszone'


def get_ans(zone):
    zone = zone.strip()
    dns = cDns.DNSQuery()
    try:
        #answer = dns.getauthns(zone)
        ns = dns.getauthns(zone)
    except Exception as e:
        logger.warning(e)
        return (zone, [])
    if not ns:
        logger.warning('Unable to determine nameserver for %s', zone)
        return (zone, [])
    #ns = [a['rdata'] for a in answer]
    logger.info('Name Servers for %s: %s', zone, ', '.join(ns))
    return (zone, ns)


def ztrans(zone_nameserver):
    zone, ns = zone_nameserver
    if not ns:
        yield(False, zone, 'Unable to determine name server for zone')
    dns = cDns.DNSQuery()
    success = False
    try:
        tr = dns.zonetransfer(zone, ns)
        if tr:
            success = True
    except Exception as e:
        tr = e
        logger.warning(e)
    if not tr:
        tr = 'Zone transfer failed on all servers'
        logger.warning('Zone transfer failed on all servers')
        success = False
    yield (success, zone, tr)
    raise StopIteration


class DnsZone(object):
    def __init__(self, args, dbh=None):
        opt = parse(args)
        self.dbh = dbh
        #self.qname = opts.zone

        self.dbh = dbh

        try:
            ig_targets = cTuples.cInputGenerator(filename=opt.T,
                                                 data=opt.t,
                                                 maxthreads=opt.nthreads,
                                                 prepare_cb=get_ans,
                                                 circle=False,
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        ig_targets.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets],
                                      prep_callback=ztrans,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def transfer(self):
        print 'Starting Zonetransfers'
        start = datetime.now()
        ntrans = 0
        nfailed = 0
        failed = []
        for success, zone, tr in self.tuples.tuple_q:
            if success:
                ntrans += 1
                for server, data in tr.items():
                    print
                    print '-' * 80
                    print 'Answer from server %s for zone %s' % (server, zone)
                    print '-' * 80
                    for rr in data:
                        print "%(domainame)s\t%(ttl)d\t%(rclass)s\t%(rtype)s\t%(rdata)s" % rr
                        if self.dbh:
                            try:
                                r = ccd.DnsRecordResult(
                                    domainame=rr['domainame'],
                                    ttl=rr['ttl'],
                                    rclass=rr['rclass'],
                                    rtype=rr['rtype'],
                                    rdata=rr['rdata']
                                )
                                self.dbh.add(r)
                            except Exception as e:
                                print e
            else:
                nfailed += 1
                failed.append(zone + ': ' + repr(tr))

        print '-' * 80
        print "finished in %fs" % cUtil.secs(start)
        print
        print "Transfer succeded on %d zones" % ntrans
        print "Transfer failed on %d zones" % nfailed
        if failed:
            out_failed_fn = 'failed_zonetransfer_' + time.strftime("%Y_%m_%d_%H_%M_%S")

            with __builtin__.openhome(out_failed_fn, 'w') as out_failed_fd:
                out_failed_fd.write('\n'.join(failed))
                out_failed_fd.flush()
                print "\tsee %s" % out_failed_fd.name
        print


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="DNS zone transfer v%f" % __version__,
        epilog=
        """  Examples (if you use an external proxy or tor, make sure /etc/resolve.conf doesn't point to a local ip):
            dnszone.plg -T hostnames.txt -nt 400
            dnszone.plg -t zonetransfer.me
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t',
                        nargs='+',
                        default=[],
                        help='zone names'
                        )
    parser.add_argument('-T',
                        default='',
                        help='file containing zone names'
                        )

    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
#    parser.add_argument('-ns',
#                        help='nameserver (default auth. ns for zone)',
#                        required=False,
#                        )
#    parser.add_argument('-port',
#                        help='port (default 53)',
#                        type=int,
#                        default=53
#                        )
    parser.add_argument("-nt",
                        dest='nthreads',
                        help="number of threads (default 1)",
                        type=int,
                        default=1)

    if not args:
        parser.print_help()
        sys.exit(1)

    opts = parser.parse_args(args)
    return opts
