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
# TODO make faster by reading chunks and par. over wordlist
# or is that so we don't accidentally ddos the server

import argparse
import sys
import socket
import logging
import logging.handlers
import itertools as it
import string
import Queue
from ctools import cTuples
from ctools import cUtil
import random
from datetime import datetime

__version__ = 0.35
__author__ = "curesec"
__email__ = "curesec"

# logging
LOG = "/tmp/subdns.log"
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import ccdClasses as ccd

# console handler
#console = logging.StreamHandler()
#console.setLevel(logging.INFO)
#formatter = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
#console.setFormatter(formatter)
#logging.getLogger("").addHandler(console)
#
#WAIT_FOR_THREADS = 0.2


def getRandomString():
    """ generates a random string - this is usefull
        for wildcard tests
    """
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    min = 5
    max = 15
    total = 2
    rnd = ""

    for count in xrange(1, total):
        for x in random.sample(alphabet, random.randint(min, max)):
            rnd += x

    return rnd


def check_wildcard(domain, tries=3):
    wild_enabled = True
    for _ in range(tries):
        sub = getRandomString()
        hostname = sub + '.' + domain
        ip4 = ""
        try:
            ip4 = socket.gethostbyname(hostname)
            if not ip4:
                wild_enabled = False
        except (socket.gaierror, socket.timeout):
            logger.debug("Failed to resolve domain name %s", hostname)
            wild_enabled = False
        except Exception as err:
            # sth else went wrong
            logger.warning(err)
            wild_enabled = False
    if wild_enabled:
        check_wildcard.wc_hosts.put(domain)
        return None
    else:
        return domain

check_wildcard.wc_hosts = Queue.Queue()


def resolve(sub, domain):

    sub = sub.strip()
    domain = domain.strip()

    hostname = sub + '.' + domain
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
        logger.debug("Failed to resolve domain name %s", hostname)
    except Exception as err:
        # sth else went wrong
        logger.warning(err)
    yield (success, hostname, ip4)


class DNSscanner():
    """
    The DNSscanner is a tool that scans for DNS subdomains in
    a multithreaded way. To do so, the scanner uses a wordlist to iterate.
    """
    PORT = 80

    def __init__(self,
                 args,
                 dbhandler=None):

        logger.info("Initialising DNS subdomain scanner..")

        #FIXME this is bad design. one does not simple initalise an object by
        # passing the program arguments ;) we need to parse that in advance
        opt = parse(args)

        self.dbh = dbhandler

        data = []
        if opt.bf_length:
            allchars = string.letters + string.digits
            chars = []
            for cs in opt.charsets:
                if len(cs) < 3 or cs[1] != '-':
                    print 'Invalid charset %s' % cs
                    sys.exit(1)
                start = allchars.find(cs[0])
                if start < 0:
                    print 'Invalid charset %s' % cs
                    sys.exit(1)
                stop = allchars.find(cs[2]) + 1
                if stop < 1:
                    print 'Invalid charset %s' % cs
                if start > stop:
                    start, stop = stop, start
                chars.extend(allchars[start:stop])
            chars.append('')
            data = it.imap(lambda t: ''.join(t),
                           it.product(chars, repeat=opt.bf_length))

        try:
            if not opt.w:
                fnames = []
            else:
                fnames = [opt.w]
            ig_subs = cTuples.cInputGenerator(filenames=fnames,
                                              data=data,
                                              maxthreads=opt.nt,
                                              circle=False,
                                              )
            ig_subs.start()
        except cTuples.ENoInput:
            print 'Please specify a set of subs or a filename containing a sublist'
            sys.exit(1)

        try:
            ig_domains = cTuples.cInputGenerator(filename=opt.T,
                                                 data=opt.t,
                                                 prepare_cb=check_wildcard,
                                                 maxthreads=opt.nt,
                                                 circle=True,
                                                 )
            ig_domains.start()
        except cTuples.ENoInput:
            print 'Please specify a set of domains or a filename containing a domainlist'
            sys.exit(1)

        self.tuples = cTuples.cTuples(inputs=[ig_subs, ig_domains],
                                      prep_callback=resolve,
                                      maxthreads=opt.nt,
                                      delay=opt.delay)
        self.tuples.start()

    def resolve(self):

        """ start resolve """

        start_time = datetime.now()

        print 'Subdomain scan started'

        fmt = "{:60}{:20}"
        print
        print fmt.format('fqdn', 'ip')
        print '-' * 80
        for success, hostname, ip in self.tuples.tuple_q:
            if success:
                print fmt.format(hostname, ip)
                if self.dbh:
                    self.dbh.add(ccd.DnsscanResult(
                        ip=ip,
                        fqdn=hostname)
                    )

        self.tuples.join()

        while True:
            try:
                dom = check_wildcard.wc_hosts.get(False, 0.1)
                print 'Wildcard enabled: %s' % dom
            except Queue.Empty:
                break

        print("\nfinished in %fs" % cUtil.secs(start_time))


def parse(args):
    parser = argparse.ArgumentParser(
        prog="subdns",
        description="subdomain dns scanner v%f" % __version__,
        epilog="Example: subdns.plg -t curesec.com -w wordlist.txt -nt 10"
    )

    parser.add_argument("-w", help="wordlist to scan of subdomains to scan ",
                        default="")
    #parser.add_argument("-v", help="verbosity",
    #                    default=False,
    #                    action="store_true")
    parser.add_argument("-T", help="host file with domains to scan, eg. -T "
                                   "doms.txt")
    parser.add_argument("-t",
                        help="list of hosts to scan, eg. -t curesec.com "
                             "mknd.net",
                        nargs="+",
                        )
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument("-l",
                        help="subdomain length for brutforce (default: 0, e.g. disabled)",
                        type=int,
                        default=0,
                        dest="bf_length"
                        )
    parser.add_argument("-cs",
                        help="charset used for brutforce (default: 0-9 a-z)",
                        default=['0-9', 'a-z'],
                        nargs='+',
                        dest="charsets"
                        )
    parser.add_argument("-nt", help="amount of threads to scan with",
                        type=int,
                        default=10)

    if not args:
        parser.print_help()
        sys.exit(1)

    opt, unknown = parser.parse_known_args(args)

    if unknown:
        print("Unknown arguments found!")
        parser.print_help()
        sys.exit(1)

    return opt

if __name__ == "__main__":
    kwargs, hosts, host_fn = parse(sys.argv[1:])
    scanner = DNSscanner(*kwargs)
    scanner.scan(hosts, host_fn)
