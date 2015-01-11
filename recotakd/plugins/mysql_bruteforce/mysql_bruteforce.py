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
import sys
from datetime import datetime
import logging
from ctools import cUtil
from ctools import cMysql
import argparse
import ccdClasses as ccd
from ctools import cTuples
import threading


__version__ = '0.0'
__author__ = 'feli'
__plgname__ = 'mysql_bruteforce'


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


def brute(target, user, passw):
    ip, port = target
    port = int(port)
    status = False
    ustr = user + '/' + ip + ':' + str(port)
    if ustr in brute.inv_users:
        logger.info('found %s in inv users' % ustr)
        raise StopIteration
    try:
        mysql = cMysql.MysqlClient(ip, port=port)
        status = mysql.login(user, passw)
        if status:
            yield (user, passw, ip, port, True)
    except Exception, e:
        logger.debug('Error on %s/%s@%s:%d --> %s' % (passw, user, ip, port, e))
    finally:
        if mysql:
            mysql.close()
    if status:
        with brute.lock:
            logger.info('adding %s to inv users' % ustr)
            brute.inv_users.append(ustr)
    raise StopIteration

brute.inv_users = []
brute.lock = threading.Lock()


class MysqlBruteforce():
    def __init__(self,
                 args,
                 dbh=None):

        """
        Initialize and run MysqlBruteforce

        input:
            args            cmdline arguments without argv[0]
            dbh       database handler
        """

        # parse argv
        opt = parse(args)

        # generators for user and password lists
        # TODO: self.tls = opt.tls
        #self.to = opt.to
        self.nthreads = opt.nthreads
        # database handle
        self.dbh = dbh
        # queue stuff

        try:
            ig_targets = cTuples.cInputGenerator(data=opt.targets,
                                                 filename=opt.target_fn,
                                                 circle=False,
                                                 expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                 ports=[opt.port],
                                                                                 noSplit=True,
                                                                                 noResolve=True
                                                                                 ),
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
        self.tuples = cTuples.cTuples(inputs=[ig_targets, ig_users, ig_passw], prep_callback=brute, delay=opt.delay)
        self.tuples.start()

    def start(self):

        """ Do the thing """

        start_time = datetime.now()

        row_fmt = "{:30} {:30} {:30} | {:30}"
        for username, password, host, port, status in self.tuples.tuple_q:
            if status:
                print row_fmt.format(password, username, host + ':' + str(port), '')
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
                        service='mysql',
                    )
                    #br = ccd.MysqlBruteforceResult(
                    #    host=host,
                    #    port=int(port),
                    #    user=username,
                    #    password=password,
                    #)
                    self.dbh.add(br)

        self.tuples.join()
        print("\nfinished in %fs" % cUtil.secs(start_time))


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="Bruteforce mysql logins. " +
        "Be careful though. as the std. configuration for mysql servers is to block users after " +
        "too many unsuccessful authentification attempts (look out for protocol version mismatche msgs)",
        epilog=
        """Examples:
        mysql_bruteforce.plg  -u user -p pass -t 192.168.1.136
        mysql_bruteforce.plg  -U user.txt -P pass.txt -t 192.168.1.0/24 -nt 100
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-T',
                        help='files containing host:port entries',
                        default='',
                        dest='target_fn'
                        )
    parser.add_argument('-t',
                        help='target hosts',
                        default=[],
                        nargs='+',
                        dest='targets',
                        )
    parser.add_argument('-port',
                        help='target port (default 3306)',
                        dest='port',
                        default=3306,
                        type=int
                        )
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument('-u',
                        help='usernames',
                        default=[],
                        nargs='+',
                        dest='users',
                        )
    parser.add_argument('-p',
                        help='passwords',
                        default=[],
                        nargs='+',
                        dest='passw',
                        )
    parser.add_argument('-U',
                        help='file containing one username per line',
                        default='',
                        dest='user_fn',
                        )
    parser.add_argument('-P',
                        help='file containing one password per line',
                        default='',
                        dest='passw_fn',
                        )
    parser.add_argument('-nt',
                        help='number of threads (default 1)',
                        dest='nthreads',
                        type=int,
                        default=1
                        )
    parser.add_argument('-to',
                        help='Server timeout (default 3s)',
                        dest='to',
                        type=int,
                        default=3
                        )
    parser.add_argument('-no_check',
                        help='disable host check',
                        action='store_true',
                        dest='no_check',
                        )
    parser.add_argument('-tls',
                        help='use tls',
                        dest='tls',
                        action='store_true'
                        )

    if not args or not args[0]:
        parser.print_help()
        sys.exit(1)

    opt = parser.parse_args(args)

    return opt


if __name__ == '__main__':
    mb = MysqlBruteforce(sys.argv[1:])
    mb.start()
