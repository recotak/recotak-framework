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
import Queue
import argparse
import sys
import ccdClasses as ccd
import socket
import ssl
from datetime import datetime
import logging
import logging.handlers
from ctools import cUtil
from ctools import cTuples

__version__ = 0.1
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "ftp_bruteforce"

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


CRLF = '\r\n'


def brute(target, user, passw):
    logger.debug('testing %s/%s on %s', user, passw, target)
    success = False
    sock = None
    code = 0
    ip, port = target
    try:
        # if I leave this in, sometimes users get lost ... no idea
        # why -> TODO
        #if user + host + str(port) in self.inv_users:
        #    continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(brute.to)
        sock.connect((ip, int(port)))
        sockfile = sock.makefile('rb')
        sockfile.readline()
        if brute.tls:
            #sock.sendall('AUTH TLS' + CRLF)
            try:
                sock.sendall('AUTH SSL' + CRLF)
                sockfile.readline()
                sock = ssl.wrap_socket(sock)
                sockfile = sock.makefile('rb')
            except Exception, e:
                logger.warning(e)
        sock.sendall('USER ' + user + CRLF)
        sockfile.readline()
        sock.sendall('PASS ' + passw + CRLF)
        r = sockfile.readline()
        code = int(r[:3])
        if code == 230:
            success = True
            yield (success, code, user, passw, ip, port)
    except Exception, e:
        logger.warning(e)
    finally:
        if sock:
            sock.close()
    raise StopIteration


def test_special_login_init(anon_q, timeout, tls):
    test_special_login.to = timeout
    test_special_login.tls = tls
    test_special_login.anon_q = anon_q


def test_special_login(target):
    logger.info('test_special: ' + repr(target))
    keep = True
    for user, password in FtpBruteforce.SPECIAL_LOGINS:
        success = False
        anon = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(test_special_login.to)
            sock.connect(target)
            sockfile = sock.makefile('rb')
            sockfile.readline()
            if test_special_login.tls:
                sock.sendall('AUTH SSL' + CRLF)
                sockfile.readline()
                sock = ssl.wrap_socket(sock)
                sockfile = sock.makefile('rb')
            sock.sendall('USER ' + user + CRLF)
            line = sockfile.readline()
            if 'Anonymous login ok' in line:
                anon = True
            sock.sendall('PASS ' + password + CRLF)
            r = sockfile.readline()
            code = int(r[:3])
            if code == 230:
                success = True
        except Exception, e:
            keep = False
            logger.warning(e)
            break
        finally:
            if sock:
                sock.close()
        if success:
            if anon:
                test_special_login.anon_q.put((target, user, password))
            else:
                test_special_login.anon_q.put((target, '', ''))
                keep = False
                break
    if keep:
        logger.info(repr(target) + ' seems to be up')
        return target
    else:
        return None


class FtpBruteforce():

    SPECIAL_LOGINS = [('anonymous', ''),
                      ('anonymous', 'anonymous'),
                      ('anonymous', 'ctest00@host.tld'),
                      ('ftp', 'ftp'),
                      ('ftp', 'ctest00@ftp.de'),
                      ]

    def __init__(self,
                 args,
                 dbh=None):

        """
        Initialize and run FtpBruteforce

        input:
            args            cmdline arguments without argv[0]
            dbhandler       database handler
        """

        logger.info('Init FTP bruteforce')

        self.dbh = dbh

        opt = parse(args)

        self.anon_q = Queue.Queue()

        brute.to = opt.to
        brute.tls = opt.tls

        self.anon = opt.anon
        if self.anon:
            test_special_login_init(self.anon_q, opt.to, opt.tls)

        expand_cb = lambda t: cUtil.mkIP2(t,
                                          ports=[opt.port],
                                          noResolve=True
                                          )
        try:
            ig_targets = cTuples.cInputGenerator(data=opt.targets,
                                                 filename=opt.target_fn,
                                                 circle=False,
                                                 expand_cb=expand_cb,
                                                 prepare_cb=opt.anon and test_special_login or None,
                                                 maxthreads=opt.nthreads
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        try:
            ig_users = cTuples.cInputGenerator(data=opt.users,
                                               filename=opt.user_fn,
                                               prepare_cb=lambda x: x.rstrip(),
                                               circle=True,
                                               maxthreads=opt.nthreads)
        except cTuples.ENoInput:
            print 'Error: No Usernames specified, please use the -u/U parameter to set usernames(s)'
            sys.exit(1)

        try:
            ig_passw = cTuples.cInputGenerator(data=opt.passw,
                                               filename=opt.passw_fn,
                                               prepare_cb=lambda x: x.rstrip(),
                                               circle=True,
                                               maxthreads=opt.nthreads)
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

        print '\nStarting bruteforce'

        row_fmt = "{:30} {:30} {:30}"

        print '-' * 80
        print 'Real logins:'
        print row_fmt.format('password', 'username', 'target')
        print '-' * 80
        for success, code, user, password, host, port in self.tuples.tuple_q:
            # we actually found sth.
            if success:

                print row_fmt.format(password, user, host + ':' + str(port))

                # add creds to database
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
                        username=user,
                        password=password,
                        service='ftp',
                    )
                    #br = ccd.FtpBruteforceResult(
                    #    host=host,
                    #    port=int(port),
                    #    user=user,
                    #    password=password,
                    #)
                    self.dbh.add(br)
        self.tuples.join()

        if self.anon:
            print '-' * 80
            print 'Anonymous logins:'
            print row_fmt.format('password', 'username', 'target')
            print '-' * 80
            while True:
                try:
                    target, passw, user = self.anon_q.get_nowait()
                except:
                    break
                host, port = target
                print row_fmt.format(passw, user, host + ':' + str(port))

                # add creds to database
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
                        username=user,
                        password=passw,
                        service='ftp',
                    )
                    #br = ccd.FtpBruteforceResult(
                    #    host=host,
                    #    port=int(port),
                    #    user=user,
                    #    password=passw,
                    #)
                    self.dbh.add(br)

        print("\nfinished in %fs" % cUtil.secs(start_time))


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="Bruteforce FTP logins",
        epilog=
        """Examples:
        ftp_bruteforce.plg -anon -P pass.txt -U user.txt -nt 400 -t 192.168.1.0/24
        ftp_bruteforce.plg -P pass.txt -U user.txt -t test.local -tls
        ftp_bruteforce.plg -anon -no_check -p pass1 pass2 -u user1 user2 -T hosts.txt
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-T',
                        help='file containing host[:port] entries',
                        dest='target_fn'
                        )
    parser.add_argument('-t',
                        help='list of target hosts',
                        nargs='+',
                        dest='targets',
                        default=[]
                        )
    parser.add_argument('-port',
                        help='target port (default 21)',
                        dest='port',
                        default=21,
                        type=int
                        )
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument('-U',
                        help='file containing username per line',
                        default='',
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
                        default='',
                        )
    parser.add_argument('-p',
                        help='passwords',
                        default=[],
                        nargs='+',
                        dest='passw',
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
    parser.add_argument('-tls',
                        help='use tls',
                        dest='tls',
                        action='store_true'
                        )
    parser.add_argument('-no_check',
                        help='disable host check',
                        action='store_true',
                        dest='no_check',
                        )
    parser.add_argument('-anon',
                        action='store_true',
                        help='test for anonymous login (open hosts are excluded from bruteforce)',
                        dest='anon',
                        )

    if not args or not args[0]:
        parser.print_help()
        sys.exit(1)

    opt = parser.parse_args(args)

    return opt
