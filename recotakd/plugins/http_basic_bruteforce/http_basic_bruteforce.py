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
import base64
import argparse
from ctools import cTuples
from ctools import cUtil
from ctools import cComm
import ccdClasses as ccd
import logging

__version__ = 0.2
__author__ = 'curesec'
__plgname__ = 'http_basic_bruteforce'

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


def brute(mark, user, password):
    data = ""
    encoded = base64.b64encode(user + ":" + password)
    headers = {"Authorization": "Basic " + encoded}
    try:
        status, data, error, uri, res_headers = \
            cComm.Comm.fetch(mark, mark.path, req_headers=headers)
        yield (status, user, password, mark)
    except Exception as e:
        print logger.warning('Error fetching resource %s/%s -> %s',
                             mark.hostname, mark.path, e)
    raise StopIteration


class HTTPBasicBruteforcer(object):
    def __init__(self, args, dbhandler=None):

        """ Initialise HTTP Basic Bruteforce.

            dbhandler: handler to store data persistently (e.g. via ccd)
        """

        logger.info('init HTTPBasicBruteforcer')
        self.dbhandler = dbhandler
        self.parse(args)

    def parse(self, args):
        description = \
            """### HTTP Basic Authentication Brute Forcer ###
            This scripts sends an HTTP request for all combinations of usernames and passwords.
            A login attempt is successful if the HTTP staus code of the HTTP reply is not 401.
            Be sure to provide a URL which is protected via HTTP Basic Authentication
            or you might get lots of false positives. (HTTP/1.1 200 OK)
            SSL is supported. Use the -ssl switch
            Output of valid credentials in the form [username:password].
            Example:
                http_basic_bruteforce.plg -t http://url.com:80/priv -u users.txt -p passwords.txt"
            """

        parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-T',
                            help='file containing url paths',
                            dest='target_fn'
                            )
        parser.add_argument('-t',
                            help='url path which enforces basic auth',
                            nargs='+',
                            dest='target',
                            default=[]
                            )
        parser.add_argument('-port',
                            help='target port (default 80)',
                            dest='port',
                            default=80,
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

        parser.add_argument('-to',
                            help='Server timeout (default 3s)',
                            dest='timeout',
                            type=int,
                            default=3
                            )
        parser.add_argument('-maxcon',
                            help='Maximum parallel connections per host (default: unlimited)',
                            type=int,
                            default=0,
                            )
        parser.add_argument('-nt',
                            help='Maximum number of threads to scan with, each host gets a new thread',
                            dest='nthreads',
                            default=10,
                            type=int
                            )

        parser.add_argument('-ssl',
                            help='Force ssl connection',
                            dest='ssl',
                            action='store_true',
                            default=False
                            )
        parser.add_argument('-nossl',
                            help='Force plain http connection',
                            dest='nossl',
                            action='store_true',
                            default=False
                            )

        if not args:
            parser.print_help()
            sys.exit(0)

        opt = parser.parse_args(args)

        cComm.Comm.SSL = opt.ssl
        cComm.Comm.NOSSL = opt.nossl

        cComm.Mark.MAX_CON = opt.maxcon
        cComm.Mark.FIX_PORT = opt.port
        cComm.Mark.TIMEOUT = opt.timeout

        def prepare_cb(target):
            ip = target[0]
            ident = ''.join(target[1])
            path = '/'
            hostname = target[1]

            if not isinstance(hostname, str):
                try:
                    hostname = target[1][0]
                    if len(target[1]) > 1:
                        path = ''.join(target[1][1:])
                except:
                    hostname = ''

                hostname = ''

            mark = cComm.Mark(ident,
                              ip=ip,
                              hostname=hostname,
                              path=path,
                              ok_codes=[401, ])

            if mark.test > 0:
                return mark
            else:
                return None

        try:
            ig_targets = cTuples.cInputGenerator(data=opt.target,
                                                 filename=opt.target_fn,
                                                 circle=False,
                                                 expand_cb=cUtil.mkIP2,
                                                 prepare_cb=prepare_cb,
                                                 maxthreads=opt.nthreads
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        try:
            ig_users = cTuples.cInputGenerator(data=opt.users,
                                               filename=opt.user_fn,
                                               prepare_cb=lambda x: x.rstrip(),
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Usernames specified, please use the -u/U parameter to set usernames(s)'
            sys.exit(1)

        try:
            ig_passw = cTuples.cInputGenerator(data=opt.passw,
                                               filename=opt.passw_fn,
                                               prepare_cb=lambda x: x.rstrip(),
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
        start_time = datetime.now()
        print 'Bruteforcing http_basic logins ...'
        row_fmt = '{:20}{:20}{:>40}'
        print '-' * 80
        print row_fmt.format('username', 'password', 'uri')
        print '-' * 80
        #time.sleep(10)
        for status, user, passw, mark in self.tuples.tuple_q:
            if status != 401:
                print(row_fmt.format(passw, user, mark.hostname + mark.path))
                # now, store result entry in data
                if self.dbhandler:
                    br = ccd.HttpBruteforceResult(
                        ip=mark.ip,
                        fqdn=mark.hostname,
                        path=mark.path,
                        port=mark.port,
                        user=user,
                        password=passw,
                    )
                    self.dbhandler.add(br)

        self.tuples.join()

        print '-' * 80
        print 'Finished in %f seconds' % cUtil.secs(start_time)


if __name__ == '__main__':
    mb = HTTPBasicBruteforcer(sys.argv[1:])
    mb.start()
