import sys
import argparse
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
import select
import logging
from ctools.cMysql import MysqlClient

__version__ = 0.1
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "mysqlclient"

# logging
LOG = "/tmp/ip2dns.log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def mysqlclient(args):

    """ mysqlclient function """

    args = parseInput(args)
    server = args.target
    port = args.port
    user = args.user
    passw = args.passw
    dbase = args.dbase
    try:
        mc = MysqlClient(server, port=port, timeout=args.timeout)
    except Exception as e:
        print 'Connection to %s:%d failed: %s' % (server, int(port), str(e))
        sys.exit(1)

    print "Connected %s/%s@%s:%d db%s" % (passw, user, server, port, dbase)
    r = mc.login(user, passw)
    if r:
        print 'Login successful'
        print 'To load a stored procedure from a file: > load_sp /path/to/file'
    else:
        print 'Login unsuccessful, terminating'
        sys.exit(1)
    while True:
        sys.stdout.write('> ')
        r, w, e = select.select([sys.stdin], [], [])
        if sys.stdin in r:
            sql_cmd = ''
            while True:
                buf = sys.stdin.read(1)
                if buf == '\n':
                    break
                sql_cmd += buf

            #sql_cmd = sys.stdin.readline()
            #sql_cmd = raw_input('> ')
            # load stored procedure
            parts = sql_cmd.split(' ')
            if parts[0] == 'load_sp':
                try:
                    sp = open(parts[1], 'r')
                    proc = sp.read()
                    sql_cmd = proc.rstrip()
                    print sql_cmd
                except Exception, e:
                    print e
            r, response = mc.send_cmd(sql_cmd)
            if r == 0x00:
                print 'OK'
            elif r == 0xff:
                print 'ERR'
            else:
                if not response:
                    continue
                header = ''
                for x in response[0]:
                    header += x + '\t'
                print header
                response = response[1:]
                if not response:
                    continue
                # TODO: make prettier
                print '-' * (len(header) + len(response[0]) * 4 - 4)
                for data in response:
                    print '\t'.join(data)
    return -1


def parseInput(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="Mysql client",
        epilog="""Examples:
        mysqlclient.plg -t 192.168.1.136 -u user -p pass
        """
    )
    parser.add_argument('-t',
                        help='target host',
                        dest='target',
                        required=True,
                        )
    parser.add_argument('-P',
                        help='target port (default 3306)',
                        dest='port',
                        default=3306,
                        type=int,
                        )
    parser.add_argument('-u',
                        help='Mysql username',
                        dest='user',
                        required=True,
                        )
    parser.add_argument('-p',
                        help='Mysql password',
                        dest='passw',
                        required=True,
                        )
    parser.add_argument('-d',
                        help='Mysql database (default none)',
                        dest='dbase',
                        default='',
                        required=False,
                        )
    parser.add_argument('-to',
                        help='Socket timeout (default 30 seconds)',
                        dest='timeout',
                        default=30,
                        type=int,
                        )

    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    return args

if __name__ == '__main__':
    mysqlclient(sys.argv[1:], None, None)
