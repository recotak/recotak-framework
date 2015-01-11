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
import socket
import ssl
import logging
import itertools as it

__version__ = 0.1
__author__ = "curesec"
__email__ = "curesec"
__plgname__ = "irc"

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

CMD = '/'
JOIN = 'JOIN'
PART = 'PART'
NICK = 'NICK'
PING = 'PING'
MSG = 'MSG'
QUIT = 'QUIT'
CHELP = 'CHELP'
LIST = 'LIST'
PRIVMSG = 'PRIVMSG'

CMDS = (JOIN, PART, NICK, PING, MSG, CHELP, PRIVMSG)


def help():
    print '-' * 80
    print '/' + CHELP + ' \t\t\tprint this help'
    print '/' + JOIN + ' <channelname>\tjoin channel'
    print '/' + PART + ' [channelname]\tpart channel given by name or current channel'
    print '/' + LIST + ' \t\t\tto list channels and users'
    #print '/' + NICK + ' <nick>\tchange nickname'
    print '/' + MSG + ' <chan/user> <msg>\tsend msg to user or channel'
    print '/' + QUIT + ' \t\t\tClose IRC client'
    print
    print 'To switch channels press <ENTER>'
    print 'To terminate this client type close (no slash)'
    print 'Please do not try to part from users'
    print '-' * 80


def ircclient(args):

    args = parseInput(args)

    server = args.target
    port = args.port
    timeout = args.to

    nick = args.nick
    ident = args.ident
    realname = args.realname
    passw = args.passw

    help()

    s = socket.socket()
    if args.ssl:
        s = ssl.wrap_socket(s)
    s.settimeout(timeout)
    logger.info('Connecting to %s:%d' % (server, int(port)))
    try:
        s.connect((server, int(port)))
    except Exception as e:
        print 'Connection to %s:%d failed: %s' % (server, int(port), str(e))
        sys.exit(1)

    chan = ['']
    cyc_chan = it.cycle(chan)
    cchan = ''
    try:
        if passw:
            s.send('PASS %s\r\n' % passw)
        s.send('NICK %s\r\n' % nick)
        s.send('USER %s %s bla :%s\r\n' % (ident, server, realname))
        logger.info('Registration completed')
        buf = ''
        while True:
                #r, w, e = select.select([sys.stdin, s], [], [], 1)
            sys.stdout.write('%s> ' % cchan)
            sys.stdout.flush()
            r, w, e = select.select([s, sys.stdin], [], [])
            if sys.stdin in r:
                inp = sys.stdin.readline()
                inp = inp.strip()
                if not inp:
                    cchan = cyc_chan.next()
                    continue
                if inp[0] == CMD:
                    cmd = inp[1:]
                    args = []
                    try:
                        cmd, args = inp[1:].split(' ', 1)
                    except:
                        pass
                    logger.info('CMD: %s' % cmd)
                    logger.info('ARGS: %s' % repr(args))

                    if cmd.upper() == JOIN:
                        # TODO make sure connection succeeds
                        chan.append(args)
                        cyc_chan = it.cycle(chan)
                        logger.info('Channels: ' + repr(chan))
                    elif cmd.upper() == PART:
                        c_to_part = ''
                        try:
                            if args:
                                c_to_part = args
                            elif cchan:
                                # part vom current channel
                                inp = inp + ' ' + cchan
                                c_to_part = args
                                chan.remove(cchan)
                            else:
                                print 'Cannot part'
                            if c_to_part:
                                chan.remove(c_to_part)
                        except:
                            print 'You are not connected to %s (channels: %s)' % \
                                (cchan, ', '.join(chan))
                        logger.info('Channels: ' + repr(chan))
                        cyc_chan = it.cycle(chan)
                        cchan = cyc_chan.next()
                    elif cmd.upper() == MSG:
                        try:
                            to, msg = args.split()
                            chan.append(to)
                            cyc_chan = it.cycle(chan)
                            logger.info('Channels: ' + repr(chan))
                            s.send(PRIVMSG + ' ' + to + ' :'  + msg + '\r\n')
                        except:
                            print 'format: /msg <to> <msg>'
                        continue
                    elif cmd.upper() == CHELP:
                        help()
                        continue
                    elif cmd.upper() == QUIT:
                        print 'Closing connection, BYE'
                        s.close()
                        s = None
                        break

                    logger.info('Sending %s', inp[1:])

                    s.send(inp[1:] + '\r\n')
                else:
                    s.send(PRIVMSG + ' ' + cchan + ' :'  + inp + '\r\n')
            if s in r:
                buf += s.recv(1024)
                print
                tmp = buf.split('\n')
                buf = tmp.pop()
                for line in tmp:
                    line = line.rstrip()
                    #logger.info(line)
                    spline = line.split()
                    if spline[0].upper() == PING:
                        s.send('PONG %s\r\n' % line[1])
                    else:
                        print ''.join(line)
    finally:
        if s:
            s.send('quit\r\n')

    return -1


def parseInput(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="IRC client",
        epilog="""Examples:
        irc.plg -t 192.168.1.136
        """
    )
    parser.add_argument('-t',
                        help='target host',
                        dest='target',
                        required=True,
                        )
    parser.add_argument('-P',
                        help='target port (default 6667)',
                        dest='port',
                        default=6667,
                        type=int,
                        )
    parser.add_argument('-to',
                        help='Socket timeout (default 30 seconds)',
                        default=30,
                        type=int,
                        )
    parser.add_argument('-ssl',
                        help='use ssl',
                        action='store_true'
                        )
    parser.add_argument('-nick',
                        help='nick (default root)',
                        default='root',
                        )
    parser.add_argument('-ident',
                        help='ident (default root)',
                        default='root',
                        )
    parser.add_argument('-realname',
                        help='real name (default root)',
                        default='root',
                        )
    parser.add_argument('-passw',
                        help='password (default empty)',
                        default='',
                        )

    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    return args

if __name__ == '__main__':
    ircclient(sys.argv[1:])
