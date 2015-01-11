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
import argparse
import os
import iptools


# TODO
# return iterator classes instaed of lists

def parse(args, pname, pdescription, rootpath, parser=None,
          ips=None, nthreads=None, timeout=None, ssl=None,
          thosts=None, port=None, users=None, passwords=None):
    if parser is None:
        parser = argparse.ArgumentParser(
            prog=pname,
            description=pdescription)
    if not ips is None:
        parser.add_argument("-i",
                            dest='fn_ip',
                            help="File with a newline seperated list of IPs," +
                            " e.g. -i ips.txt")
        parser.add_argument("-I",
                            dest='ip',
                            help="IP address to resolve" +
                            ", e.g. -I 8.8.8.8")
        parser.add_argument("-r",
                            dest='ip_range',
                            help="Range of IPs to resolve" +
                            ", e.g. -r 82.165.197.0/24")
    if not nthreads is None:
        parser.add_argument("-t",
                            dest='nthreads',
                            help="amount of threads to scan with (default 400)",
                            type=int,
                            default=400)
    if not timeout is None:
        parser.add_argument('-to',
                            dest='timeout',
                            help='timeout (default 3s)',
                            type=int,
                            default=3
                            )
    if not ssl is None:
        parser.add_argument('-ssl',
                            action='store_true',
                            dest='ssl',
                            )
    if not thosts is None:
        parser.add_argument('-s',
                            help='file containing ip[:port] entries',
                            dest='fn_thost'
                            )
        parser.add_argument('-S',
                            help='target ip[:port]',
                            dest='thost',
                            )
    if not port is None:
        parser.add_argument('-P',
                            help='target port',
                            dest='port',
                            default=21,
                            type=int
                            )
    if not users is None:
        parser.add_argument('-u',
                            help='file containing username per line',
                            dest='fn_users',
                            )
    if not passwords is None:
        parser.add_argument('-p',
                            help='file containing password per line',
                            dest='fn_passwords',
                            )

    opts = parser.parse_args(args)
    if not ips is None:
        if opts.fn_ip:
            fn_ip = os.path.join(rootpath, opts.fn_ip)
            with open(fn_ip, 'r') as f:
                ips.extend(f.read().splitlines())
        if opts.ip:
            ips.append(opts.ip)
        if opts.ip_range:
            for ip in iptools.IpRange(opts.ip_range):
                ips.append(ip)
    if not nthreads is None:
        nthreads.append(opts.nthreads)
    if not timeout is None:
        timeout.append(opts.timeout)
    if not ssl is None:
        if opts.ssl:
            ssl.append(True)
        else:
            ssl.append(False)
    if not port is None:
        port.append(opts.port)
    # TODO: convert port to int
    if not thosts is None:
        if opts.fn_thost:
            fn_thost = os.path.join(rootpath, opts.fn_thost)
            with open(fn_thost, 'r') as f:
                for th in f.read().splitlines():
                    if th.find(':') > 0:
                        thosts.append(tuple(th.split(':')))
                    else:
                        thosts.append((th, port[0]))
        if opts.thost:
            if opts.thost.find(':') > 0:
                thosts.append(tuple(opts.thost.split(':')))
            else:
                thosts.append((opts.thost, port[0]))
    if not users is None:
        fn_users = os.path.join(rootpath, opts.fn_users)
        with open(fn_users, 'r') as f:
            users.extend(f.read().splitlines())
    if not passwords is None:
        fn_passwords = os.path.join(rootpath, opts.fn_passwords)
        with open(fn_passwords, 'r') as f:
            passwords.extend(f.read().splitlines())

    return opts


if __name__ == '__main__':
    import sys
    ips=[]
    nthreads=[]
    timeout=[]
    thosts=[]
    port=[]
    users=[]
    passwords=[]
    parse(sys.argv[1:], 'bla', 'blubb', './', ips=ips, thosts=thosts, port=port, users=users, passwords=passwords)
    #parse(sys.argv[1:], 'bla', 'blubb', './', nthreads, timeout, passwords)
    #for l in locals():
    #    print l
    #parse(sys.argv[1:], 'bla', 'blubb', './', ips, nthreads, timeout, thosts, port, users, passwords)
    #for l in locals():
    #    print l
    print '\n'.join(locals())
