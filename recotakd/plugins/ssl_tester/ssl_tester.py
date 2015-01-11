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
import ccdClasses as ccd
from ctools import cTuples
from ctools import cComm
from ctools import cUtil
from datetime import datetime
import argparse
import ssl
import socket
import sys
import logging

# logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

__version__ = 0.1
__plgname__ = "ssl_tester"


# callback to check if cipher suite is supported by target
def check_ssl(mark, cipher_specs):
    """
    check if the given ssl suite is supported by the target

    input:
        ((mark, (cs, cipher, sev, version)), )
        mark        cComm.Mark instance containing Target information
        cs          Cipher Suite
        cipher      Cipher
        sev         Risk ranking
        version     SSL Version (TLS1/2/3, SSL1/2)
    """
    # cipher information
    cs, cipher, sev, version = cipher_specs

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(mark.timeout)
        s.connect((mark.ip, mark.port))

        logger.debug('testing "%s" "%s"' % (version, cipher))
        # ssl.wrap will throw an exception on failed handshake
        s = ssl.wrap_socket(s, ssl_version=getattr(ssl, version), ciphers=cipher)
        yield (mark, cs, cipher, sev, version)
    except ssl.SSLError:
        # we expect SSL errors to occur on unsupported cipher suites
        pass
    except Exception as e:
        logger.warning('Unexpected error in check_ssl on input %s, %s -> %s',
                       mark.ident, cipher_specs, e)
    if s:
        s.close()
    raise StopIteration


# callback to prepare passed url strings
def prepare_target(target):
    logger.info('Preparing url string %s', target)
    ip, sp_url = target
    #if not cUtil.isUp((ip, 443)):
    #    logger.info('%s is down', target)
    #    #cComm.Mark(hostname, hostname=hostname, ip=ip, path=path)
    #    return None
    #hostname = ip
    path = '/'
    try:
        if sp_url:
            hostname, path = sp_url
    except:
        hostname = sp_url
    return cComm.Mark(ip, ip=ip, hostname=hostname, path=path)


# callback to prepare lines from the cipher list file
# Example line:
# SSL_RSA_WITH_NULL_MD5                   NULL-MD5 weak ssl.PROTOCOL_SSLv3
def prepare_cb_cipher(cline):
    # skip comments
    if cline.startswith('#'):
        return None
    # remove newlines
    cline = cline.rstrip()
    # skip empty lines
    if not cline:
        return None
    # split by space
    items = cline.split()
    items[3] = items[3][4:]
    try:
        # check if protocol version is supported by ssl module
        getattr(ssl, items[3])
    except AttributeError:
        #logger.warning('%s is not supported by current ssl module version', items[3])
        return None
    return items


def ssl_test(args, dbh=None):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="ssl version tester v%f" % __version__,
        epilog=
        """  Examples:
                ssl_tester.plg -t www.curesec.com -maxcon 10
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-T',
                        help='file containing urls or ips',
                        dest='target_fn'
                        )
    parser.add_argument('-t',
                        help='url or ir',
                        nargs='+',
                        dest='target',
                        default=[]
                        )
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument('-C',
                        help='filename of cipher suite list to test against (default cipherlist.txt)',
                        dest='cipher_fn',
                        default='cipherlist.txt'
                        )
    parser.add_argument('-port',
                        help='target port (default 443)',
                        dest='port',
                        default=443,
                        type=int
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
                        help='Maximum number of threads to scan with, each host gets a new thread (default 10)',
                        dest='nthreads',
                        default=10,
                        type=int
                        )

    if not args:
        parser.print_help()
        sys.exit(0)

    opt = parser.parse_args(args)

    # set global target parameters
    cComm.Mark.MAX_CON = opt.maxcon
    cComm.Mark.FIX_PORT = opt.port
    cComm.Mark.TIMEOUT = opt.timeout
    # only use ssl connections no plain http
    cComm.Comm.SSL = True

    start = datetime.now()
    try:
        ig_targets = cTuples.cInputGenerator(data=opt.target,
                                             filename=opt.target_fn,
                                             circle=False,
                                             expand_cb=cUtil.mkIP2,
                                             prepare_cb=prepare_target,
                                             maxthreads=opt.nthreads
                                             )
    except cTuples.ENoInput:
        print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
        sys.exit(1)

    try:
        ig_ciphers = cTuples.cInputGenerator(data=[],
                                             filename=opt.cipher_fn,
                                             prepare_cb=prepare_cb_cipher,
                                             circle=True)
    except cTuples.ENoInput:
        print 'Error: No Ciphers specified, please use the -C parameter to set a cipher list file'
        sys.exit(1)

    ig_targets.start()
    ig_ciphers.start()

    tuples = cTuples.cTuples(inputs=[ig_targets, ig_ciphers],
                             prep_callback=check_ssl,
                             maxthreads=opt.nthreads,
                             delay=opt.delay)
    tuples.start()

    results = {}
    for mark, cs, cipher, sev, version in tuples.tuple_q:
        if dbh:
            br = ccd.SslInfoResult(
                ip=mark.ip,
                fqdn=mark.hostname,
                port=mark.port,
                cs=cs,
            )
            dbh.add(br)

        try:
            results[mark.ip + ' / ' + mark.hostname][sev].append(cs)
        except:
            results[mark.ip + ' / ' + mark.hostname] = {}
            results[mark.ip + ' / ' + mark.hostname]['weak'] = []
            results[mark.ip + ' / ' + mark.hostname]['medium'] = []
            results[mark.ip + ' / ' + mark.hostname]['strong'] = []
    tuples.join()

    for ip, c in results.items():
        print '-' * len(ip)
        print ip
        print '-' * len(ip)
        for cs in c['weak']:
            print '\033[91m%s\033[0m' % cs
        for cs in c['medium']:
            print '\033[93m%s\033[0m' % cs
        for cs in c['strong']:
            print '\033[92m%s\033[0m' % cs

    print
    print 'Finished in %f seconds' % cUtil.secs(start)
