""" some nice helper things """

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
import multiprocessing.dummy as mpd
from datetime import datetime
import dns
import multiprocessing as mp
import itertools as it
import threading
import logging
import random
import socket
import ctools
import struct
import Queue
import time
import ssl
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.NullHandler())

def add_rotat_logger(fn,
                     level,
                     maxBytes=20000000,
                     backupCount=10,
                     formatter=None):
    """ returns a logging handler.

        input:
            fn              filename to log to
            level           logging level to log
            maxBytes(o)     bytes written to file before rotating
            backupCount(o)  amount of file rotations
            formatter(o)    formatter object to added to ratation logger

        output:
            handler         RotatingFileHandler

    """
    handler = logging.handlers.RotatingFileHandler(
        fn,
        maxBytes=maxBytes,
        backupCount=backupCount)
    handler.setLevel(level)

    if not formatter:
        fmt_str = ("%(asctime)s,p:%(process)s %(threadName)s, [%(levelname)s] "
                   "%(name)s(%(funcName)s): %(message)s")
        formatter = logging.Formatter(fmt_str)

    handler.setFormatter(formatter)
    return handler


class EST_SIZE():
    IP = len('111.222.333.444')
    PORT = 6
    USER = 42
    PASSWORD = 42


ssh_version = it.cycle(['SSH-2.0-OpenSSH_6.1', 'SSH-2.0-OpenSSH_5.1', 'SSH-2.0-OpenSSH_4.1'])

DOMAIN_RE = re.compile(
    "([A-Za-z]{3,9}:(?:\/\/)?)?" +    # match protocol, allow in format http:// or mailto:
    "(?P<domain>" +                  # domain part
    #"(?:[\-;:&=\+\$,\w]+@)?" +       # allow something@ for email addresses
    #"[A-Za-z0-9\.\-]+" +             # anything looking at all like a domain, non-unicode domains
    #"|" +                            # or instead of above
    "(?:www\.|[\-;:&=\+\$,\w]+@)?" +  # starting with something@ or www.
    "[A-Za-z0-9\.\-]+" +             # anything looking at all like a domain
    ")" +
    "(?P<params>" +                  # path / querystr part
    "(?:\/[\+~%\/\.\w\-_]*)" +       # allow optional /path
    "?\??(?:[\-\+=&;%@\.\w_]*)" +    # allow optional query string starting with ?
    "#?(?:[\.\!\/\\\w]*)"            # allow optional anchor #anchor
    ")?")
IP_RE = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
RNGE_RE = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" +
                     "-(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
MASK_RE = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" +
                     "?\/([0-9]|[1-3][0-2])+$")

MAX_THREADS = 100
Q_TIMEOUT = 1
FB_PORT = None


class TTYPE(object):
    IP = 1
    RNGE = 2
    MASK = 3
    DOMAIN = 4


def splitUrl(url):
    m = DOMAIN_RE.match(url)
    return m.groupdict()


def getTargetType(targetstr):
    if IP_RE.match(targetstr):
        return TTYPE.IP
    elif RNGE_RE.match(targetstr):
        return TTYPE.RNGE
    elif MASK_RE.match(targetstr):
        return TTYPE.MASK
    elif DOMAIN_RE.match(targetstr):
        return TTYPE.DOMAIN
    else:
        raise Exception('Invalid Target %s' % targetstr)


def _test_getTargetType():
    test_domain = [
        'abc.de',
        'abc.de/x',
        'abc.de',
        'abc.de',
        'abc.de/x',
        'abc.de/x',
        'abc.de',
        'abc.de',
        'abc.de/x',
        'abc.de/x',
        'sub.abc.de/x',
        'sub.abc.de',
        'sub.abc.de',
        'sub.abc.de/x',
        'sub.abc.de/x',
        'sub.abc.de',
        'sub.abc.de',
        'sub.abc.de/x',
        'sub.abc.de/x',
        'abc.de',
        'abc.de/x',
        'http://www.abc.de',
        'http://abc.de',
        'http://www.abc.de/x',
        'http://abc.de/x',
        'https://www.abc.de',
        'https://abc.de',
        'https://www.abc.de/x',
        'https://abc.de/x',
        'www.sub.abc.de/x',
        'http://www.sub.abc.de',
        'http://sub.abc.de',
        'http://www.sub.abc.de/x',
        'http://sub.abc.de/x',
        'https://www.sub.abc.de',
        'https://sub.abc.de',
        'https://www.sub.abc.de/x',
        'https://sub.abc.de/x',
    ]
    test_ip = ['1.1.1.1', '127.0.0.1', '255.255.255.255']
    test_rnge = ['1.1.1.1-1.2.3.4', ]
    test_mask = ['1.1.1.0/24', '1.2.3.4/32', '1.2.3.4/0', '1.2.3./0']

    for dom in test_domain:
        if getTargetType(dom) != TTYPE.DOMAIN:
            print 'Error on ' + dom
        print repr(splitUrl(dom))

    for ip in test_ip:
        if getTargetType(ip) != TTYPE.IP:
            print 'Error on ' + ip

    for rnge in test_rnge:
        if getTargetType(rnge) != TTYPE.RNGE:
            print 'Error on ' + rnge

    for mask in test_mask:
        if getTargetType(mask) != TTYPE.MASK:
            print 'Error on ' + mask


def _get_start_end(ipstr):
    ttype = getTargetType(ipstr)
    if not ttype:
        raise

    if ttype == TTYPE.RNGE:
        logger.debug('Matched %s as ip range', ipstr)
        idx_rnge = ipstr.find('-')
        if not idx_rnge:
            raise

        start_dotted = ipstr[idx_rnge + 1:]
        end_dotted = ipstr[:idx_rnge]
        start = struct.unpack(">I", socket.inet_aton(start_dotted))[0]
        end = struct.unpack(">I", socket.inet_aton(end_dotted))[0]

    elif ttype == TTYPE.MASK:
        logger.debug('Matched %s as ip mask', ipstr)
        idx_mask = ipstr.find('/')
        if not idx_mask:
            raise

        mask = int(ipstr[idx_mask + 1:])
        ipstr = ipstr[:idx_mask]
        start, end = ctools.getNetmask(ipstr, int(mask))

    elif ttype == TTYPE.IP:
        logger.debug('Matched %s as ip', ipstr)
        start = struct.unpack(">I", socket.inet_aton(ipstr))[0]
        end = struct.unpack(">I", socket.inet_aton(ipstr))[0]

    elif ttype == TTYPE.DOMAIN:
        logger.debug('Matched %s as domain name', ipstr)
        start = ipstr
        end = start

    return ttype, start, end

def mkIP2(oIpstr, ports=[], noResolve=False, noSplit=False):
    """
    _generate_ (this is a generator) ips by throwing all kinds of stuff at
    this function. if ports are specified, ip tuples are generated for each
    port

    Input:
        oIpstr          ip string optionally with port definition or domain
        noResolve       Do not attempt to resolve ips or domains
        noSplit         return the domain as a whole, not split into domain
                        and query parts

    ports=[port1, port2]
    supported input formats are:

        * ip: 127.0.0.1                     -> ((127.0.0.1, port0), hostname),
                                                ((127.0.0.1, port1), hostname)

        * hostname: x.de                    -> ((ip, port0), x.de),
                                                ((ip, port1), x.de)

        * ip{,port}*: 127.0.0.1,port3,port4 -> ((127.0.0.1, port3), hostname),
                                                ((127.0.0.1, port4), hostname)
                                               (default ports are overridden)

        * iprange: 127.0.0.1-127.0.0.2      -> ((127.0.0.1, port0), hostname),
                                                ((127.0.0.1, port1), hostname),
                                               ((127.0.0.2, port0), hostname),
                                                ((127.0.0.2, port1), hostname)

        * iprange{,port}*: ...              -> see ip{,port}*

        * ipmask: 127.0.0.1/31              -> ((127.0.0.1, port0), hostname),
                                                ((127.0.0.1, port1), hostname),
                                               ((127.0.0.2, port0), hostname),
                                               ((127.0.0.2, port1), hostname)

        * ipmask{,port}*: ...              -> see ip{,port}*

    output:
        returns a generator

        e.g:

            >>> for i in mkIP2("127.0.0.1/24"):
                ...     print i
                ...
                ('127.0.0.0', 'localhost.localdomain')
                ('127.0.0.1', 'localhost.localdomain')
                ('127.0.0.2', 'localhost.localdomain')
                ('127.0.0.3', 'localhost.localdomain')
                ('127.0.0.4', 'localhost.localdomain')
                ('127.0.0.5', 'localhost.localdomain')
                ('127.0.0.6', 'localhost.localdomain')
                ('127.0.0.7', 'localhost.localdomain')


    """

    #logger.debug('mkIP of %s %s', oIpstr, repr(ports))
    # save original ipstr for debugging purpases
    oIpstr = oIpstr.strip('\n')

    if not oIpstr:
        raise StopIteration

    if oIpstr.startswith('#'):
        raise StopIteration

    ipstr = oIpstr
    hostname = ''
    ports = ports
    start = None
    end = None

    try:
        # remove appended ports, e.g. 127.0.0.1,80,443 or 127.0.0.0/24,80,443
        idx_port = ipstr.find(',')
        if idx_port > 0:
            portstr = ipstr[idx_port + 1:]
            # override default ports
            ports = map(int, portstr.split(','))
            # remove port portion for ipstr for further processing
            ipstr = ipstr[:idx_port]

        try:
            ttype, start, end = _get_start_end(ipstr)

        except:
            logger.warning('Invalid Target %s', oIpstr)
            raise StopIteration

        if ttype == TTYPE.DOMAIN:
            sp_url = splitUrl(ipstr)
            base = sp_url['domain']

            dom = sp_url['domain']
            # hostname may be an ip address, if you got something like
            # 127.0.0.1/private/index.html
            if dns.validate.is_ip(dom):
                # or sth lime 127.0.0.1:8080/private
                # TODO
                ip = dom
                ipstr = dom
                hostname = gethostbywhatever(dom)
                if not noSplit:
                    hostname = (hostname, sp_url['params'] or '/')
                else:
                    hostname += sp_url['params']
            else:
                if not noSplit:
                    hostname = (sp_url['domain'], sp_url['params'] or '/')
                else:
                    hostname = base

                if not noResolve:
                    try:
                        ip = gethostbywhatever(ipstr)
                    except (socket.herror, socket.gaierror):
                        ip = None
                else:
                    ip = None

            for port in ports:
                if ip:
                    yield ((ip, port), hostname)

                else:
                    yield ((hostname, port))

            if not ports:
                yield (ip, hostname) if ip else ((hostname))

            raise StopIteration

        if start > end:
            start, end = end, start

        for ip in range(start, end + 1):
            try:
                ip_dotted = socket.inet_ntoa(struct.pack(">I", ip))

                if not noResolve:
                    try:
                        domain = gethostbywhatever(ip_dotted)
                    except (socket.herror, socket.gaierror):
                        domain = ''
                else:
                    domain = ''

                for port in ports:
                    if domain:
                        yield ((ip_dotted, port), domain)

                    else:
                        yield ((ip_dotted, port))

                if not ports:
                    yield (ip_dotted, domain)  # if domain else ((ip_dotted))

            except Exception as e:
                # continue with next one anyway
                print('Something wrong with %s / %s -> %s',
                      ip_dotted, hostname, e)

        #logger.debug('mkIP of %s done', oIpstr)
    except Exception as e:
        logger.exception(e)

    raise StopIteration


def gethostbywhatever(whatever):
    """
    returns either a hostname or an ip address of whatever depending of
    its ttype. in case of illegal ttype, it raises exception. since it
    calls socket.gethostby* it might raise socket.gaierror if resolving
    fails.

    input:
        whatever    either an IP or a hostname

    output:
        returns either domain name or IP

    """
    ttype = getTargetType(whatever)

    if ttype == TTYPE.DOMAIN:
        return socket.gethostbyname(whatever)

    elif ttype == TTYPE.IP:
        return socket.gethostbyaddr(whatever)[0]

    else:
        raise

def mkIPrandom(ips, ports, dns_resolve=True, randomness=10):
    """
    gets a list of ip/hostnames and ports and yields a random targets

    input:
        ips         list of ip/hostnames
        ports       list of ports
        dns_resolve flag that tiggers dns resolving (optional, default=True)
        randomness  an integer, that indicates the randomness. the higher, the
                    more random are the targets but the lower is performance

                        1    no randomness
                        2    randomness
                        10   high randomness
                        100  ultra randomness
                        1000 incredible ranomness

    outputs:
        generator that contains a random target

    """
    cache = []

    for ip in ips:
        for new in mkIP2(ip,
                         ports=ports,
                         noResolve=not dns_resolve,
                         noSplit=True):

            if random.randint(0, randomness) == 1:
                yield new

            else:
                cache.append(new)

    while cache:
        elem = random.choice(cache)
        yield elem
        cache.remove(elem)

    raise StopIteration


def mkIP(ipstr, port=FB_PORT, check_host=None, check_init=None, init_args=[]):
    logger.warning('mkIP is deprecated, use mkIP2')
    for ip in mkIP2(ipstr, [port]):
        yield ip
    raise StopIteration
    logger.debug('mkIP of %s' % ipstr)
    ipstr = ipstr.strip('\n')
    # try to resolve host
    ipstr = ipstr.strip('\n')
    hostname = ''
    # try to resolve host
    try:
        # if ipstr is actually an ip, it will be returned unchanged
        hostname = socket.gethostbyname(ipstr)
        if hostname == ipstr:
            try:
                hostname = socket.gethostbyaddr(ipstr)[0]
            except socket.gaierror as e:
                logger.warning('No hostname for %s -> %s', ipstr, e)
        else:
            hostname, ipstr = ipstr, hostname
    except socket.gaierror:
        logger.warning('Can not resolve %s' % ipstr)
        raise StopIteration

    port = port
    start = None
    end = None

    idx_port = ipstr.find(',')
    if idx_port > 0:
        port = int(ipstr[idx_port + 1:])
        ipstr = ipstr[:idx_port]
        #logger.debug('Port: %d' % port)

    idx_mask = ipstr.find('/')
    if idx_mask > 0:
        logger.debug('Mask')
        mask = int(ipstr[idx_mask + 1:])
        ipstr = ipstr[:idx_mask]
        start, end = ctools.getNetmask(ipstr, int(mask))

    idx_rnge = ipstr.find('-')
    if idx_rnge > 0:
        #logger.debug('Range')
        start_dotted = ipstr[idx_rnge + 1:]
        end_dotted = ipstr[:idx_rnge]
        start = struct.unpack(">I", socket.inet_aton(start_dotted))[0]
        end = struct.unpack(">I", socket.inet_aton(end_dotted))[0]

    if not start or not end:
        #logger.debug('IP')
        start = struct.unpack(">I", socket.inet_aton(ipstr))[0]
        end = struct.unpack(">I", socket.inet_aton(ipstr))[0]

    if start > end:
        start, end = end, start

    if check_host:
        ips = it.imap(lambda x: socket.inet_ntoa(struct.pack(">I", x)),
                      xrange(start, end + 1))
        ps = int(max(1, (min(end - start, MAX_THREADS))))
        out_q = mp.Queue()
        args = [out_q]
        args.extend(init_args)
        if check_init:
            pool = mpd.Pool(ps, check_init, args)
        else:
            pool = mpd.Pool(ps)
        if port:
            pool.map(check_host, it.izip(ips, it.repeat(port)))
        else:
            pool.map(check_host, ips)
        pool.close()
        pool.join()
        while True:
            try:
                target = out_q.get(False, Q_TIMEOUT)
                #logger.debug('mkIP yield %s' % repr(target))
                yield target
            except Queue.Empty:
                break
    else:
        for ip in range(start, end + 1):
            ip_dotted = socket.inet_ntoa(struct.pack(">I", ip))
            #logger.debug('mkIP yield %s' % repr(ip_dotted))
            if port:
                logger.debug('Yielding')
                yield(ip_dotted, port)
            else:
                yield(ip_dotted)
    logger.debug('mkIP %s done' % ipstr)
    raise StopIteration


def secs(start_time):
    dt = datetime.now() - start_time
    secs = (dt.days * 24 * 60 * 60 + dt.seconds * 1000 +
            dt.microseconds / 1000) / 1000.0
    return secs


def validFilename(fn):
    """ Function checks whether file name contains allowed chars. """
    if not isinstance(fn, str) and not isinstance(fn, unicode):
        return False

    #valid = re.compile("^[a-zA-Z0-9_(\.\w)]+(\.\w\w\w(\w)*)*$")
    #return True if valid.match(fn) is not None else False
    for char in ("..", "&", "~"):
        if char in fn:
            return False
    return True


def validString(totest, match="^([\w\-_]*)$"):
    """ returns whether input is valid string """
    if not isinstance(totest, str) and not isinstance(totest, unicode):
        return False

    valid = re.compile(match)
    return True if valid.match(totest) is not None else False


def isIP(totest):
    """ returns whether input is an ip """
    if not isinstance(totest, str) and not isinstance(totest, unicode):
        return False

    print("ctools.ctools.cUtil.isIP is deprecated. use ctools.dns.validate.is_ip"
          " instead")
    m = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                 "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", totest)
    return m


def isDomain(totest):
    """ returns whethter input is a domain """
    print("ctools.ctools.cUtil.isDomain is deprecated. use "
          "ctools.dns.validate.is_domain instead")
    if not isinstance(totest, str) and not isinstance(totest, unicode):
        return False

    return True if not re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}"
                                "[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$",
                                totest) is None else False


def check_init(out_q, to):
    check.out_q = out_q
    check.to = to


def check_ssl(target):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(check.to)
    con_open = False
    try:
        sock = ssl.wrap_socket(sock)
        sock.connect(target)
        con_open = True
    except:
        pass
    finally:
        sock.close()
    if con_open:
        #logger.debug('UP: ' + repr(target))
        check.out_q.put(target)


def check(target):
    logger.debug('Checking %s:%d' % target)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(check.to)
    con_open = False
    try:
        sock.connect(target)
        con_open = True
    except:
        logger.debug('%s:%d is DOWN' % target)
        pass
    finally:
        sock.close()
    if con_open:
        logger.debug('%s:%d is UP' % target)
        check.out_q.put(target)


def isUp(target):
    logger.debug('Checking %s:%d' % target)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(isUp.to)
    con_open = False
    try:
        sock.connect(target)
        con_open = True
    except:
        logger.debug('%s:%d is DOWN' % target)
        return None
    finally:
        sock.close()
    if con_open:
        logger.debug('%s:%d is UP' % target)
        return target
    return None
isUp.to = 3


def ip_in_netmask(ip_dotted, netmask):

    """
    check if ip is in netrange
    Input:
        ip          Ip address
        netmask     netmask in the form of (ip, mask)
    """

    start, end = ctools.getNetmask(*netmask)
    if start > end:
        start, end = end, start
    ip = struct.unpack(">I", socket.inet_aton(ip_dotted))[0]
    if start <= ip <= end:
        return True
    return False


def mkPort(portstr):
    portstr = portstr.rstrip()

    if not portstr:
        raise StopIteration

    if '-' in portstr:
        parts = portstr.split('-')
        if len(parts) > 2:
            print 'ERROR: invalid port %s' % portstr
        start = int(parts[0])
        stop = int(parts[1]) + 1
        for port in range(start, stop):
            yield port
    else:
        yield int(portstr)


class cTimer(threading.Thread):
    def __init__(self, event, timeout):
        super(cTimer, self).__init__()
        self.ev = event
        self.timeout = timeout

    def run(self):
        time.sleep(self.timeout)
        logger.debug('timed out')
        self.ev.set()


def __test_mkIP():
    inputs = ['11.22.33.44-11.22.33.55,80']
    for i in inputs:
        start = datetime.now()
        print 'IPs up in %s' % i
        #up_ips = mkIP(i)
        up_ips = mkIP(i, check, check_init, [3])
        for ip, port in up_ips:
            print '%s, %d' % (ip, port)
        stop = secs(start)
        print 'finished in %f seconds' % stop
        logger.debug('finished in %f seconds' % stop)
