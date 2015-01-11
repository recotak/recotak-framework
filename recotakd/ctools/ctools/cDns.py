#!/usr/bin/env python
#
# Copyright (C) 2006 - 2012, Shumon Huque
#
# pydig is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# pydig is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pydig; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# Author: Shumon Huque <shuque -@- upenn.edu>
#

# pydig: A small DNS query tool.


import socket
import binascii
import struct
import random

# logging
import logging
#LOG = "/tmp/cDNS.log"
#FORMAT = '%(asctime)s - %(name)s - ' + \
#    '%(levelname)s - %(threadName)s - %(message)s'
#logging.basicConfig(filename=LOG,
#                    filemode="w",
#                    format=FORMAT,
#                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())


RESOLV_CONF    = "/etc/resolv.conf"    # where to find default server
DEFAULT_PORT   = 53
ITIMEOUT       = 0.5                   # initial timeout in seconds
RETRIES        = 3                     # how many times to try
BUFSIZE        = 4096                  # socket read/write buffer size
EDNS0_UDPSIZE  = 4096
DEBUG          = False                 # for more debugging output (-d)

count_compression = 0                  # count of compression pointers derefs
size_query = 0
size_response = 0


# raised by decode_rr on short data
class EInvalidDNS(Exception):

    name = 'cDns'

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# raised by decode_axfr on attempting non permitted zone transfer
class NOTAUTH(Exception):

    name = 'cDns'

    def __str__(self):
        return 'Zone Transfers not allowed'


class DNSparam:
    """Class to encapsulate some DNS parameter types (type, class etc)"""

    def __init__(self, prefix, name2val):
        self.name2val = name2val
        self.val2name = dict([(y, x) for (x, y) in name2val.items()])
        self.prefix = prefix
        self.prefix_offset = len(prefix)

    def get_name(self, val):
        """given code (value), return text name of dns parameter"""
        if self.prefix:
            return self.val2name.get(val, "%s%d" % (self.prefix, val))
        else:
            return self.val2name[val]

    def get_val(self, name):
        """given text name, return code (value) of a dns parameter"""
        if self.prefix and name.startswith(self.prefix):
            return int(name[self.prefix_offset:])
        else:
            return self.name2val[name]

# Instantiate the DNS parameter classes at the module level, since they
# are used by a variety of module routines.

qt = DNSparam("TYPE",
              dict(A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, SIG=24,
                   KEY=25, AAAA=28, NXT=30, SRV=33, NAPTR=35, CERT=37, A6=38,
                   DNAME=39, OPT=41, DS=43, SSHFP=44, IPSECKEY=45, RRSIG=46,
                   NSEC=47, DNSKEY=48, DHCID=49, NSEC3=50, NSEC3PARAM=51,
                   TLSA=52, HIP=55, SPF=99, AXFR=252, TKEY=249, TSIG=250,
                   ANY=255, TA=32768, DLV=32769))

qc = DNSparam("CLASS",
              dict(IN=1, CH=3, HS=4, ANY=255))

rc = DNSparam("RCODE",
              dict(NOERROR=0, FORMERR=1, SERVFAIL=2, NXDOMAIN=3, NOTIMPL=4,
                   REFUSED=5, NOTAUTH=9, BADVERS=16, BADKEY=17, BADTIME=18,
                   BADMODE=19, BADNAME=20, BADALG=21, BADTRUNC=22))

dnssec_proto = {0: "Reserved", 1: "TLS", 2: "Email", 3: "DNSSEC", 4: "IPSEC"}


def hexdump(input, separator=' '):
    """return a hexadecimal representation of the given string"""
    hexlist = ["%02x" % ord(x) for x in input]
    return separator.join(hexlist)


def packed2int(input):
    """convert arbitrary sized bigendian packed string into an integer"""
    sum = 0
    for (i, x) in enumerate(input[::-1]):
        sum += ord(x) * 2 ** (8 * i)
    return sum


def domain_name_match(s1, s2):
    return (s1.lower() == s2.lower())


def ip2ptr(address):
    """return PTR owner name of an IPv4 or IPv6 address (for -x option)"""
    v4_suffix = '.in-addr.arpa.'
    v6_suffix = '.ip6.arpa.'
    error = False
    try:
        if address.find('.') != -1:                             # IPv4 address
            packed = socket.inet_pton(socket.AF_INET, address)
            octetlist = ["%d" % ord(x) for x in packed]
            ptrowner = "%s%s" % ('.'.join(octetlist[::-1]), v4_suffix)
        elif address.find(':') != -1:                           # IPv6 address
            packed = socket.inet_pton(socket.AF_INET6, address)
            hexstring = ''.join(["%02x" % ord(x) for x in packed])
            ptrowner = "%s%s" % \
                       ('.'.join([x for x in hexstring[::-1]]), v6_suffix)
        else:
            error = True
    except socket.error:
        error = True
    if error:
        raise Exception("%s isn't an IPv4 or IPv6 address" % address)

    return ptrowner


def get_socketparams(server, port, af, type):
    """Only the first set of parameters is used. Passing af=AF_UNSPEC prefers
    IPv6 if possible."""
    ai = socket.getaddrinfo(server, port, af, type)[0]
    family, socktype, proto, canonname, sockaddr = ai
    server_addr, port = sockaddr[0:2]
    return (server_addr, port, family, socktype)


def send_request_udp(pkt, host, port, family, itimeout, retries):
    """Send the request via UDP, with retries using exponential backoff"""
    gotresponse = False
    responsepkt, responder_addr = "", ("", 0)
    s = socket.socket(family, socket.SOCK_DGRAM)
    timeout = itimeout
    while (retries > 0):
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (host, port))
            (responsepkt, responder_addr) = s.recvfrom(BUFSIZE)
            gotresponse = True
        except socket.timeout:
            timeout = timeout * 2
            logger.warning("Request timed out with no answer")
            pass
        retries -= 1
        if gotresponse:
            break
    s.close()
    return (responsepkt, responder_addr)


def send_request_tcp(pkt, host, port, family):
    """Send the request packet via TCP"""

    # prepend 2-byte length field, per RFC 1035 Section 4.2.2
    pkt = struct.pack("!H", len(pkt)) + pkt
    s = socket.socket(family, socket.SOCK_STREAM)
    response = ""
    try:
        s.connect((host, port))
        s.send(pkt)
        s.settimeout(8)
        # ??
        # time.sleep(1)
        while True:
            chunk = s.recv(BUFSIZE)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    except socket.error, diag:
        logger.error('Error from %s -> %s', host, diag)
        s.close()
        raise
    s.close()
    return response


def do_axfr(pkt, host, port, family):
    """AXFR uses TCP, and is answered by a sequence of response messages."""

    # prepend 2-byte length field, per RFC 1035 Section 4.2.2
    pkt = struct.pack("!H", len(pkt)) + pkt
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.send(pkt)
        s.settimeout(2)       # setting non-blocking is often too aggressive
        Done = False
        response = ""
        readSoFar = 0
        while not Done:
            chunk = s.recv(BUFSIZE)
            chunklen = len(chunk)
            if chunklen == 0:
                Done = True
                continue
            response += chunk
            readSoFar += chunklen
    except socket.timeout:
        pass                     # end of data
    except socket.error, diag:
        logger.error(diag)
        s.close()
        raise
    s.close()

    return (response, readSoFar)


def decode_axfr(response, resplen):
    """given a string containing a sequence of response messages from
    an AXFR request, decode and print only the answer RRs"""
    rrtotal = 0
    msgtotal = 0
    answers = []
    msgsizes = dict(max=-1, min=0, avg=0, total=0)
    p = response
    while p:
        msglen, = struct.unpack('!H', p[0:2])
        msgtotal += 1
        if msgsizes["max"] == -1:
            msgsizes["max"] = msglen
            msgsizes["min"] = msglen
        else:
            if msglen > msgsizes["max"]:
                msgsizes["max"] = msglen
            if msglen < msgsizes["min"]:
                msgsizes["min"] = msglen
        msgsizes["total"] += msglen
        msg = p[2:2 + msglen]
        answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
            qdcount, ancount, nscount, arcount = \
            decode_header(msg, -1, checkid=False)
        if rcode != 0:
            raise NOTAUTH  # Exception("Zone transfer failed: %s" % rc.get_name(rcode))

        offset = 12                     # skip over DNS header

        for i in range(qdcount):
            domainname, rrtype, rrclass, offset = decode_question(msg, offset)

        for i in range(ancount):
            domainname, rrtype, rrclass, ttl, rdata, offset = \
                decode_rr(msg, offset, False)
            answer = {'domainame': pdomainname(domainname),
                      'ttl': ttl,
                      'rclass': qc.get_name(rrclass),
                      'rtype': qt.get_name(rrtype),
                      'rdata': rdata,
                      }
            answers.append(answer)
        rrtotal += ancount

        for section, rrcount in \
                [("authority", nscount), ("additional", arcount)]:
            if rrcount == 0:
                continue
            for i in range(rrcount):
                domainname, rrtype, rrclass, ttl, rdata, offset = \
                    decode_rr(msg, offset, False)
                if rrtype == 250:            # should decode and verify here
                    answer = {'domainame': pdomainname(domainname),
                              'ttl': ttl,
                              'rclass': qc.get_name(rrclass),
                              'rtype': qt.get_name(rrtype),
                              'rdata': rdata,
                              }
                    answers.append(answer)
        p = p[2 + msglen:]

    return answers


def decode_header(pkt, sentid, checkid=True):
    """Decode a DNS protocol header

             0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      ID                       |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |QR|   OpCode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                QDCOUNT/ZOCOUNT                |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                ANCOUNT/PRCOUNT                |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                NSCOUNT/UPCOUNT                |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ARCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    answerid, answerflags, qdcount, ancount, nscount, arcount = \
        struct.unpack('!HHHHHH', pkt[:12])
    if checkid and (answerid != sentid):
        # probably should continue listening for a valid response
        # rather than bailing out here ..
        raise Exception("got response with id: %ld (expecting %ld)" %
                        (answerid, sentid))

    qr = answerflags >> 15
    opcode = (answerflags >> 11) & 0xf
    aa = (answerflags >> 10) & 0x1
    tc = (answerflags >> 9) & 0x1
    rd = (answerflags >> 8) & 0x1
    ra = (answerflags >> 7) & 0x1
    z  = (answerflags >> 6) & 0x1
    ad = (answerflags >> 5) & 0x1
    cd = (answerflags >> 4) & 0x1
    rcode = (answerflags) & 0xf

    return (answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode,
            qdcount, ancount, nscount, arcount)


def txt2domainname(input, canonical_form=False):
    """turn textual representation of a domain name into its wire format"""
    if input == ".":
        d = '\x00'
    else:
        d = ""
        for label in input.split('.'):
            if canonical_form:
                label = label.lower()
            length = len(label)
            d += struct.pack('B', length) + label
    return d


def get_domainname(pkt, offset):
    """decode a domainname at the given packet offset; see RFC 1035"""
    global count_compression
    labellist = []               # a domainname is a sequence of labels
    Done = False
    while not Done:
        llen, = struct.unpack('B', pkt[offset])
        if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
            count_compression += 1
            c_offset, = struct.unpack('!H', pkt[offset:offset + 2])
            c_offset = c_offset & 0x3fff       # last 14 bits
            offset += 2
            rightmostlabels, junk = get_domainname(pkt, c_offset)
            labellist += rightmostlabels
            Done = True
        else:
            offset += 1
            label = pkt[offset:offset + llen]
            offset += llen
            labellist.append(label)
            if llen == 0:
                Done = True
    return (labellist, offset)


def pdomainname(labels):
    """given a sequence of domainname labels, return a printable string"""
    if len(labels) == 1:          # list with 1 empty label is the root
        return "."
    else:
        return ".".join(labels)


def decode_question(pkt, offset):
    """decode question section of a DNS message"""
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass = struct.unpack("!HH", pkt[offset:offset + 4])
    offset += 4
    return (domainname, rrtype, rrclass, offset)


def generic_rdata_encoding(rdata, rdlen):
    """return generic encoding of rdata for unknown types; see RFC 3597"""
    return "\# %d %s" % (rdlen, hexdump(rdata, separator=''))


def decode_txt_rdata(rdata, rdlen):
    """decode TXT RR rdata into a string of quoted text strings,
    escaping any embedded double quotes"""
    txtstrings = []
    position = 0
    while position < rdlen:
        slen, = struct.unpack('B', rdata[position])
        s = rdata[position + 1:position + 1 + slen]
        s = '"%s"' % s.replace('"', '\\"')
        txtstrings.append(s)
        position += 1 + slen
    return ' '.join(txtstrings)


def decode_soa_rdata(pkt, offset, rdlen):
    """decode SOA rdata: mname, rname, serial, refresh, retry, expire, min"""
    d, offset = get_domainname(pkt, offset)
    mname = pdomainname(d)
    d, offset = get_domainname(pkt, offset)
    rname = pdomainname(d)
    serial, refresh, retry, expire, min = \
        struct.unpack("!IiiiI", pkt[offset:offset + 20])
    return "%s %s %d %d %d %d %d" % \
           (mname, rname, serial, refresh, retry, expire, min)


def decode_srv_rdata(pkt, offset):
    """decode SRV rdata: priority (2), weight (2), port, target; RFC 2782"""
    priority, weight, port = struct.unpack("!HHH", pkt[offset:offset + 6])
    d, offset = get_domainname(pkt, offset + 6)
    target = pdomainname(d)
    return "%d %d %d %s" % (priority, weight, port, target)


def decode_naptr_rdata(pkt, offset, rdlen):
    """decode NAPTR: order, pref, flags, svc, regexp, replacement; RFC 2915"""
    param = {}
    order, pref = struct.unpack('!HH', pkt[offset:offset + 4])
    position = offset + 4
    for name in ["flags", "svc", "regexp"]:
        slen, = struct.unpack('B', pkt[position])
        s = pkt[position + 1:position + 1 + slen]
        param[name] = '"%s"' % s.replace('\\', '\\\\')
        position += (1 + slen)
    d, junk = get_domainname(pkt, position)
    replacement = pdomainname(d)
    return "%d %d %s %s %s %s" % (order, pref, param["flags"], param["svc"],
                                  param["regexp"], replacement)


def decode_rr(pkt, offset, hexrdata):
    """ Decode a resource record, given DNS packet and offset"""

    domainname, offset = get_domainname(pkt, offset)

    if len(pkt) < offset + 10:
        logger.error('Invalid DNS packet %s', binascii.hexlify(pkt))
        raise EInvalidDNS(binascii.hexlify(pkt))

    rrtype, rrclass, ttl, rdlen = \
        struct.unpack("!HHIH", pkt[offset:offset + 10])
    offset += 10
    rdata = pkt[offset:offset + rdlen]
    if hexrdata:
        rdata = hexdump(rdata)
    elif rrtype == 1:                                        # A
        rdata = socket.inet_ntop(socket.AF_INET, rdata)
    elif rrtype in [2, 5, 12, 39]:                           # NS, CNAME, PTR
        rdata, junk = get_domainname(pkt, offset)            # DNAME
        rdata = pdomainname(rdata)
    elif rrtype == 6:                                        # SOA
        rdata = decode_soa_rdata(pkt, offset, rdlen)
    elif rrtype == 15:                                       # MX
        mx_pref, = struct.unpack('!H', pkt[offset:offset + 2])
        rdata, junk = get_domainname(pkt, offset + 2)
        rdata = "%d %s" % (mx_pref, pdomainname(rdata))
    elif rrtype in [16, 99]:                                 # TXT, SPF
        rdata = decode_txt_rdata(rdata, rdlen)
    elif rrtype == 28:                                       # AAAA
        rdata = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rrtype == 33:                                       # SRV
        rdata = decode_srv_rdata(pkt, offset)
    elif rrtype == 35:                                       # NAPTR
        rdata = decode_naptr_rdata(pkt, offset, rdlen)
    else:                                                    # use RFC 3597
        rdata = generic_rdata_encoding(rdata, rdlen)
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, rdata, offset)


class DNSQuery(object):

    def __init__(self,
                 server=None,
                 port=DEFAULT_PORT,
                 udp=False,
                 aa=0,
                 cd=0,
                 rd=1,
                 use_edns0=False,
                 dnssec_ok=0,
                 hexrdata=False,
                 ptr=False,
                 af=socket.AF_UNSPEC,
                 msgid=None):

        self.server = server
        self.port = port
        self.udp = udp
        self.aa = aa
        self.cd = cd
        self.rd = rd
        self.use_edns0 = use_edns0
        self.dnssec_ok = dnssec_ok
        self.hexrdata = hexrdata
        self.ptr = ptr
        self.af = af
        self.msgid = msgid

        if not server:
            self.server = '8.8.8.8'
            #for line in open(RESOLV_CONF):
            #    if line.startswith("nameserver"):
            #        self.server = line.split()[1]
            #        break
            #else:
            #    raise Exception("Couldn't find a default server in %s" %
            #                    RESOLV_CONF)

    def mk_id(self):
        if self.msgid:
            return self.msgid
        else:
            random.seed()
            return random.randint(1, 65535)

    def mk_request(self, qname, qtype_val, qclass, id):
        """Construct DNS query packet, given various parameters"""
        packed_id = struct.pack('!H', id)
        qr = 0                                      # query/response
        opcode = 0                                  # standard query
        aa = self.aa                          # authoritative answer
        tc = 0                                      # truncated response
        rd = self.rd                          # recursion desired
        ra = 0                                      # recursion available
        z = 0                                       # reserved
        ad = 0                                      # authenticated data
        cd = self.cd                          # checking disabled
        rcode = 0                                   # response code
        qdcount = struct.pack('!H', 1)              # 1 question
        ancount = struct.pack('!H', 0)              # 0 answer
        nscount = struct.pack('!H', 0)              # 0 authority

        arcount = struct.pack('!H', 0)
        additional = ""

        flags = (qr << 15) + (opcode << 11) + (aa << 10) + (tc << 9) + \
                (rd << 8) + (ra << 7) + (z << 6) + (ad << 5) + (cd << 4) + rcode
        flags = struct.pack('!H', flags)

        wire_qname = txt2domainname(qname)          # wire format domainname

        msg = packed_id
        msg += flags
        msg += qdcount
        msg += ancount
        msg += nscount
        msg += arcount
        #msg += question
        msg += str(wire_qname)
        msg += struct.pack('!H', qtype_val)
        msg += struct.pack('!H', qclass)
        msg += additional

        return msg

    def query(self, qname, qtype='A', qclass='IN'):
        if self.ptr:
            qname = ip2ptr(qname)
            qtype = "PTR"
            qclass = "IN"
        else:
            if not qname.endswith("."):
                qname += "."

        qtype_val = qt.get_val(qtype)
        qclass_val = qc.get_val(qclass)

        try:
            server_addr, port, family, socktype = \
                get_socketparams(self.server, self.port,
                                 self.af, socket.SOCK_DGRAM)
        except socket.gaierror, diag:
            raise Exception("bad server: %s (%s)" % (self.server, diag))

        id = self.mk_id()
        tc = 0
        request = self.mk_request(qname, qtype_val, qclass_val, id)
        #size_query = len(request)

        if qtype == "AXFR":
            response, resplen = do_axfr(request, server_addr, port, family)
            return decode_axfr(response, resplen)

        responsepkt = send_request_tcp(request, server_addr, port, family)
        if not responsepkt:
            logger.warning('Empty response from %s', self.server)
            return []
        responsepkt = responsepkt[2:]           # ignore 2-byte length
        answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
            qdcount, ancount, nscount, arcount = \
            decode_header(responsepkt, id)

        r = responsepkt
        offset = 12                     # skip over DNS header

        answer_qname = ''
        for i in range(qdcount):
            domainname, rrtype, rrclass, offset = decode_question(r, offset)
            answer_qname = pdomainname(domainname)

        if (not domain_name_match(answer_qname, qname)) \
           or (qtype_val != rrtype) or (qclass_val != rrclass):
            logger.warning("WARNING: Answer form %s didn't match question qname: %s/%s, qtype: %d/%d, qclass: %d/%d",
                           self.server, answer_qname, qname, qtype_val, rrtype, qclass_val, rrclass)

        answers = []
        for section, rrcount in \
                [("answer", ancount),  ("authority", nscount), ("additional", arcount)]:
            if rrcount == 0:
                continue
            for i in range(rrcount):
                domainname, rrtype, rrclass, ttl, rdata, offset = \
                    decode_rr(r, offset, self.hexrdata)
                answer = {'domainame': pdomainname(domainname),
                          'ttl': ttl,
                          'rtype': qt.get_name(rrtype),
                          'rdata': rdata,
                          }
                answers.append(answer)

        return answers

    def getauthns(self, qname):
        re = self.query(qname, 'NS', 'IN')
        ns = []
        for a in re:
            ns.extend(a['rdata'].split(' '))
        return ns

    def gethostbyname(self, qname):
        return self.query(qname, 'ANY', 'IN')

    def gethostbyaddr(self, ip):
        self.ptr = True
        resp = self.query(ip, 'PTR', 'IN')
        self.ptr = False
        return resp

    def zonetransfer(self, qname, ns=[]):
        trans = {}
        if ns:
            for server in ns:
                self.server = server
                try:
                    trans[server] = self.query(qname, 'AXFR', 'IN')
                    if trans[server]:
                        break
                except NOTAUTH:
                    logger.warning('%s does not allow zone transfers', self.server)
                except socket.error:
                    logger.warning('%s timed out', self.server)
        else:
            try:
                trans[self.server] = self.query(qname, 'AXFR', 'IN')
            except NOTAUTH:
                logger.warning('%s does not allow zone transfers', self.server)
        return trans

    def version(self):
        return self.query('version.bind', 'TXT', 'CH')


def getauthns(qname):
    dns = DNSQuery()
    re = dns.query(qname, 'NS', 'IN')
    ns = []
    for a in re:
        ns.extend(a['rdata'].split(' '))
    return ns


def gethostbyname(qname):
    dns = DNSQuery()
    return dns.query(qname, 'ANY', 'IN')


def gethostbyaddr(ip):
    dns = DNSQuery()
    dns.ptr = True
    resp = dns.query(ip, 'PTR', 'IN')
    dns.ptr = False
    return resp


if __name__ == "__main__":
    q = DNSQuery()
    r = q.gethostbyname('curesec.com')
    print repr(r)
    r = q.gethostbyaddr('87.106.123.182')
    print repr(r)
    q = DNSQuery(server='ns12.zoneedit.com')
    r = q.version()
    print repr(r)
    q = DNSQuery(server='ns12.zoneedit.com')
    r = q.zonetransfer('zonetransfer.me')
    print repr(r)
