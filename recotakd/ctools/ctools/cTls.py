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
# This is a super simple tool to create raw packet data for ssl handshakes
# Client_Hello Version 2: https://tools.ietf.org/html/rfc6101#section-5.5
# Client Hello: http://tools.ietf.org/html/rfc5246#section-7.4.1.2
# Signature Algorithms: http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
# renegotiation_info: http://tools.ietf.org/html/rfc5746#section-3.2

import struct
import random
import time


class CipherSuites:

    """ http://tools.ietf.org/html/rfc5246#appendix-A.5 """

   #The following  definitions require that the server provide
   #an RSA certificate that can be used for key exchange.  The server may
   #request any signature-capable certificate in the certificate request
   #message.

    TLS_RSA_WITH_NULL_MD5         = {0x00, 0x01}
    TLS_RSA_WITH_NULL_SHA         = {0x00, 0x02}
    TLS_RSA_WITH_NULL_SHA256          = {0x00, 0x3B}
    TLS_RSA_WITH_RC4_128_MD5          = {0x00, 0x04}
    TLS_RSA_WITH_RC4_128_SHA          = {0x00, 0x05}
    TLS_RSA_WITH_3DES_EDE_CBC_SHA     = {0x00, 0x0A}
    TLS_RSA_WITH_AES_128_CBC_SHA      = {0x00, 0x2F}
    TLS_RSA_WITH_AES_256_CBC_SHA      = {0x00, 0x35}
    TLS_RSA_WITH_AES_128_CBC_SHA256       = {0x00, 0x3C}
    TLS_RSA_WITH_AES_256_CBC_SHA256       = {0x00, 0x3D}

    #The following cipher suite definitions are used for server-
    #authenticated (and optionally client-authenticated) Diffie-Hellman.
    #DH denotes cipher suites in which the server's certificate contains
    #the Diffie-Hellman parameters signed by the certificate authority
    #(CA).  DHE denotes ephemeral Diffie-Hellman, where the Diffie-Hellman
    #parameters are signed by a signature-capable certificate, which has
    #been signed by the CA.  The signing algorithm used by the server is
    #specified after the DHE component of the  name.  The
    #server can request any signature-capable certificate from the client
    #for client authentication, or it may request a Diffie-Hellman
    #certificate.  Any Diffie-Hellman certificate provided by the client
    #must use the parameters (group and generator) described by the
    #server.

    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = {0x00, 0x0D}
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = {0x00, 0x10}
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = {0x00, 0x13}
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = {0x00, 0x16}
    TLS_DH_DSS_WITH_AES_128_CBC_SHA       = {0x00, 0x30}
    TLS_DH_RSA_WITH_AES_128_CBC_SHA       = {0x00, 0x31}
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA      = {0x00, 0x32}
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA      = {0x00, 0x33}
    TLS_DH_DSS_WITH_AES_256_CBC_SHA       = {0x00, 0x36}
    TLS_DH_RSA_WITH_AES_256_CBC_SHA       = {0x00, 0x37}
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA      = {0x00, 0x38}
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA      = {0x00, 0x39}
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = {0x00, 0x3E}
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = {0x00, 0x3F}
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = {0x00, 0x40}
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = {0x00, 0x67}
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = {0x00, 0x68}
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = {0x00, 0x69}
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = {0x00, 0x6A}
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = {0x00, 0x6B}

    #The following cipher suites are used for completely anonymous
    #Diffie-Hellman communications in which neither party is
    #authenticated.  Note that this mode is vulnerable to man-in-the-
    #middle attacks.  Using this mode therefore is of limited use: These
    #cipher suites MUST NOT be used by TLS 1.2 implementations unless the
    #application layer has specifically requested to allow anonymous key
    #exchange.  (Anonymous key exchange may sometimes be acceptable, for
    #example, to support opportunistic encryption when no set-up for
    #authentication is in place, or when TLS is used as part of more
    #complex security protocols that have other means to ensure
    #authentication.)

    TLS_DH_anon_WITH_RC4_128_MD5      = {0x00, 0x18}
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = {0x00, 0x1B}
    TLS_DH_anon_WITH_AES_128_CBC_SHA      = {0x00, 0x34}
    TLS_DH_anon_WITH_AES_256_CBC_SHA      = {0x00, 0x3A}
    TLS_DH_anon_WITH_AES_128_CBC_SHA256   = {0x00, 0x6C}
    TLS_DH_anon_WITH_AES_256_CBC_SHA256   = {0x00, 0x6D}


class HashAlgorithm():
    none, sha1, md5, sha224, sha256, sha394, sha512 = range(7)


class SignatureAlgorithm():
    anonymous, rsa, dsa, ecdsa = range(4)


class RenegotiationInfo():

    """ http://tools.ietf.org/html/rfc5746#section-3.2 """

    ident = '\xff\x01'

    @staticmethod
    def data():
        pkt = RenegotiationInfo.ident + '\x00\x01\x00'
        return pkt


class Signature():

    """ http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 """

    ident = '\x00\x0d'

    @staticmethod
    def data(algorithms=[(HashAlgorithm.none, 0x08),
                         (HashAlgorithm.sha256, SignatureAlgorithm.dsa),
                         (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                         (HashAlgorithm.sha1, SignatureAlgorithm.dsa),
                         (HashAlgorithm.sha1, SignatureAlgorithm.rsa)
                         ]
             ):

        pkt = ''
        pkt += Signature.ident
        pkt += struct.pack('!H', len(algorithms) * 2)
        for a in algorithms:
            pkt += struct.pack('bb', *a)
        return pkt


class ClientHello():

    """ http://tools.ietf.org/html/rfc5246#section-7.4.1.2 """

    ident = '\x16'

    @staticmethod
    def data(version=(3, 0),
             cipher_suites=[CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
                            CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
                            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
                            CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                            CipherSuites.TLS_RSA_WITH_RC4_128_MD5,
                            CipherSuites.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                            CipherSuites.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                            CipherSuites.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                            CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                            CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                            CipherSuites.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA],
             client_pref_version=(3, 3),
             compression_methods=[0],
             extensions=[RenegotiationInfo, Signature]):
        pkt = ''
        ## packet type
        #pkt += struct.pack('c', ClientHello.ident)
        ## client version
        #pkt += struct.pack('!HH', *version)
        ## handshake type ... yea
        #pkt += struct.pack('c', '\x01')
        ## message length
        ## TODO
        #pkt += '\x00' + struct.pack('!H', 0)
        # client preferred version
        pkt += struct.pack('!BB', *client_pref_version)

        # timestamp
        pkt += struct.pack('!I', time.time())
        # random data
        r = random.getrandbits(28 * 8)
        while r:
            pkt += struct.pack('c', chr(r & 0xFF))
            r = r >> 8

        # session id length
        pkt += struct.pack('c', '\x00')

        # cipher suites
        pkt += struct.pack('!H', len(cipher_suites) * 2)
        for cs in cipher_suites:
            pkt += struct.pack('!BB', *cs)

        # compression methods
        pkt += struct.pack('!c', chr(len(compression_methods)))
        for cm in compression_methods:
            pkt += struct.pack('!b', cm)

        for e in extensions:
            pkt += e.data()

        mlength = len(pkt)
        pkt = '\x01\x00' + struct.pack('!H', mlength) + pkt
        mlength = len(pkt)
        pkt = struct.pack('c', ClientHello.ident) + struct.pack('!BB', *version) + struct.pack('!H', mlength) + pkt
        return pkt
