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
import socket
import struct
import binascii
import sys
import cTls


#test = '\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03' + \
#       '\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51' + \
#       '\x4c\x53\x65\x72\x76\x65\x72\x00\x56\x55\x00\x00'
#test2 ='\x16' + \  # msg type
#       '\x03\x00' + \  # ssl version
#       '\x00\x58' + \  # len cipher list
#       '\x01' + \ # handshake type client_hello
#       '\x00\x00\x54' + \  # len msg
#       '\x03\x03' + \  # client preferred version
#       \ # (time, rand28) client random
#       '\x52\xf3\x61\x4a' + '\x68\xc4\x86\xf5' + '\xd1\x99\xe8\xfc' + '\x9d\x09\x23\x07' + \
#       '\x7e\xf2\x50\x8b' + '\x64\x42\xb9\x47' + '\xc8\x03\x16\x88' + '\x6e\x30\x75\x13' + \
#       '\x00' + \  # Session ID Length 0 (for resuming the session)
#       '\x00\x18' + \  # Ciphersuit Length
#       '\x00\x35' + \
#       '\x00\x2f' + \
#       '\x00\x0a' + \
#       '\x00\x05' + \
#       '\x00\x04' + \
#       '\x00\x38' + \
#       '\x00\x32' + \
#       '\x00\x13' + \
#       '\x00\x66' + \
#       '\x00\x39' + \
#       '\x00\x33' + \
#       '\x00\x16' + \
#       '\x01' + \  # comprssion method length
#       '\x00' + \  # compression method
#       '\x00\x13' + \  # length of extensions
#       '\xff\x01' + \  # renegotioation info
#       '\x00\x01' + \  # length
#       '\x00' + \  # for inital handshakes
#       '\x00\x0d' + \  # signature_algorithm
#       '\x00\x0a' + \  # length
#       '\x00\x08\x04\x02\x04\x01\x02\x01\x02\x02'  # hash algorithms

def print_8x8(data):
    print ''
    for idx, c in enumerate(data):
        if idx and idx % 2 == 0:
            sys.stdout.write(' ')
        if idx and idx % 16 == 0:
            sys.stdout.write('\t')
        if idx and idx % 32 == 0:
            sys.stdout.write('\n')
        sys.stdout.write('%s' % c)
    print ''


class Mssql():
    rPRELOGIN_TOKTYPE = ['version',
                         'encryption',
                         'instopt',
                         'threadid',
                         'mars',
                         'traceid',
                         'fedauthrequired',
                         'nonceopt',
                         ]
    PRELOGIN_TOKTYPE = dict([val, idx] for idx, val in enumerate(rPRELOGIN_TOKTYPE))
    PRELOGIN_TOKFMT = {'version': '!IH',
                       'encryption': 'c',
                       'instopt': '%dc',
                       'threadid': '!I',
                       'mars': 'c',
                       'traceid': '16c',
                       'fedauthrequired': 'c',
                       'nonceopt': '32c'
                       }
    PTYP = {0x04: 'response',
            0x12: 'prelogin',
            0x10: 'login7',
            }

    def __init__(self, ip, port, timeout=3, ssl=False):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.ssl = ssl
        self.sock = None

    def connect(self):
        self.sock = socket.socket()
        self.sock.connect((self.ip, int(self.port)))

    def _wrap_header(self, pkt, pkt_type=0x12):
        l = len(pkt) + 8
        header = ''
        header += struct.pack('!c', chr(pkt_type))  # 0x12 == TDS7 PRE_LOGIN
        header += struct.pack('!c', '\x01')  # status: end of message
        header += struct.pack('!H', l)       # pkt length
        header += struct.pack('!H', 0x00)  # channel
        header += struct.pack('!c', '\x00')  # packet number
        header += struct.pack('!c', '\x00')  # window
        pkt = header + pkt
        return pkt

    def send_prelogin(self):
        pkt = self._pack_prelogin_stream(version=[0x08000155, 0x00],
                                         encryption=['\x02'],
                                         instopt='MSSQLServer\0',
                                         threadid=[0])
        pkt = self._wrap_header(pkt)
        self.sock.sendall(pkt)
        data = self._get_pkt()
        self._unpack_stream(data)
        # TEST: send ssl payload
        print 'sending test data'
        pkt = cTls.ClientHello()
        pkt = self._wrap_header(pkt)
        self.sock.sendall(pkt)

    def _get_pkt(self):
        # read header
        data = self.sock.recv(1)
        ptype = struct.unpack('!c', data)[0]
        print 'Packet type: %x' % ord(ptype)
        data = self.sock.recv(1)
        status = struct.unpack('!c', data)[0]
        print 'Status: %x' % ord(status)
        data = self.sock.recv(2)
        length = struct.unpack('!H', data)[0]
        print 'Length: %x' % (length)
        data = self.sock.recv(2)
        channel = struct.unpack('!H', data)[0]
        print 'Channel: %x' % (channel)
        data = self.sock.recv(1)
        pnum = struct.unpack('!c', data)[0]
        print 'P number: %x' % ord(pnum)
        data = self.sock.recv(1)
        window = struct.unpack('!c', data)[0]
        print 'Window: %x' % ord(window)

        # read stream
        stream_length = length - 8
        data = ''
        while True:
            buf = self.sock.recv(stream_length)
            if not buf:
                break
            data += buf
            if len(data) >= stream_length:
                break
        return data

    def _unpack_stream(self, stream):
        cstream = stream[:]
        while cstream:
            tok_typ = ord(struct.unpack('c', cstream[:1])[0])
            cstream = cstream[1:]
            print "Token Typ: %x (%s)" % (tok_typ, Mssql.rPRELOGIN_TOKTYPE[tok_typ])
            tok_pos = struct.unpack('!H', cstream[:2])[0]
            cstream = cstream[2:]
            print "Token Pos: %x" % tok_pos
            tok_len = struct.unpack('!H', cstream[:2])[0]
            cstream = cstream[2:]
            print "Token Len: %x" % tok_len
            tok_data = struct.unpack('%ds' % tok_len, stream[tok_pos:(tok_pos + tok_len)])[0]
            print tok_data
            print binascii.hexlify(tok_data)
            if tok_pos + tok_len >= len(stream):
                break

    def _sorted_tokidx(self, **kwargs):
        for x in sorted([(Mssql.PRELOGIN_TOKTYPE[item[0]], item) for item in kwargs.items()]):
            yield x[1]
        raise StopIteration

    def _pack_prelogin_stream(self, **kwargs):
        print kwargs
        # each token description is 5 bytes long (type/number:1, position:2, length:2)
        # plus o byte for terminator: 0xff
        meta_len = len(kwargs) * 5 + 1
        stream_cpos = meta_len
        meta = ''
        data = ''
        for k, v in self._sorted_tokidx(**kwargs):
            print k
            tokidx = Mssql.PRELOGIN_TOKTYPE[k]
            tokfmt = Mssql.PRELOGIN_TOKFMT[k]
            # insert length for variable sized fields
            idx_fstr = tokfmt.find('%d')
            if idx_fstr >= 0:
                tokfmt = tokfmt % len(v)
                print tokfmt
            toklen = struct.calcsize(tokfmt)
            tokstart = stream_cpos
            stream_cpos += toklen

            # Write token metadata
            # token type
            meta += struct.pack('c', chr(tokidx))
            # token start
            meta += struct.pack('!H', tokstart)
            # token length
            meta += struct.pack('!H', toklen)

            # Write token data
            data += struct.pack(tokfmt, *v)

        return meta + '\xff' + data

    def _pack_stream(self, tokens):
        # so ... it seems like the format is like
        # n = 0
        # for tupel in tuples:
        #   1 TokenType: n
        #   2 TokenPosition: x x
        #   3 TokenLength: x x
        # actual data
        descr = ''
        stream = ''
        # each token is 5 bytes long (type/number:1, position:2, length:2)
        stream_cpos = len(tokens) * 5 + 1
        for idx, tok in enumerate(tokens):
            l_tok = tok['len']
            descr += struct.pack('c', chr(idx))
            descr += struct.pack('!H', stream_cpos)
            descr += struct.pack('!H', l_tok)
            stream_cpos += l_tok
            print tok['fmt']
            print tok['data']
            stream += struct.pack(tok['fmt'], *tok['data'])
        print binascii.hexlify(descr)
        print binascii.hexlify(stream)
        return descr + '\xff' + stream

    def _pack_prelogin(self,
                       version=0x55,
                       encryption=0x00,
                       instvalifity='MSSQLServer\0',
                       threadid=0):
        tokens = []

        tok_version = {}
        tok_version['len'] = 6
        tok_version['data'] = [0x08000155, 0x00]
        tok_version['fmt'] = '!IH'
        tokens.append(tok_version)

        tok_encryption = {}
        tok_encryption['len'] = 1
        tok_encryption['data'] = [chr(encryption)]
        tok_encryption['fmt'] = '!c'
        tokens.append(tok_encryption)

        tok_instvalifity = {}
        tok_instvalifity['len'] = len(instvalifity)
        tok_instvalifity['data'] = instvalifity
        tok_instvalifity['fmt'] = '%dc' % tok_instvalifity['len']
        tokens.append(tok_instvalifity)

        tok_threadid = {}
        tok_threadid['len'] = 4
        tok_threadid['data'] = [threadid]
        tok_threadid['fmt'] = '!I'
        tokens.append(tok_threadid)

        return self._pack_stream(tokens)

if __name__ == '__main__':
    ch = cTls.ClientHello.data()
    print_8x8(binascii.hexlify(ch))
    #ms = Mssql('192.168.170.114', 1433)
    #ms.connect()
    #ms.send_prelogin()
    #ms._unpack_stream(test2)
    #pkt = ms._pack_prelogin()
    #print binascii.hexlify(pkt)
    #print binascii.hexlify(test)
    #ms._unpack_stream(pkt)
    #pkt = ms._wrap_header(pkt)
    #print binascii.hexlify(pkt)
