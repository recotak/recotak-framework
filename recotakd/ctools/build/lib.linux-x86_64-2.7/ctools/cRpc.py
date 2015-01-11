from __future__ import with_statement
import struct
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
import select
import random
import socket
import binascii
import __builtin__


PROGRAM = {'PORTMAP': 100000, }
PORT = {'SUNRPC': 111, }
MSG_TYPE = {'CALL': 0,
            'REPLY': 1}
REPLY_STAT = {'MSG_ACCEPTED': 0,
              'MSG_DENIED': 1}
ACCEPT_STAT = {'SUCCESS': 0,
               'PROG_UNAVAIL': 1,
               'PROG_UNAVAIL': 1,
               'PROG_MISMATCH': 2,
               'PROC_UNAVAIL': 3,
               'GARBAGE_ARGS': 4,
               'SYSTEM_ERR': 5}
REJECT_STAT = {
    'RPC_MISMATCH': 0,
    'AUTH_ERROR': 1
}
FLAVOR = {'AUTH_UNIX': 1}
PROTO = {'TCP': 0x06, 'UDP': 0x07}
RPROTO = {'6': 'TCP', '17': 'UDP'}
PROC_NAMES = {'DUMP': 4, 'GETPORT': 3, 'EXPORT': 5}
RPC_NAMES = {}
RRPC_NAMES = {}
RPC_PATH = '/etc/rpc'


def read_rpc():
    names = None
    try:
        names = __builtin__.openany(RPC_PATH, 'r')
    except:
            names = open(RPC_PATH, 'r')
    for line in names.read().splitlines():
        if not line or line[0] == '#':
            continue
        data = list(line.split())
        RPC_NAMES[data[0].upper()] = int(data[1])
        RRPC_NAMES[int(data[1])] = data[0].upper()


class MOUNTD():
    @staticmethod
    def EXPORT(pkt):
        dir_follows = struct.unpack('!I', pkt[:4])[0]
        pkt = pkt[4:]

        def read_entry(pkt):
            # read length
            l = struct.unpack('!I', pkt[:4])[0]
            pkt = pkt[4:]
            data = struct.unpack('!%ds' % l, pkt[:l])[0]
            # calculate padding
            l = l + 4
            padding = l % 4
            if padding:
                l += 4 - padding
            pkt = pkt[l - 4:]
            # read value_follows flag
            value_follows = struct.unpack('!I', pkt[:4])[0]
            pkt = pkt[4:]
            return (value_follows, data, pkt)

        dir_entries = []
        # read directories
        while dir_follows:
            group_follows, dir_entry, pkt = read_entry(pkt)
            groups = []
            while group_follows:
                group_follows, group, pkt = read_entry(pkt)
                groups.append(group)
                dir_entries.append((dir_entry, groups))
            dir_follows = struct.unpack('!I', pkt[:4])[0]
            pkt = pkt[4:]
        return dir_entries


class PORTMAPPER():
    def pack_call_getport(self, program, version, proto=PROTO['TCP'], port=0):
        pkt = struct.pack('!IIII',
                          RPC_NAMES[program],
                          version,
                          proto,
                          port)
        return pkt

    @staticmethod
    def DUMP(pkt):
        map_entries = []
        entry_follows = struct.unpack('!I', pkt[:4])[0]
        pkt = pkt[4:]
        parsed = []
        while entry_follows:
            try:
                map_entry = list(struct.unpack('!IIII', pkt[:16]))

                name = ''
                try:
                    name = RRPC_NAMES[int(map_entry[0])]
                except KeyError:
                    pass
                map_entry.append(name)
                map_entries.append(map_entry)

                parsed.append(binascii.hexlify(pkt[:20]))
                pkt = pkt[16:]
                entry_follows = struct.unpack('!I', pkt[:4])[0]
                pkt = pkt[4:]
            except struct.error as e:
                print 'Can not decode %s: \n\t%s' % (e, binascii.hexlify(pkt))
                print 'Parsed: \n\t%s' % '\n\t'.join(parsed)
                break
        return map_entries

    @staticmethod
    def GETPORT(pkt):
        port = struct.unpack('!I', pkt[:4])[0]
        return port


class Rpc():
    def __init__(self, ip, keep_alive=False, timeout=1, xid=0, version=2):

        """ Connect an RPC client instance to IP

            input:
                ip          RPC server ip
                keep_alive  Keep connection to RPC server alive during session (default False)
                timeout     server timeout (optional)
                xid         random id (optional)
                version     ... of the RPC client (default 2)
        """

        self.xid = xid
        if not self.xid:
            self.xid = random.getrandbits(32)
        self.version = version
        self.ip = ip
        self.timeout = timeout

        self.portmap = None
        if not RPC_NAMES:
                read_rpc()

    def close(self):
        # we open a new connection for each call
        # so there is no cleanup
        pass

    def call2(self, program, proc, version=1, proto=PROTO['TCP']):
        """ Like call, but this function gets all the information out of the portmap dump

            input:
                program     program_name proc                Name of the program function (e.g. DUMP)
                proto               Protocol to use (choices: TCP, UDP)

            output:
                Return value of PROGRAM.PROC(raw packet data)
        """
        if not self.portmap:
            # get protmap dump
            self.portmap = self.call('PORTMAPPER', 2, 'DUMP', PORT['SUNRPC'], PROTO['TCP'])

        program_num = RPC_NAMES[program.upper()]
        port = 0
        for prog_data in self.portmap:
            if prog_data[0] == program_num and \
                    prog_data[1] == version and \
                    prog_data[2] == proto:
                version = prog_data[1]
                port = prog_data[3]
                break
        #print '%s.%s (v%d) @ %d:0x%x' % (program, proc, version, port, proto)
        return self.call(program, version, proc, port, proto)

    def call(self, program, program_version, proc, port, proto=PROTO['TCP']):

        """ This fuinction calls a routine via rpc.
            The handling of the reply is handled by the class function named:
                PROGRAM.PROC(raw packet data)

            input:
                program             RPC program Name from /etc/rpc (e.g. PORTMAPPER)
                program_version     Version of the selected program
                proc                Name of the program function (e.g. DUMP)
                port                Port the program is listening on
                proto               Protocol to use (choices: TCP, UDP)

            output:
                Return value of PROGRAM.PROC(raw packet data)
        """

        # connect to rpc server
        sock = None
        try:
            if proto == PROTO['TCP']:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            elif proto == PROTO['UDP']:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                raise Exception('Bad protocol type: %s' % proto)
            sock.settimeout(self.timeout)
            if proto == PROTO['TCP']:
                sock.connect((self.ip, int(port)))

            # construct and send call_pkt packet
            call_pkt = self.pack_call(program, program_version, proc, proto)
            call_pkt += self.pack_verifyer()
            call_pkt += self.pack_verifyer()
            if proto == PROTO['TCP']:
                # TODO
                call_pkt = self.wrap_header(call_pkt)
                sock.sendall(call_pkt)
            elif proto == PROTO['UDP']:
                sock.sendto(call_pkt, (self.ip, int(port)))

            # get and dissect reply_pkt
            reply_pkt = ''
            if proto == PROTO['TCP']:
                reply_pkt = self.get_tcp_packet(sock)
            elif proto == PROTO['UDP']:
                reply_pkt = self.get_udp_packet(sock)

            # process rpc part of the reply
            reply_pkt = self.unpack_reply(reply_pkt)
            # process reply via according class
            reply_func = getattr(globals()[program.upper()], proc.upper())
        finally:
            sock.close()
        return reply_func(reply_pkt)

    def pack_verifyer(self):
        pkt = struct.pack('!II', 0, 0)
        return pkt

    def pack_call(self, program, program_version,
                  procedure, proto='TCP'):
        pkt = ''
        pkt += struct.pack('!IIIIII',
                           self.xid,
                           MSG_TYPE['CALL'],
                           self.version,
                           RPC_NAMES[program],
                           program_version,
                           PROC_NAMES[procedure])
        return pkt

    def unpack_reply(self, pkt):

        xid = struct.unpack('!I', pkt[:4])[0]
        if xid != self.xid:
            raise Exception('Error: xid mismatch (%x != %x)' % (self.xid, xid))
        pkt = pkt[4:]

        msg_type = struct.unpack('!I', pkt[:4])[0]
        if msg_type != MSG_TYPE['REPLY']:
            raise Exception('Error: wrong message type')
        pkt = pkt[4:]

        reply_state = struct.unpack('!I', pkt[:4])[0]
        if reply_state != 0:
            raise Exception('Rpc call unsuccessful: reply state %d' % reply_state)
        pkt = pkt[4:]

        #verifyer = struct.unpack('!II', pkt[:8])[0]
        pkt = pkt[8:]

        accept_state = struct.unpack('!I', pkt[:4])[0]
        if accept_state != 0:
            raise Exception('Rpc call unsuccessful: accept_state %d' % accept_state)
        pkt = pkt[4:]

        return pkt

    def wrap_header(self, pkt):
        l = len(pkt)
        fragment_header = struct.pack('!HH', 0x8000, l)
        return fragment_header + pkt

    def get_tcp_packet(self, sock):

        """ read the packet size x (first 3 bytes) and return x bytes of the remaining pkt

            input:
                sock    stream socket

            output:
                raw packet data
        """

        # the first? byte indicates the fragment status (last fragament==1?)
        # after that goes the packet size
        pkt = ''
        try:
            while True:
                psize = ''
                while True:
                    psize += sock.recv(1)
                    if len(psize) == 4:
                        break
                p0 = psize[0]
                psize = '\0' + psize[1:4]  # remove packet number
                psize = int(struct.unpack('!I', psize)[0])
                # read actual pkt
                while True:
                    pkt += sock.recv(1)
                    if len(pkt) == psize:
                        break
                if binascii.hexlify(p0) == '80':
                    break
        except socket.timeout:
            pass
        return pkt

    def get_udp_packet(self, sock, size=0):

        """ read the all the packet data

            input:
                sock    datagram socket
                size    amount of data to be read (optional)

            output:
                raw packet data
        """

        pkt = ''
        while True:
            buf = ''
            try:
                buf = sock.recvfrom(64)[0]
            except socket.timeout:
                break
            if size and len(pkt) >= size:
                break
            if not buf:
                break
            pkt += buf
        return pkt


if __name__ == '__main__':

    import sys
    if sys.argv[1]:
        ip = sys.argv[1]
    else:
        ip = '192.168.1.125'

    print 'PORTMAPPER.DUMP'
    rpc = Rpc(ip)
    reply = rpc.call('PORTMAPPER', 2, 'DUMP', 111, PROTO['TCP'])
    for program in reply:
        for field in program:
            print field
        print ''

    print 'PORTMAPPER.GETPORT'
    rpc = Rpc(ip)
    mountd_port = rpc.call('PORTMAPPER', 2, 'GETPORT', 111, PROTO['UDP'])
    print 'Port: %d' % mountd_port

    print 'MOUNTD.EXPORT'
    rpc = Rpc(ip)
    dirs = rpc.call2('MOUNTD', 'EXPORT')
    for dir in dirs:
        print dir
