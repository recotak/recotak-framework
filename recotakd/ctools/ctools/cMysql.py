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
# protocol documentation at
# http://dev.mysql.com/doc/internals/en/connection-phase-packets.html

import socket
import struct
import binascii
import hashlib
import sys
import ssl

# logging
import logging
#LOG = "/tmp/cMysql.log"
#FORMAT = '%(asctime)s - %(name)s - ' + \
#    '%(levelname)s - %(threadName)s - %(message)s'
#logging.basicConfig(filename=LOG,
#                    filemode="w",
#                    format=FORMAT,
#                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())


Capability = {
    "CLIENT_LONG_PASSWORD":        0x0001,   # new more secure passwords
    "CLIENT_FOUND_ROWS":           0x0002,   # Found instead of affected rows
    "CLIENT_LONG_FLAG":            0x0004,   # Get all column flags
    "CLIENT_CONNECT_WITH_DB":      0x0008,   # One can specify db on connect
    "CLIENT_NO_SCHEMA":            0x0010,   # Don't allow database.table.column
    "CLIENT_COMPRESS":             0x0020,   # Can use compression protocol
    "CLIENT_ODBC":                 0x0040,   # Odbc client
    "CLIENT_LOCAL_FILES":          0x0080,   # Can use LOAD DATA LOCAL
    "CLIENT_IGNORE_SPACE":         0x0100,   # Ignore spaces before '('
    "CLIENT_PROTOCOL_41":          0x0200,   # New 4.1 protocol
    "CLIENT_INTERACTIVE":          0x0400,   # This is an interactive client
    "CLIENT_SSL":                  0x0800,   # Switch to SSL after handshake
    "CLIENT_IGNORE_SIGPIPE":       0x1000,   # IGNORE sigpipes
    "CLIENT_TRANSACTIONS":         0x2000,   # Client knows about transactions
    "CLIENT_SECURE_CONNECTION":    0x8000,   # New 4.1 authentication
    "CLIENT_MULTI_STATEMENTS":     0x10000,  # Enable/disable multi-stmt support
    "CLIENT_MULTI_RESULTS":        0x20000,  # Enable/disable multi-results
    "CLIENT_PLUGIN_AUTH":          0x80000,  # ??? standard
    "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA": 0x200000,
}

CTYPE = {
    'COM_SLEEP': 0x00,
    'COM_QUIT': 0x01,
    'COM_INIT_DB': 0x02,
    'COM_QUERY': 0x03,
    'COM_FIELD_LIST': 0x04,
    'COM_CREATE_DB': 0x05,
    'COM_DROP_DB': 0x06,
    'COM_REFRESH': 0x07,
    'COM_SHUTDOWN': 0x08,
    'COM_STATISTICS': 0x09,
    'COM_PROCESS_INFO': 0x0a,
    'COM_CONNECT': 0x0b,
    'COM_PROCESS_KILL': 0x0c,
    'COM_DEBUG': 0x0d,
    'COM_PING': 0x0e,
    'COM_TIME': 0x0f,
    'COM_DELAYED_INSERT': 0x10,
    'COM_CHANGE_USER': 0x11,
    'COM_BINLOG_DUMP': 0x12,
    'COM_TABLE_DUMP': 0x13,
    'COM_CONNECT_OUT': 0x14,
    'COM_REGISTER_SLAVE': 0x15,
    'COM_STMT_PREPARE': 0x16,
    'COM_STMT_EXECUTE': 0x17,
    'COM_STMT_SEND_LONG_DATA': 0x18,
    'COM_STMT_CLOSE': 0x19,
    'COM_STMT_RESET': 0x1a,
    'COM_SET_OPTION': 0x1b,
    'COM_STMT_FETCH': 0x1c,
    'COM_DAEMON': 0x1d,
    'COM_BINLOG_DUMP_GTID': 0x1e,
    'COM_RESET_CONNECTION': 0x1f,
}


class MysqlClient():

    """ MysqlClient performs a basic login handshake with an mysql server. """

    def __init__(self, ip, port=3306, timeout=3, client_capabilities=0x05a6, tls=False):

        """ MysqlClient ...

            input:
                ip                      Server ip
                port                    Mysql port (default 3306)
                timeout                 Socket timeout (default 3)
                client_capabilities     Capability flags to determin the bahaviour of the client (default 0x05a6)
        """

        self.sock = None
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None
        # TODO
        self.tls = tls

        self.max_packet_size = 0x00000001
        self.protocol_version = 0x0a
        self.server_version = ''
        self.salt = ''
        self.server_capabilities = 0
        self.character_set = 0
        self.status_flags = 0
        self.auth_plugin_name = ''

        self.client_capabilities = client_capabilities
        #if self.tls:
        #    self.client_capabilities = \
        #        self.client_capabilities | Capability['CLIENT_SSL']
        self.connect_attributes = {}

    def close(self):
        if self.sock:
            self.sock.close()

    def login(self, user, passw, database=''):

        """ Try to authenticate with user/passw at the mysql server

            input:
                user        Username
                passw       User password
                database    Name of the database to connect to (optional)

            output:
                True if the login was successful, Fale otherwise
        """

        r = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip, int(self.port)))
        pkt = self._get_packet()
        self._unpack_HandshakeV10(pkt)
        logger.info('Recieved server handshake request')
        #self.client_capabilities = self.client_capabilities & self.server_capabilities
        if self.tls:
            #if not self.client_capabilities & Capability['CLIENT_SSL']:
            #    raise Exception('Server does not support SSL connections')
            #else:
            old_cap = self.client_capabilities
            self.client_capabilities = 0x05ae
            pkt = self._pack_SSLRequest()
            pkt = self._wrap_header(pkt)
            self.sock.sendall(pkt)
            self.sock = ssl.wrap_socket(self.sock)
            logger.info('SSL handshake successfull')
            self.client_capabilities = old_cap
        pkt = self._pack_HandshakeResponse41(user, passw, database)
        pkt = self._wrap_header(pkt)
        self.sock.sendall(pkt)
        logger.info('HandshakeResponse41 sent')
        r, pkt = self._check_server_response()
        return (ord(r) == 0x00)

    def send_cmd(self, cmd):
        """ pack sql cmd into a packet and send it to the server

            input:
                cmd     sql command string

            output:
                response code   0x00: E

        """
        pkt = self._pack_ComQuery(cmd)
        self.sock.sendall(pkt)
        r, pkt = self._check_server_response()
        r = ord(r)
        server_response = []
        if r != 0x00 and r != 0xff:
            server_response = self._unpack_server_response(pkt, r)
        return (r, server_response)

    def _unpack(self, fmt, pkt, postpro=None):

        """ This function unpacks part of the packet as specified by the format string,
            the remaining packet data is returned.
            Null terminated strings are specified by the format string '.s', the point
            will be replaced by an appropiate integer

            input:
                fmt         Format string
                pkt         Raw packet data
                postpro     Postprocessing function to call on the unpacked values (optional)

            output:
                Unpacked tuple, if multiple values are specified in the format string,
                otherwise the unpacked data element
        """

        varsize = fmt.find('.')
        if varsize >= 0:
            strlen = pkt.find('\0')
            if strlen < 0:
                strlen = len(pkt)
            else:
                strlen += 1
            fmtl, fmtr = fmt.split('.')
            fmt = '%s%d%s' % (fmtl, strlen, fmtr)
        fmt_size = struct.calcsize(fmt)
        data = struct.unpack(fmt, pkt[:fmt_size])
        if len(data) == 1:
            data = data[0]
        if postpro:
            data = postpro(data)
        pkt = pkt[fmt_size:]
        return data, pkt

    def _wrap_header(self, pkt):
        l = len(pkt)
        header = struct.pack('!HH', l << 8, 1)
        return header + pkt

    def _make_password_hash(self, passw):

        """ hash password string with SHA1 using a 20bit salt """

        # SHA1( password ) XOR SHA1( "20-bytes random data from server"
        # <concat> SHA1( SHA1( password ) ) )

        hash0 = hashlib.sha1(passw).digest()
        hash1 = hashlib.sha1(hash0).digest()
        hash2 = hashlib.sha1(self.salt + hash1).digest()
        # XOR
        passw_enc = [ord(a) ^ ord(b) for a, b in zip(hash0, hash2)]
        return passw_enc

    def _lenenc(self, dsize):

        """ mysql lenencoded integers """

        if dsize < 256:
            return ('!1b', '')
        if dsize < 65536:
            return ('!H', '\xfc')
        if dsize < 16777216:
            return ('!3b', '\xfd')
        else:
            return ('!I', '\xfe')

    def _pack_ComQuery(self, sql_query):
        pkt = ''
        l = len(sql_query) + 1
        pkt += struct.pack('!HH', l << 8, 0)
        pkt += struct.pack('c', chr(CTYPE['COM_QUERY']))
        pkt += struct.pack('%ds' % (l - 1), sql_query)
        return pkt

    def _pack_SSLRequest(self):
        """ pack a SSL Request packet"""
        # TODO
        pkt = ''
        pkt += struct.pack('!H', self.client_capabilities)
        pkt += struct.pack('!H', 0x0f00)
        pkt += struct.pack('!I', self.max_packet_size)  # TODO: evaluate this value
        pkt += struct.pack('!b', 0x21)  # charset
        pkt += '\0' * 23
        return pkt

    def _pack_HandshakeResponse41(self, user, passw, database=''):

        """ pack a handshake response packet

            input:
                user        Username
                passw       User password
                database    Name of the database to connect to (optional)

            output:
                Raw packet data to be send to the mysql server
        """

        pkt = ''
        # client capability flags
        pkt += struct.pack('!H', self.client_capabilities)
        # client capability flags ext.
        pkt += struct.pack('H', 0x000f)
        # max packet size
        pkt += struct.pack('!I', self.max_packet_size)  # TODO: evaluate this value
        # charset ... whatever
        pkt += struct.pack('!b', 0x21)  # TODO
        # reserved 23 all [0]
        pkt += struct.pack('!23s', '\0' * 23)
        # username NUL terminates
        user = str(user)
        usize = len(user)
        pkt += struct.pack('!%dsc' % usize, user, '\0')  # TODO

        # make salted password hash (make sure that you actually read the salt
        # already)
        passw_enc = self._make_password_hash(passw)
        psize = len(passw_enc)  # should always be 20
        if self.server_capabilities & Capability['CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA']:
            fmt, prefix = self._lenenc(psize)
            pkt += prefix + struct.pack(fmt, passw_enc)
        elif self.server_capabilities & Capability['CLIENT_SECURE_CONNECTION']:
            pkt += struct.pack('c', chr(psize))
            for c in passw_enc:
                pkt += struct.pack('c', chr(c))
        else:  # NUL terminated
            for c in passw_enc:
                pkt += struct.pack('c', chr(c))
            pkt += struct.pack('c', '\0')

        # TODO
        #if database:  # and self.client_capabilities & Capability['CLIENT_CONNECT_WITH_DB']:
        #    database = str(database)
        #    l = len(database)
        #    pkt += struct.pack('!%dsc'%l, database, '\0')
        if self.auth_plugin_name:  # and self.client_capabilities & Capability['CLIENT_PLUGIN_AUTH']:
            l = len(self.auth_plugin_name)
            pkt += struct.pack('!%dsc' % l, self.auth_plugin_name, '\0')
        if self.connect_attributes and self.client_capabilities & Capability['CLIENT_CONNECT_ATTRS']:
            raise Exception('Not yet implemented')

        return pkt

    def _unpack_HandshakeV10(self, pkt):

        """ read and process initial handshake packet from server

            input:
                pkt     Raw packet data
        """

        protocol_version, pkt = self._unpack('!c', pkt, ord)
        if protocol_version != self.protocol_version:
            raise Exception('Protocol version mismatch %x' % protocol_version)
        self.server_version, pkt = self._unpack('!.s', pkt)
        self.connection_id, pkt = self._unpack('!I', pkt)
        self.salt, pkt = self._unpack('8s', pkt)
        # Throw away filler byte
        pkt = pkt[1:]
        self.server_capabilities, pkt = self._unpack('H', pkt)
        # there might be more to read ... maybe
        if pkt:
            self.character_set, pkt = self._unpack('!c', pkt, ord)
            self.status_flags, pkt = self._unpack('!H', pkt)
            # check server capabilities (part 2)
            capabilities_p2, pkt = self._unpack('!H', pkt)
            self.server_capabilities = (capabilities_p2 << 16) + self.server_capabilities
            # only mysql versions above 4.1 supported
            if not (self.server_capabilities & Capability['CLIENT_PROTOCOL_41']):
                raise Exception('Mysql version not supported')
            salt_p2_len, pkt = self._unpack('!c', pkt, lambda x: int(binascii.hexlify(x)))
            # reserved 10
            pkt = pkt[10:]
            if self.server_capabilities & Capability['CLIENT_SECURE_CONNECTION']:
                salt_p2_len = max(13, salt_p2_len)
                salt_p2, pkt = self._unpack('.s', pkt)
                # TODO why am I doing this?
                self.salt += salt_p2[:-1]
                if len(self.salt) != 20:
                    raise Exception('Salt too long')
            if pkt or self.server_capabilities & Capability['CLIENT_PLUGIN_AUTH']:
                self.auth_plugin_name, pkt = self._unpack('!.s', pkt)

    def _unpack_EOFMarker(self, pkt):
        if not pkt:
            pkt = self._get_packet()
        return ord(pkt[:1]), pkt

    def _unpack_ColumnDefinition41(self, pkt):
        if not pkt:
            pkt = self._get_packet()
        l, pkt = self._unpack('c', pkt, ord)
        value, pkt = self._unpack('%ds' % l, pkt)
        l, pkt = self._unpack('c', pkt, ord)
        value, pkt = self._unpack('%ds' % l, pkt)
        l, pkt = self._unpack('c', pkt, ord)
        value, pkt = self._unpack('%ds' % l, pkt)
        l, pkt = self._unpack('c', pkt, ord)
        value, pkt = self._unpack('%ds' % l, pkt)
        l, pkt = self._unpack('c', pkt, ord)
        value, pkt = self._unpack('%ds' % l, pkt)
        l, pkt = self._unpack('c', pkt, ord)
        value, pkt = self._unpack('%ds' % l, pkt)
        name = str(value)

        next_l, pkt = self._unpack('c', pkt)

        charset, pkt = self._unpack('H', pkt)
        next_l, pkt = self._unpack('I', pkt)

        return name

    def _unpack_server_response(self, pkt, field_count):
        columns = []
        columns.append([])
        for _ in range(field_count):
            columns[0].append(self._unpack_ColumnDefinition41(pkt))
        eof, pkt = self._unpack_EOFMarker(pkt)
        while True:
            pkt = self._get_packet()
            status = ord(pkt[:1])
            if status == eof:
                break
            fields = []
            while pkt:
                l, pkt = self._unpack('c', pkt, ord)
                data, pkt = self._unpack('%ds' % l, pkt)
                fields.append(data)
            columns.append(fields)
        return columns

    def _check_server_response(self, pkt=''):
        if not pkt:
            pkt = self._get_packet()
        #print binascii.hexlify(pkt)
        status = pkt[:1]
        logger.info('Response status %x' % ord(status))
        pkt = pkt[1:]
        logger.info('Response %s' % binascii.hexlify(pkt))
        # 00 -> ok
        # ff -> ERR
        # fb -> get more data ??
        # lenenc int -> data
        # http://dev.mysql.com/doc/internals/en/com-query-response.html
        return (status, pkt)

    def _check_login_response(self):
        pkt = self._get_packet()
        server_status = struct.unpack('!H', pkt[2:4])[0]
        if server_status == 2:
            return True
        return False

    def _get_packet(self):
        """ read the packet size x (first 3 bytes) and return x bytes of the remaining pkt """
        # actually the first 4 bytes contain the packet length (1:3) and the
        # packet number (4), we read the packet number, but ignore it.
        # (Maybe TODO)
        psize = ''
        while True:
            psize += self.sock.recv(1)
            if len(psize) == 4:
                break
        psize = psize[:3] + '\0'  # remove packet number
        psize = int(struct.unpack('I', psize)[0])
        # read actual pkt
        pkt = ''
        while True:
            pkt += self.sock.recv(1)
            if len(pkt) == psize:
                break
        return pkt


# sample session:
# --------------
#
# 00
# Login successful
# > show databases;
# SCHEMA_NAME
# ------------
# information_schema
# aaa
# mysql
# performance_schema
# > use aaa;
# OK
# > show tables;
# TABLE_NAME
# -----------
# a
# b
# c
# > select * from a
# id      data
# ------------
# 0       abc
# 1       def
#
if __name__ == '__main__':
    mc = MysqlClient('127.0.0.1', tls=True)
    #mc = MysqlClient('127.0.0.1', client_capabilities=0x05ae, tls=True)
    r = mc.login('root', 'toor')
    if r:
        print 'Login successful'
        print 'To load a stored procedure from a file: > load_sp \'/path/to/file\''
    else:
        print 'Login unsuccessful, terminating'
        print str(r)
        sys.exit(1)
    while True:
        #sql_cmd = sys.stdin.readline()
        sql_cmd = raw_input('> ')
        # load stored procedure
        parts = sql_cmd.split(' ')
        if parts[0] == 'load_sp':
            try:
                sp = open(parts[1], 'r')
                proc = sp.read()
                sql_cmd = proc.rstrip()
                print sql_cmd
            except Exception, e:
                print e
        r, response = mc.send_cmd(sql_cmd)
        if r == 0x00:
            print 'OK'
        elif r == 0xff:
            print 'ERR'
        else:
            if not response:
                continue
            header = ''
            for x in response[0]:
                header += x + '\t'
            print header
            response = response[1:]
            if not response:
                continue
            print '-' * (len(header) + len(response[0]) * 4 - 4)
            for data in response:
                print '\t'.join(data)
#
#    print 'Trying: bla/blubb'
#    if mc.login('bla', 'blubb'):
#        print 'Login successful'
#    else:
#        print 'Login failed'
#
#    print 'Trying: root/toor'
#    if mc.login('root', 'toor'):
#        print 'Login successful'
#    else:
#        print 'Login failed'
