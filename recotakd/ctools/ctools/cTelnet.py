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
import binascii
import socket
import ssl
import re
import multiprocessing as mp
import Queue
import select
import time
import logging

__version__ = '0.0'
__author__ = 'feli'
__plgname__ = 'telnet_bruteforce'

# logging
#LOG = "/tmp/" + __plgname__ + ".log"
#FORMAT = '%(asctime)s - %(name)s - ' + \
#    '%(levelname)s - %(threadName)s - %(message)s'
#logging.basicConfig(filename=LOG,
#                    filemode="w",
#                    format=FORMAT,
#                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.NullHandler())


CRLF = '\r\n'
SELECT_TIMEOUT = 0.5

# from telnetlib.py
# Telnet protocol characters (don't change)
IAC  = chr(255)  # "Interpret As Command"
DONT = chr(254)
DO   = chr(253)
WONT = chr(252)
WILL = chr(251)
theNULL = chr(0)

SE  = chr(240)  # Subnegotiation End
NOP = chr(241)  # No Operation
DM  = chr(242)  # Data Mark
BRK = chr(243)  # Break
IP  = chr(244)  # Interrupt process
AO  = chr(245)  # Abort output
AYT = chr(246)  # Are You There
EC  = chr(247)  # Erase Character
EL  = chr(248)  # Erase Line
GA  = chr(249)  # Go Ahead
SB  = chr(250)  # Subnegotiation Begin


# Telnet protocol options code (don't change)
# These ones all come from arpa/telnet.h
BINARY = chr(0)  # 8-bit data path
ECHO = chr(1)  # echo
RCP = chr(2)  # prepare to reconnect
SGA = chr(3)  # suppress go ahead
NAMS = chr(4)  # approximate message size
STATUS = chr(5)  # give status
TM = chr(6)  # timing mark
RCTE = chr(7)  # remote controlled transmission and echo
NAOL = chr(8)  # negotiate about output line width
NAOP = chr(9)  # negotiate about output page size
NAOCRD = chr(10)  # negotiate about CR disposition
NAOHTS = chr(11)  # negotiate about horizontal tabstops
NAOHTD = chr(12)  # negotiate about horizontal tab disposition
NAOFFD = chr(13)  # negotiate about formfeed disposition
NAOVTS = chr(14)  # negotiate about vertical tab stops
NAOVTD = chr(15)  # negotiate about vertical tab disposition
NAOLFD = chr(16)  # negotiate about output LF disposition
XASCII = chr(17)  # extended ascii character set
LOGOUT = chr(18)  # force logout
BM = chr(19)  # byte macro
DET = chr(20)  # data entry terminal
SUPDUP = chr(21)  # supdup protocol
SUPDUPOUTPUT = chr(22)  # supdup output
SNDLOC = chr(23)  # send location
TTYPE = chr(24)  # terminal type
EOR = chr(25)  # end or record
TUID = chr(26)  # TACACS user identification
OUTMRK = chr(27)  # output marking
TTYLOC = chr(28)  # terminal location number
VT3270REGIME = chr(29)  # 3270 regime
X3PAD = chr(30)  # X.3 PAD
NAWS = chr(31)  # window size
TSPEED = chr(32)  # terminal speed
LFLOW = chr(33)  # remote flow control
LINEMODE = chr(34)  # Linemode option
XDISPLOC = chr(35)  # X Display Location
OLD_ENVIRON = chr(36)  # Old - Environment variables
AUTHENTICATION = chr(37)  # Authenticate
ENCRYPT = chr(38)  # Encryption option
NEW_ENVIRON = chr(39)  # New - Environment variables
# the following ones come from
# http://www.iana.org/assignments/telnet-options
# Unfortunately, that document does not assign identifiers
# to all of them, so we are making them up
TN3270E = chr(40)  # TN3270E
XAUTH = chr(41)  # XAUTH
CHARSET = chr(42)  # CHARSET
RSP = chr(43)  # Telnet Remote Serial Port
COM_PORT_OPTION = chr(44)  # Com Port Control Option
SUPPRESS_LOCAL_ECHO = chr(45)  # Telnet Suppress Local Echo
TLS = chr(46)  # Telnet Start TLS
KERMIT = chr(47)  # KERMIT
SEND_URL = chr(48)  # SEND-URL
FORWARD_X = chr(49)  # FORWARD_X
PRAGMA_LOGON = chr(138)  # TELOPT PRAGMA LOGON
SSPI_LOGON = chr(139)  # TELOPT SSPI LOGON
PRAGMA_HEARTBEAT = chr(140)  # TELOPT PRAGMA HEARTBEAT
EXOPL = chr(255)  # Extended-Options-List
NOOPT = chr(0)


class Listener(mp.Process):
    def __init__(self, ip, port, conn_s, conn_r, a, b, stopEvent, use_ssl=False, timeout=3, verbose=False):

        """
        Handles communication with telnet server.
        All commands are answered with WONT.
        Data is passed to the client via pipe.
        Data from the client is read through a pipe and forwarded to the server.
        """

        logger.info('Init Listener for %s:%d', ip, port)
        super(Listener, self).__init__()
        #a.close()
        #b.close()
        self.a = a
        self.b = b

        self.ip = ip
        self.port = port
        self.sock = None
        try:
            # connect to server
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((ip, int(port)))
            if use_ssl:
                self.sock = ssl.wrap_socket(self.sock)
            self.sock.setblocking(0)
        except Exception, e:
            logger.warning('Can\'t connect to %s:%d -> %s' % (ip, int(port), str(e)))
            if self.sock:
                self.sock.close()
            self.a.close()
            self.b.close()
            self.conn_r.close()
            self.conn_s.close()
            raise

        # communication with client
        self.conn_r = conn_r
        self.conn_s = conn_s
        self.verbose = verbose
        self.stopEvent = stopEvent

    def join(self):
        super(Listener, self).join()
        self.sock.close()
        self.a.close()
        self.b.close()
        self.conn_r.close()
        self.conn_s.close()
        self.stopEvent.set()

    def run(self):
        logger.info('Started Listener for %s:%d', self.ip, self.port)
        data = ''
        inp = [self.sock, self.conn_r]
        try:
            while not self.stopEvent.is_set():
                #self.conn_s.send('')
                r, w, e = select.select(inp, [], [], SELECT_TIMEOUT)
                for fd in r:
                    if fd == self.sock:
                        buf = ''
                        try:
                            buf = self.sock.recv(64)
                        except Exception, e:
                            logger.warning('Error while recving from %s:%d -> %s', self.ip, self.port, e)
                        data += buf
                        remain = self.process(data)
                        # remember remaining data for next round
                        # there might be a problem if the server never sends
                        # anything again ever
                        # but assuming that we only have remaining data if it was
                        # incomlete to begin with, the server will probalbly send the rest at
                        # some point
                        data = remain
                    elif fd == self.conn_r:
                        # get data from client in order to forward it to the server
                        buf = ''
                        try:
                            buf = self.conn_r.recv()
                        except EOFError:
                            # wtf, this should not happen, since select just told
                            # us that there is sth to read
                            continue
                        if self.verbose:
                            print 'to server: \'' + buf + '\''
                        self.sock.send(buf)
        except EOFError as e:
            pass
        logger.info('Stopped Listener for %s:%d', self.ip, self.port)

    def process(self, buf):

        """
        Process incoming data.
        Commands are immediatly answered with WONT do that.
        Data is send to the client via pipe.
        """

        # see what we have
        while len(buf) > 2:
            mark = buf[0]
            if mark == IAC:  # interpret as command
                # we need at least 3 bytes for a cmd
                # if we don't have enough, return the remainder and wait for
                # more
                if len(buf) >= 3:
                    cmd = buf[1]
                    what = buf[2]
                    # throw away the processed bytes
                    buf = buf[3:]
                    # just answer no ... we don't care
                    if cmd == DO or cmd == WILL:
                        if self.verbose:
                            print 'WONT %x' % ord(what)
                        self.sock.send(IAC + WONT + what)
                    else:
                        raise Exception('Unexpected command: %s' % binascii.hexlify(buf))
            else:
                # find next cmd byte, if there is one
                idx = buf.find(IAC)
                # return the data via pipe
                l = (idx > 0) and idx or (len(buf) + 1)
                if self.verbose:
                    print 'to client: \'' + buf[:l] + '\''
                try:
                    self.conn_s.send(buf[:l])
                except IOError, e:
                    logger.warning('remote end closed -> ' + repr(e))
                buf = buf[l:]
        return buf


class Telnet():
    def __init__(self, ip, port=23, timeout=2, use_ssl=False, verbose=False, out=''):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.wonts = []
        self.donts = []
        self.data = ''
        self.use_ssl = use_ssl
        self.cmd_q = Queue.Queue()
        self.verbose = verbose
        self.fd_out = None
        if out:
            try:
                self.fd_out = open(out, 'w')
                self.fd_out.write('communication to/from %s:%d\n' % (ip, int(port)))
                self.fd_out.flush()
            except IOError as e:
                logger.warning('Error opening %s -> %s', out, e)

    def connect(self):
        self.parent_conn_r, self.child_conn_s = mp.Pipe(False)
        self.child_conn_r, self.parent_conn_s  = mp.Pipe(False)
        self.stopEvent = mp.Event()
        self.listener = Listener(
            self.ip,
            self.port,
            self.child_conn_s,
            self.child_conn_r,
            self.parent_conn_s,
            self.parent_conn_r,
            self.stopEvent,
            #use_ssl=use_ssl,
            #timeout=self.timeout,
            #verbose=self.verbose,
        )
        self.listener.start()

    def expect(self, patterns, timeout):
        # just read all we have until now
        # if it's not enough we have a problem here ...
        endtime = time.time() + timeout
        data = ''
        while True:
            rtime = endtime - time.time()
            if rtime < 0:
                break
            try:
                buf = self.parent_conn_r.recv()
                if self.fd_out:
                    self.fd_out.write('----->\n')
                    self.fd_out.write(buf)
                    self.fd_out.write('\n')
                    self.fd_out.flush()
                data += buf
            except EOFError:
                logger.error('Remote end closed (%s:%d)', self.ip, self.port)
                break
            if data:
                for p in patterns:
                    m = p.search(data)
                    if m:
                        return m
        logger.info('expectations not met on %s:%d', self.ip, self.port)

    def write(self, data):
        if self.fd_out:
            self.fd_out.write('<-----\n')
            self.fd_out.write(data)
            self.fd_out.write('\n')
            self.fd_out.flush()
        self.parent_conn_s.send(data)

    def close(self):
        logger.info('joining Listener on %s:%d', self.ip, self.port)
        self.child_conn_s.close()
        self.child_conn_r.close()
        if self.fd_out:
            self.fd_out.close()
            self.fd_out = None
        self.stopEvent.set()
        self.listener.join()

if __name__ == '__main__':
    import sys
    ip, user, passw = sys.argv[1:4]
    telnet = Telnet(ip, port=23, timeout=1)
    telnet.connect()
    telnet.expect((re.compile('login', re.IGNORECASE),
                   re.compile('username', re.IGNORECASE)))
    telnet.write(user + CRLF)
    m = telnet.expect((re.compile('password', re.IGNORECASE), ))
    print 'matched: ' + m.group()
    telnet.write(passw + CRLF)
    m = telnet.expect((re.compile('last login', re.IGNORECASE),
                       re.compile('incorrect', re.IGNORECASE)))
    print 'matched: ' + m.group()
    if m:
        print 'matched: ' + m.group()
    telnet.close()
