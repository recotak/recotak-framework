"""
ccd protocol implementation which is used for communication between ccd server
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
and ccd client.

CHANGELOG:
v0.492
- base64 encoding of serialised payload

v0.491
- added MTH_TERMINATE
- add OP_PERMISSION_DENIED

v0.490
- added OP_USEGROUP

v0.480
- added OP_NEWPROXY
- added OP_DELPROXY
- added OP_SHOWPROXY

v0.470
- added OP_DOWNLOAD

v0.460
- added OP_HOMEDIR
- added OP_REPORT

v0.450
- added OP_PLUGIN and MTH_INPUT/OUTPUT to handle plugin io forwarding

v0.441
- empty messages, occuring if remote socket closes, raise InvalidPacketError

v0.440
- add plugin to workgroup
- del plugin from workgroup

v0.431
- minor fix due to payload length

v0.43
- commands for user, project and workgroup management
- reassigning some byte of general and plugin commands

v0.42
- 4Byte length

v0.41
- PLN now 2Bytes instead of 4B
- new operations: OP_REGISTER, OP_UNREGISTER, OP_GETSTATE

v0.40
- replaced pickle with json

 ----- ----- ---------------- ---------------- ------- ---------------- ------- -------  ----------- ------------...----------
|  1B |  1B |      16B       |      16B       |  2B   |      16B       |   8B   |  2B   |    4B     |           nB            |
 ----- ----- ---------------- ---------------- ------- ---------------- ------- -------  ----------- ------------...----------
  V     OP        SID               RID          CAT        PID            GID      MTH     PLN              PLD

V:      Version
OP:     Operation
SID:    Session ID
RID:    Request ID
CAT:    Category ID
PID:    Plugin ID
GID:    Group ID
MTH:    Method
PLN:    Payload length
PLD:    Payload

"""

import logging
import socket
import struct
import base64
import errno
import json

__version__ = 0.492

logger = logging.getLogger("ccd.%s" % __name__)

PROTOCOL_VERSION = 1

# 1 Byte Operation
# general commands
OP_NOP = 0x00
OP_HELP = 0x01
OP_STATUS = 0x02
OP_LOGIN = 0x03
OP_LOGOUT = 0x04
OP_GETRID = 0x05
OP_GETPLG = 0x06
OP_GETCAT = 0x07
OP_GETROOTCAT = 0x8

# plugin operations
OP_EXEC = 0x10
OP_KILL = 0x11
OP_UPLOAD = 0x12
OP_GETLOG = 0x13
OP_RELOAD = 0x14
OP_GETSTATE = 0x15
OP_REGISTER = 0x16
OP_UNREGISTER = 0x17
OP_PLUGIN = 0x18
OP_DOWNLOAD = 0x19

# proxy chains and connection groups
OP_SHOWPCHAIN = 0x20
OP_FLUSHPCHAIN = 0x21
OP_DELPCHAIN = 0x22
OP_NEWPCHAIN = 0x23
OP_NEWGROUP = 0x24
OP_SHOWGROUP = 0x25
OP_FLUSHGROUP = 0x26
OP_DELGROUP = 0x27
OP_USEGROUP = 0x28

# user management
OP_NEWUSER = 0x30
OP_DELUSER = 0x31
OP_UPDATEUSER = 0x32
OP_SHOWUSER = 0x33
OP_UPDATEUSERPWD = 0x34
OP_GETHOME = 0x35

# workgroup management
OP_NEWWGROUP = 0x40
OP_DELWGROUP = 0x41
OP_UPDATEWGROUP = 0x42
OP_ADDWGROUPMEMBER = 0x43
OP_DELWGROUPMEMBER = 0x44
OP_SHOWWGROUP = 0x45
OP_ADDWGROUPPLG = 0x46
OP_DELWGROUPPLG = 0x47

# project management
OP_NEWPROJ = 0x50
OP_DELPROJ = 0x51
OP_UPDATEPROJ = 0x52
OP_ADDPROJMEMBER = 0x53
OP_DELPROJMEMBER = 0x54
OP_SHOWPROJ = 0x55
OP_SETPROJ = 0x56
OP_ADDPROJPLG = 0x57
OP_DELPROJPLG = 0x58

# report
OP_REPORT = 0x60

# proxy management
OP_NEWPROXY = 0x70
OP_DELPROXY = 0x71
OP_SHOWPROXY = 0x72

# server responses
OP_SUCCESS = 0xf0
OP_FAILURE = 0xf1
OP_MISSING_FILE = 0xf2
OP_PROTOCOL_ERROR = 0xf3
OP_WRONGID = 0xf4
# all the current ccdErrors
# caused by invalid client input
OP_INVALID_INPUT = 0xf6
OP_PERMISSION_DENIED = 0xf4
OP_NOT_FOUND = 0xf5
OP_ALREADY_EXISTS = 0xf7

# 2 Byte Method
MTH_NOP = 0x0000
MTH_HELP = 0x0001
MTH_EXEC = 0x0002
MTH_FORCE = 0x0003
MTH_INTERACTIVE = 0x0004
MTH_INPUT = 0x0005
MTH_OUTPUT = 0x0006
MTH_VIEW = 0x0007
MTH_INFO = 0x0008
MTH_SAVE = 0x0009
MTH_TERMINATE = 0x0010

LEN_VER = 1
LEN_OP = 1
LEN_SID = LEN_RID = LEN_PLG = 16
LEN_CAT = 2
LEN_GID = 8
LEN_MTH = 2
LEN_PLN = 4

LEN_HEADER = LEN_VER +\
    LEN_OP +\
    LEN_SID +\
    LEN_RID +\
    LEN_CAT +\
    LEN_PLG +\
    LEN_GID +\
    LEN_MTH +\
    LEN_PLN

TIMEOUT = 10.0

def recv(sock):
    """
    Function receives data on socket, unpacks it and unpickles
    the payload. It returns a tuple.

    input:
        sock    socket to read from

    output:
        return a tuple consisting of:
            op  ccd protocol opertion
            sid session id
            rid request id
            cat category id
            plg plugin id
            gid connection group id
            mth method to perform
            pld payload


    """
    logger.debug("receiving data.. from %s on %s",
                 str(sock.getpeername()),
                 str(sock)
                 )

    try:
        # read version
        ver_bin = sock.recv(LEN_VER)
        if not ver_bin:
            raise EmptyException("Received empty packet!")

        ver = int(struct.unpack(">B", ver_bin)[0])
        if (int(ver) != PROTOCOL_VERSION):
            raise InvalidPacketError("fatal: Invalid protocol version!")
        logger.debug("ver:%d", ver)

        # get rest of header
        data = sock.recv(LEN_HEADER - LEN_VER)
        offset = 0
        op = struct.unpack(">B", data[offset])[0]
        offset += LEN_OP
        logger.debug("op:%s", hex(op))

        sid = struct.unpack(">QQ", data[offset:offset + LEN_SID])
        sid = (sid[0] << 64) | sid[1]
        sid = ("%x" % sid).zfill(32)
        offset += LEN_SID
        logger.debug("sid:%s", sid)

        rid = struct.unpack(">QQ", data[offset:offset + LEN_RID])
        rid = (rid[0] << 64) | rid[1]
        rid = ("%x" % rid).zfill(32)
        offset += LEN_RID
        logger.debug("rid:%s", rid)

        cat = struct.unpack(">BB", data[offset:offset + LEN_CAT])
        cat = (cat[0] << 16) | cat[1]
        offset += LEN_CAT
        logger.debug("cat:%s", cat)

        plg = struct.unpack(">QQ", data[offset:offset + LEN_PLG])
        plg = (plg[0] << 64) | plg[1]
        plg = ("%x" % plg).zfill(32)
        offset += LEN_PLG
        logger.debug("plg:%s", plg)

        gid = struct.unpack(">Q", data[offset:offset + LEN_GID])
        gid = ("%x" % gid).zfill(8)
        offset += LEN_GID
        logger.debug("gid:%s", gid)

        mth = struct.unpack(">BB", data[offset:offset + LEN_MTH])
        mth = (mth[0] << 16) | mth[1]
        offset += LEN_MTH
        logger.debug("mth:%s", mth)

        pln = struct.unpack(">L", data[offset:offset + LEN_PLN])[0]
        pln = int(pln)
        logger.debug("pln: %d", pln)
        payload_data = ""

        if pln > 0:
            while len(payload_data) < pln:
                logger.debug("waiting for payload (%d B)", pln)
                payload_data += sock.recv(pln)

            pld_base64 = struct.unpack("%ds" % pln, payload_data)[0]
            pld_serialised = base64.decodestring(pld_base64)
            pld = json.loads(pld_serialised)

        else:
            pld = ""

        logger.debug("received:%d", len(payload_data) + LEN_HEADER)

    # if parsing fails, the packet is malformed and we inform the caller
    except struct.error as err:
        logger.error("Received malformed packet: '%s'", err)
        logger.exception(err)
        raise InvalidPacketError("fatal: Unpacking failed!")

    # socket error
    except socket.error as err:
        no = err.args[0]
        if no == errno.EAGAIN or no == errno.EWOULDBLOCK:
            logger.warning("No data available!")
        raise err

    # invalid packet occurs e.g. if protocol version is invalid
    except InvalidPacketError as ipacketerr:
        raise ipacketerr

    # remaining errors
    except Exception as err:
        logger.warning("Error while receiving packet:'%s'", err)
        raise err

    logger.debug("pld:%s", repr(pld))
    return (op, sid, rid, cat, plg, gid, mth, pld)

def send(sock, request_t):
    """
    Function get request tuple and builds ccd protocol conform packet
    to rend it over socket. The payload will be pickled automatically.

    input:
        sock        socket to send from
        request_t   tuple containing the full request:
                        op  ccd protocol opertion
                        sid session id
                        rid request id
                        cat category id
                        plg plugin id
                        gid connection group id
                        mth method to perform
                        pld payload


    output:
        sent        return sent bytes

    """
    logger.debug("sending data.. on %s to %s over %s",
                 str(sock.getsockname()),
                 str(sock.getpeername()),
                 str(sock)
                 )
    max_int64 = 0xFFFFFFFFFFFFFFFF
    max_int16 = 0xFFFF
    packet = ""
    sent = 0

    try:
        op, sid, rid, cat, plg, gid, mth, pld = request_t

        packet += struct.pack(">B", PROTOCOL_VERSION)
        logger.debug("ver:%d", PROTOCOL_VERSION)

        packet += struct.pack(">B", op)
        logger.debug("op:%s", hex(op))

        sid_int = long(sid, 16)
        packet += struct.pack(">QQ", (sid_int >> 64) & max_int64, sid_int & max_int64)
        logger.debug("sid:%s", sid)

        rid_int = long(rid, 16)
        packet += struct.pack(">QQ", (rid_int >> 64) & max_int64, rid_int & max_int64)
        logger.debug("rid:%s", rid)

        packet += struct.pack(">BB", (cat >> 16) & max_int16, cat & max_int16)
        logger.debug("cat:%s", cat)

        plg_int = long(plg, 16)
        packet += struct.pack(">QQ", (plg_int >> 64) & max_int64, plg_int & max_int64)
        logger.debug("plg:%s", plg)

        gid_int = long(gid, 16)
        packet += struct.pack(">Q", gid_int)
        logger.debug("gid:%s", gid)

        packet += struct.pack(">BB", (mth >> 16) & max_int16, mth & max_int16)
        logger.debug("mth:%s", mth)

        if pld:
            pld_serialised = json.dumps(pld, separators=(",", ":"))
            pld_base64 = base64.encodestring(pld_serialised)
            pln = len(pld_base64)
        else:
            pld_base64 = ""
            pln = 0

        packet += struct.pack(">L", pln)
        logger.debug("pln:%d", pln)

        packet += pld_base64
        logger.debug("pld:%s", repr(pld_base64))

        sent = sock.send(packet)

        if (sent <= 0):
            logger.warning("warning: Sent %d bytes!", sent)

    except Exception as err:
        logger.warning("Error while sending packet:'%s'", err)
        logger.exception(err)
        raise

    logger.debug("sent %d bytes", sent)
    return sent

def checkRsp(request, response):
    """
    Function validates whether sid, rid, cat, plg and method
    match.

    input:
        request     request tuple that triggered response
        response    response to check against request

    output:
        boolean     indicates whether the response is valid against the request

    """
    op, sid, rid, cat, plg, gid, mth, pld = request
    r_op, r_sid, r_rid, r_cat, r_plg, r_gid, r_mth, r_pld = response
    result = True

    # version is already checked by recvPacket
    # operation is checked by caller
    # check the rest
    if r_sid != sid.zfill(32):
        result = False

    elif r_rid != rid.zfill(32):
        result = False

    elif r_cat != cat:
        result = False

    elif r_plg != plg.zfill(32):
        result = False

    elif r_gid != gid.zfill(8):
        result = False

    logger.debug("validation result:%s", result)
    return result


rev_OP_map = dict([(v, k) for k, v in globals().items() if k.startswith('OP_')])
rev_MTH_map = dict([(v, k) for k, v in globals().items() if k.startswith('MTH_')])


def pkt2dict(pkt, fields=['op', 'sid', 'rid', 'cat', 'plg', 'gid', 'mth', 'pld']):
    fields_dict = {}
    try:
        fields_dict = dict(zip(fields, map(str, pkt)))
        fields_dict['op'] += '(%s)' % rev_OP_map[int(fields_dict['op'])]
        fields_dict['mth'] += '(%s)' % rev_MTH_map[int(fields_dict['mth'])]
    except:
        pass
    return fields_dict

def pkt2str(pkt, sep=', '):
    ret = repr(pkt)
    try:
        ret = sep.join(['%s:%s' % (k, v) for k, v in pkt2dict(pkt).items()])
    except:
        pass
    return ret

class EmptyException(Exception):
    pass

class InvalidPacketError(Exception):
    def __init__(self, v, pkt=None):
        self.value = v
        self.pkt = pkt

    def __str__(self):
        return repr(self.value)
