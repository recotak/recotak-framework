"""
ccd client module to send ccd conform packets to the server
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

"""

import reco_client.core.errors as errors
#import reco_client.core.window as window
#from reco_client.core.errors import *
#from reco_client.core.window import window.get_win_by_rid
import ccdlib
import logging
logger = logging.getLogger("client.%s" % __name__)

DEFAULT_MTH = ccdlib.MTH_NOP
DEFAULT_RID = "0".zfill(32)
DEFAULT_PLG = "0"
DEFAULT_PLD = ""

def _get_request_id(session):
    """ asks the ccd for a request id and returns it """
    resp_t = sendpacket(session,
                        op=ccdlib.OP_GETRID,
                        pld=dict(rid=DEFAULT_RID))[-1]
    if not "rid" in resp_t:
        raise errors.InvalidServerResponse(message="No rid found in payload.", response=resp_t)
    return resp_t["rid"]

def _handle_termination_packet(session, resp_t):
    """
    the ccd server might sent MTH_TERMINATE packets which indicate, that
    a plugin is finshed. if such a packet is received, close the
    corresponding window. these packets can be sent at anytime by the ccd
    and do not depend on any request

    input:
        session session affected by that packet
        resp_t  response tuple representing the servers response packet

    """

    try:
        rid = resp_t[2]
    except IndexError as e:
        # this actually can not happen, because we set a default value for rid
        # ... but whatever
        logger.exception(e)
        raise errors.InvalidServerResponse(message="No rid in terminate response", response=resp_t)

    try:
        win_state = resp_t[-1]["code"]
    except (IndexError, KeyError) as e:
        logger.exception(e)
        raise errors.InvalidServerResponse(message="No state in terminate response payload", response=resp_t)

    #win = window.get_win_by_rid(session, rid)
    win = session.get_win_by_rid(rid)
    win.set_state(win_state)

def _handle_output_packet(session, resp_t):
    """
    the ccd server might sent MTH_OUTPUT packets that indicate packet
    containing a plugin's stdout. if such a packet is received, forward the
    corresponding output to the window.

    input:
        session session affected by that packet
        resp_t  response tuple representing the servers response packet

    """
    try:
        rid = resp_t[2]
    except (IndexError) as e:
        # this actually can not happen, because we set a default value for rid
        # ... but whatever
        logger.exception(e)
        raise errors.InvalidServerResponse(message="No rid or state in terminate response", response=resp_t)

    #win = window.get_win_by_rid(session, rid)
    win = session.get_win_by_rid(rid)
    win._write_to_output(resp_t)

def sendpacket(session, op, **kwargs):
    """
    wrapper method for ccdlib. mostly equivalent to

        ccdlib.send(..)
        ccdlib.recv(..)

    basically gets the same arguments as ccdlib.send. in contrast to ccdlib
    functions, sendpacket sets missing arguments automatically. it also calls
    for a valid request id (rid). it also verifies that the response is valid.

    mandatory arguments:
        session session object holding session id
        op      ccd operation

    optional arguments:
        rid     request id
        cat     category id
        plg     plugin id
        gid     connection group id
        mth     method
        pld     payload

    """
    sock = session.sock

    sid = session.sid
    gid = kwargs["gid"] if "gid" in kwargs else session.current_group_gid
    cat = kwargs["cat"] if "cat" in kwargs else session.current_category.id
    mth = kwargs["mth"] if "mth" in kwargs else DEFAULT_MTH
    plg = kwargs["plg"] if "plg" in kwargs else DEFAULT_PLG
    pld = kwargs["pld"] if "pld" in kwargs else DEFAULT_PLD
    rid = kwargs["rid"] if "rid" in kwargs else DEFAULT_RID

    # first we need a new request id for the request
    if op not in (ccdlib.OP_GETRID, ccdlib.OP_LOGIN) and rid == DEFAULT_RID:
        rid = _get_request_id(session)

    # second, build request and send it
    logger.debug("sending packet:%s %s", hex(op), pld)
    request = (op, sid, rid, cat, plg, gid, mth, pld)
    ccdlib.send(sock, request)

    # third, get response
    return wait_for_response(session, request)

def wait_for_response(session, request, maxfail=5):
    sock = session.sock
    response = None  # hold response packet on success
    req_str = ccdlib.pkt2str(request)
    tries = 0
    while not response:
        if tries >= maxfail:
            raise errors.InvalidServerResponse(
                message='Abadoning request after %d pkts' % tries,
                request=request,
                response=response
            )

        logger.debug("waiting for response on %s", req_str)
        # yes we do want this to block
        # if you want to be sure, that this function returns, use select
        # beforhand (like so in window.py)
        resp_t = ccdlib.recv(sock)
        res_str = ccdlib.pkt2str(resp_t)
        logger.debug("received response while waiting on %s: %s", req_str, res_str)

        # check whether the incoming packet is ours, if so handle it
        # correspondingly
        if ccdlib.checkRsp(request, resp_t):
            logger.debug("validated response successfully %s", res_str)
            succ = resp_t[0]

            try:
                msg = resp_t[-1]
            except:
                pass
            if not msg and isinstance(request[-1], dict):
                msg = ', '.join(['%s: %s' % (k, str(v)) for k, v in request[-1].items()])

            if succ == ccdlib.OP_PERMISSION_DENIED:
                raise errors.PermissionDenied(message=msg, request=request, response=resp_t)

            elif succ == ccdlib.OP_NOT_FOUND:
                raise errors.NotFoundError(message=msg, request=request, response=resp_t)

            elif succ == ccdlib.OP_INVALID_INPUT:
                raise errors.InputError(message=msg, request=request, response=resp_t)

            elif succ == ccdlib.OP_ALREADY_EXISTS:
                raise errors.AlreadyExistingError(message=msg, request=request, response=resp_t)

            elif not succ == ccdlib.OP_SUCCESS:
                raise errors.InvalidServerResponse(message=msg, request=request, response=resp_t)

            response = resp_t

        # the packet is not ours. is it a termination packet, update the
        # corresponding window and continue waiting for our response
        #elif resp_t[0] == ccdlib.OP_SUCCESS and resp_t[6] == ccdlib.MTH_TERMINATE:
        # better do further checking later, is more accurate that way
        elif resp_t[6] == ccdlib.MTH_TERMINATE:
            logger.debug("processing answer that failed to validate, but seems "
                         "to be a MTH_TERMINATE")
            try:
                _handle_termination_packet(session, resp_t)
            except errors.ClientError as e:
                logger.warning(e)
            continue

        # the packet is not ours, but a plugin's stdout packet. update the
        # corresponding window and continue waiting for our response
        #elif resp_t[0] == ccdlib.OP_SUCCESS and resp_t[6] == ccdlib.MTH_OUTPUT:
        # better do further checking later, is more accurate that way
        elif resp_t[6] == ccdlib.MTH_OUTPUT:
            logger.debug("processing answer that failed to validate, but it "
                         "seems to be a MTH_OUTPUT")
            try:
                _handle_output_packet(session, resp_t)
            except errors.ClientError as e:
                logger.warning(e)
            continue

        # we received a packet, that is not ours and somewhat corrupted
        else:
            raise errors.InvalidServerResponse(message='Orphaned packet', request=request, response=response)

    return response
