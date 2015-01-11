""" major exceptions """

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

# request = (op,  sid, rid, cat, plg, gid, mth, pld)
# resp_t  = (suc, sid, rid, cat, plg, gid, mth, result)

class ClientError(Exception):
    """ base error """
    def __init__(self, message='', reason='', request=None, response=None):
        self.message = ""
        self.reason = ""
        self.request = None
        self.response = None

        if isinstance(message, str):
            self.message = message

        if isinstance(reason, str):
            self.reason = reason

        if isinstance(request, (list, tuple)) and len(request) == 8:
            self.request = request

        if isinstance(response, (list, tuple)) and len(response) == 8:
            self.response = response

    def __str__(self):
        ret = "[%s] %s" % (self.reason, self.message)
        return ret

class AlreadyExistingError(ClientError):
    """
    raised if user tries to do sth.
    like add a plugin to a project, ...
    that has already been done
    """
    def __init__(self, message='', request=None, response=None):
        super(AlreadyExistingError, self).__init__(
            message=message,
            reason="Resource already exists",
            request=request,
            response=response
        )

class InputError(ClientError):
    """ raised if user inputs invalid stuff """
    def __init__(self, message='', request=None, response=None):
        super(InputError, self).__init__(
            message=message,
            reason="Input error",
            request=request,
            response=response
        )

class NotFoundError(ClientError):
    """ if wgroup, user, project, .. not found """
    def __init__(self, message='', request=None, response=None):
        super(NotFoundError, self).__init__(
            message=message,
            reason="Resource not found",
            request=request,
            response=response
        )

class PermissionDenied(ClientError):
    """ user is not allowed to execute operation """
    def __init__(self, message='', request=None, response=None):
        super(PermissionDenied, self).__init__(
            message=message,
            reason="Permission denied",
            request=request,
            response=response
        )

class InvalidServerResponse(ClientError, socket.error):
    """ client receives an response that does not match excepted criterions """
    def __init__(self, message='', request=None, response=None):
        super(InvalidServerResponse, self).__init__(
            message=message,
            reason="Server sends invalid response",
            request=request,
            response=response
        )

class InvalidServerPath(ClientError):
    """ client tries to access paths outside the overlay """
    def __init__(self, message=''):
        super(InvalidServerPath, self).__init__(
            message=message,
            reason="Invalid path (use $home, $shared or pluginname)"
        )
