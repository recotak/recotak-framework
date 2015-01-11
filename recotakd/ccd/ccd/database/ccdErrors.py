"""
This module contains basic ccd errors. The general idea behind error catching
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
is, to enable the application to react in an appriopriate way. Avoid catching
exceptions just for raise changing the exception message:

    try:
        foo()
    except:
        raise Exception("something went wrong during foo()")

This information is already encoded in the stack trace and therefore it is
redunant. Besides that, it breaks the stack trace and makes debugging harder.

There are more or less precise descriptions that indicate which exception is
for which use case.

"""

class CcdError(Exception):
    pass

class EClosed(IOError, CcdError):
    """ Pipe has already been closed """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class SessionError(CcdError):
    """
    A session exception might be raised if one of the session authentication
    stages fail.

    """
    pass

class SessionEnd(SessionError):
    """ if a OP_LOGOUT is received throw a SessionEnd error"""
    pass

class InvalidSessionID(SessionError):
    """
    raised if an invalid session id encounters

    """
    def __init__(self, sid):
        CcdError.__init__(self, "Invalid session id(%s)" % sid)


class InputError(CcdError):
    """
    used for invalid json formats or input that arrives via ccd protocol
    and is illegal

    """
    pass

class PermissionDenied(CcdError):
    """ used in case of illegal access """
    def __init__(self, name):
        CcdError.__init__(self, "Permission denied for %s" % name)

class NotFoundError(CcdError):
    """ if wgroup, user, project, .. not found """
    pass

