""" provides means to validate user cli input """

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
from errors import InputError
import re

def validate_filename(fn):
    """ Function checks whether file name contains allowed chars. """
    #valid = re.compile("^[a-zA-Z0-9_(\.\w)]+(\.\w\w\w(\w)*)*$")
    #return True if valid.match(fn) is not None else False
    for char in ("..", "&", "~"):
        if char in fn:
            return False
    return True

def validate_pluginid(plg_id, LEN_PLGID=32):
    """ raises an cli.InputError in case of invalid plugin id """
    valid = re.compile("[a-fA-F0-9]{32,}")

    if not len(plg_id) == LEN_PLGID or \
            valid.match(plg_id) is None:

        raise InputError("Invalid plugin id %s!" % str(plg_id))

def validate_name(name, MAX_LEN_NAME=255):
    """ raises an InputError in case of invalid name """
    if len(name) > MAX_LEN_NAME:
        raise InputError("Name exceeds limit of %d chars." %
                         MAX_LEN_NAME)

def validate_mail(mail, MAX_LEN_MAIL=255):
    """ raises an InputError in case of in valid mail string """
    if len(mail) > MAX_LEN_MAIL:
        raise InputError("Mail exceeds limit of %d chars." %
                         MAX_LEN_MAIL)

def validate_description(description, MAX_LEN_DESC=8096):
    """ raises an InputError in case of invalid description string """
    if len(description) > MAX_LEN_DESC:
        raise InputError("Desc exceeds limit of %d chars." %
                         MAX_LEN_DESC)
