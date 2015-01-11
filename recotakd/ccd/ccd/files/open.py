"""
Provides means to plugins to open files in the $shared or the user's $home
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
directory. Plugins use them like the builtin open command.

"""
from ctools.cUtil import validFilename
from database.ccdErrors import *
import logging
import os

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

def open_shared(fn, mode="r", buffering=-1):
    """
    Open a file in the shared directory.

    input:
        fn          name of file to open
        mode        mode to open file with (if ommitted: 'r')
        buffering   specifies the file's desired buffer size: 0 means
                    unbuffered, 1 means line buffered, any other positive
                    value means use a buffer of (approximately) that size
                    (in bytes). A negative buffering means to use the system
                    default, which is usually line buffered for tty devices
                    and fully buffered for other files. If omitted, the
                    system default is used)

    output:
        return file object

    """
    logger.debug("request to open shared file %s", fn)
    base_dir = open_shared.base_dir

    if not validFilename(fn) or fn.startswith("/"):
        raise NotFoundError("Invalid file name %s!" % fn)

    to_open = os.path.join(base_dir, fn)
    logger.debug("request to open file %s", to_open)
    return open(to_open, mode, buffering)

def open_home(fn, mode="r", buffering=-1):
    """
    Open a file in the plugin's home directory directory.

    input:
        fn          name of file to open
        mode        mode to open file with (if ommitted: 'r')
        buffering   specifies the file's desired buffer size: 0 means
                    unbuffered, 1 means line buffered, any other positive
                    value means use a buffer of (approximately) that size
                    (in bytes). A negative buffering means to use the system
                    default, which is usually line buffered for tty devices
                    and fully buffered for other files. If omitted, the
                    system default is used)

    output:
        return file object

    """
    logger.debug("request to open home file %s", fn)
    base_dir = open_home.base_dir

    if not validFilename(fn) or fn.startswith("/"):
        raise NotFoundError("Invalid file name %s!" % fn)

    to_open = os.path.join(base_dir, fn)
    logger.debug("request to open file %s", to_open)
    return open(to_open, mode, buffering)


def open_any(fn, mode="r", buffering=-1):
    """
    Open a file in the plugin's home directory directory.

    input:
        fn          name of file to open
        mode        mode to open file with (if ommitted: 'r')
        buffering   specifies the file's desired buffer size: 0 means
                    unbuffered, 1 means line buffered, any other positive
                    value means use a buffer of (approximately) that size
                    (in bytes). A negative buffering means to use the system
                    default, which is usually line buffered for tty devices
                    and fully buffered for other files. If omitted, the
                    system default is used)

    output:
        return file object

    """

    logger.info('OPEN ANYWHERE: ' + fn)
    SYM_SHARED = "$shared"
    SYM_HOME = "$home"

    ident = ''
    fn_part = fn[:]
    idx = fn.find('/')
    if idx > 0:
        while not ident:
            ident, fn_part = fn_part.split('/', 1)

        if ident == SYM_HOME:
            return open_home(fn_part, mode, buffering)

        elif ident == SYM_SHARED:
            return open_shared(fn_part, mode, buffering)

    r = None
    try:
        r = open_home(fn, mode, buffering)
    except:
        r = open_shared(fn, mode, buffering)

    return r
