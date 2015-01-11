""" provides functionality to download files from ccd to client"""

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
from ctools.cUtil import validFilename
from files import DIR_SHARED, DIR_HOME
from database.ccdErrors import *
from database import ccddb
import logging
import base64
import os

#logger = logging.getLogger("ccd.%s" % __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def download_file(ccd, sid, plg_id, pld):
    """
    Read a file from disk. The user is only allowed to download either from its
    home directory, the plugin directory or the shared directory.

    input:
        sid     session id
        plg_id  plugin id
        pld     payload containing the requested file name

    output:
        a dictionary containing the data

    """

    logger.info('file download: %s', pld)

    try:
        fn = pld["fn"]
    except KeyError:
        raise InputError("Unproper json format")

    if not validFilename(fn):
        raise InputError("Invalid file name %s!" % fn)

    user, _ = ccd.get_user_and_workgroup(sid)
    dirnames = fn.split("/")
    logger.info('dirnames: %s', dirnames)
    root = dirnames[0]

    # file is in shared
    if root == DIR_SHARED:
        logger.info('Downloading rom shared')
        subpath = "/".join(dirnames[1:])
        path_dst = os.path.join(ccd.config.shared_directory, subpath)

    # file is in user's home
    elif root == DIR_HOME:
        logger.info('Downloading from home')
        subpath = "/".join(dirnames[1:])
        path_dst = os.path.join(user.home_dir, subpath)

    # file is in plugin's home
    else:
        logger.info('Downloading from plugin: %s', plg_id)
        # verify the plugin's id in the request
        if not ccddb.get_plugin_name_by_id(ccd._db.conn, plg_id):
            raise InputError("Invalid plugin id!")

        path_plg = os.path.join(user.home_dir, plg_id)

        # the given file name must be in the plugin's home directory
        subpath = "/".join(dirnames)
        path_dst = os.path.join(path_plg, subpath)

    logger.info('Downloading from %s', path_dst)

    try:
        blob = open(path_dst, "r+b").read()
    except IOError as ioerror:
        if ioerror.errno == 2:
            raise NotFoundError("No such file %s!" % path_dst)
        else:
            raise ioerror

    string = base64.encodestring(blob)

    return dict(content=string)
