""" functionality to upload files either to user $home or $shared directory """

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
from plugins.setup import setup_plugin_conf_dir
from ctools.cUtil import validFilename
from plugins.plugin import getplugin_byid
from files import DIR_SHARED, DIR_HOME
from database.ccdErrors import *
from connection import ccdlib
from database import ccddb
import logging
import base64
import os

#logger = logging.getLogger("ccd.%s" % __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def get_write_location(ccd, sid, fn, plg_id=None):
    """
    takes a filename, validates whether user is allowed to write there and
    returns abosolute path. If plugin id is passed, check whether location
    is valid with respect to the passed plugin id.

    """
    if not validFilename(fn):
        raise IOError("Invalid file name %s!" % fn)

    #TODO we need to check, whether it is an upload to the plugin's home
    # directory (in the user's home directory) or an upload to the shared
    # directory
    user, _ = ccd.get_user_and_workgroup(sid)
    dirname = os.path.dirname(fn)

    #print 'plg_id' + repr(plg_id)
    #print 'dirname' + repr(dirname)

    if dirname == DIR_SHARED:

        # the only user who is allowed to upload in shared directory, is
        # the superadmin
        if not user.uid == ccd.superadmin.uid:
            raise PermissionDenied(user.name)

        path_dst = ccd.config.shared_directory

    # the user is able to upload things to its direct home directory. doing so,
    # file will not be written either to plugin directory nor to shared.
    elif dirname == DIR_HOME:
        path_dst = os.path.join(ccd.config.userdir, user.name)

        if not os.path.exists(path_dst):
            raise NotFoundError("fatal: user dir does not exist!")

    # every user is allowed to upload files into the plugin's directory within
    # the user's home directory. this happens, if the user does not make any
    # statements where to put the file
    #elif plg_id and not dirname:
    else:
        plg_id = dirname

        # we need to check, whether the plugin id is of a non-deleted
        # plugin
        if not ccddb.get_plugin_name_by_id(ccd._db.conn, plg_id):
            logger.error("User wants to write to an invalid destination %s"
                         % fn)
            raise PermissionDenied(user.name)
            #raise NotFoundError("Invalid plugin id!")

        path_dst = os.path.join(user.home_dir, plg_id)

        if not os.path.exists(path_dst):
            # if plugin dir is missing, create one by copying
            # the config dir of the plugin as we would do
            # during the installation process
            plg = getplugin_byid(ccd, plg_id)
            path_dst = setup_plugin_conf_dir(ccd, sid, plg)

    #else:
    #    logger.error("User wants to write to an invalid destination %s"
    #                 % fn)
    #    raise PermissionDenied(user.name)

    return os.path.join(path_dst, os.path.basename(fn))

def upload_file(ccd, sid, plg_id, pld, options):
    """ Writes a file to disk. """

    logger.info('file upload: %s', pld)

    try:
        fn = pld["fn"]
        content = pld["content"]
    except KeyError:
        raise Exception("Unproper json format in payload while"
                        "trying to upload file")

    # validates and returns location that is allowed to write
    path_dst = get_write_location(ccd, sid, fn, plg_id)
    logger.info('Uploading to %s', path_dst)

    if options != ccdlib.MTH_FORCE and os.path.exists(path_dst):
        raise IOError("File already exists.")

    try:
        blob = base64.decodestring(content)
    except Exception as e:
        logger.error("Failed to decode base64 string:'%s'", e)
        raise IOError("Failed to decode base64 string")

    open(path_dst, "w+b").write(blob)
    os.chown(path_dst, ccd.config.runAsUid, ccd.config.runAsGid)
