""" handles the installation of a plugin into ccd context """

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
from plugins import localCategory
from connection import ccdCrypto
from database import ccdUser
from database import ccddb
import logging
import shutil
import time
import sys
import imp
import os

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)


def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)


def setup_plugin_conf_dir(ccd, sid, plg):
    """ Function moves the config directory to users home dir. It returns
        plugin's new root path.
    """
    logger.debug("setting plugin configuration directory..")
    path_dst = get_plugin_dir(ccd, sid, plg.id)

    path_plg = os.path.join(ccd.config.plugindir, plg.name)
    path_src = os.path.join(path_plg, "config")
    logger.debug("looking for :%s", path_src)
    # check whether src plugin's config dir exists

    if not os.path.exists(path_dst):
        logger.warning("fatal: Plugin directory does not exist!")

        # at least create the plugin dir
        try:
            logger.debug("creating %s", path_dst)
            os.mkdir(path_dst)
        except Exception as e:
            logger.warning("Failed to create plugin dir(%s): %s",
                           path_dst, e)

        # set owner of directory
        try:
            logger.debug("chown to %s:%s.", ccd.config.runAsUid,
                         ccd.config.runAsGid)
            os.chown(path_dst, ccd.config.runAsUid, ccd.config.runAsGid)
        except Exception as e:
            logger.error("Failed to change owner of directory (%s):'%s'",
                         path_dst, e)

        # create directory for fd forwarding
        fd_path = os.path.join(path_dst, ccdUser.User.FD_DIR)
        # create directory
        try:
            os.mkdir(fd_path)
        except Exception as e:
            logger.warning("Error while creating fd dir:%s", e)
        logger.debug('Created fd dir as %s', fd_path)

    if not os.path.exists(path_src):
        logger.warning("fatal: Plugin directory does not exist!")
        return path_dst

    try:
        # copy directory
        logger.debug("Copying from %s to %s ...", path_src, path_dst)
        #shutil.copytree(path_src, path_dst)
        copytree(path_src, path_dst)
        logger.debug("Adusting Permissions for %s ...", path_dst)
        os.chown(path_dst, ccd.config.runAsUid, ccd.config.runAsGid)

        # set file owner
        for root, dirs, files in os.walk(path_dst):
            for f in files:
                os.chown(os.path.join(root, f),
                         ccd.config.runAsUid,
                         ccd.config.runAsGid)
            for d in dirs:
                os.chown(os.path.join(root, d),
                         ccd.config.runAsUid,
                         ccd.config.runAsGid)

    except Exception as err:
        logger.error(str(err))

    return path_dst

def setup_plugin_categories(ccd, module):
    """ Function looks for the plugin's requested categories. If found,
        it links plugin, otherwise it creates categories first.

        input:
            ccd     ccd instance to operate on
            module  the module to import

    """
    logger.debug("Categorising module: %s", str(module.categories))

    for wanted in module.categories:
        category = ccd.pluginCategory
        subcats = wanted.strip("/").split("/")
        for subcat in subcats:
            logger.debug("looking for cat %s", subcat)
            if not subcat in category:
                logger.debug("Creating category %s", subcat)
                newcat = new_category(ccd, subcat)
                category.link(newcat)
                category = newcat
            else:
                logger.debug("found %s", subcat)
                category = category.get(subcat)

        category.link(module)


def new_category(ccd, name):
    cat = localCategory.LocalCategory(name)
    ccd.categories.append(cat)
    return cat


def setup_plugin_fd(ccd, sid, rid, args):
    """ Returns the new stdout/stdin. The new fd is named after some
        random bla. Further, the fd is stored in db with some additional
        information like user that started the plugin and command that
        issued the execution.

        input:
            sid     session id
            args    arguments that were passed with OP_EXEC

        output:
            fd      new fd name
            fid     database id of the fd in db

    """
    logger.debug("setting forwarder for plugin")
    fd_out = "/dev/null"
    fd_in = "/dev/null"
    fid = -1

    uid = ccd.get_user_and_workgroup(sid)[0].uid
    command = "%s %s" % (ccd.current_plugin.name, " ".join(args))
    plg_id = ccd.current_plugin.id

    # get directory for client io files
    fd_dir = get_fd_dir(ccd, sid, plg_id)

    # random name for new stdout/stdin
    fd = os.path.join(
        fd_dir,
        ccdCrypto.getRandomBytes(16))

    # create new stdout
    fd_out = os.path.join(fd_dir, fd + "_out")
    # create the output fifo
    os.mkfifo(fd_out)
    logger.debug('Output Fifo created: %s', fd_out)

    # create new stdin
    if ccd.current_plugin.interactive:
        fd_in = os.path.join(fd_dir, fd + "_in")
        # create the input fifo
        os.mkfifo(fd_in)
        logger.debug('Input Fifo created: %s', fd_in)

    # store created fds in database
    fid = ccddb.storeFd(ccd._db.conn, fd_out, fd_in, uid, command, plg_id, rid)
    logger.debug("fid=%d", fid)

    return fd_out, fd_in, fid


def reload_plugins(ccd):
    """ reloads all plugins """
    ccd._initCategories()


def scan_plugin_directory(ccd):
    """ Scans the plugin dir to find the main.py of the plugin.
        If the file is found, add it to plugins array.
    """
    logger.info("Scanning plugin directory..")

    if not os.path.exists(ccd.config.plugindir):
        logger.error("fatal: Invalid plugin directory %s!",
                     ccd.config.plugindir)
        raise Exception("Invalid plugin directory!")

    sys.path.append(ccd.config.plugindir)

    for root, dirs, _ in os.walk(ccd.config.plugindir):
        if root != ccd.config.plugindir:
            break
        for subdir in dirs:
            try:
                add_plugin(ccd, subdir)
            except Exception as err:
                logger.warning("Error while adding plugin %s:'%s'",
                               subdir, str(err))


def __import__(name):
    # delete old plugins
    for key in sys.modules.keys():
        if key.startswith(name):
            logger.debug("deleting %s from sys.modules.keys..", key)
            del(sys.modules[key])

    try:
        # If any of the following calls raises an exception,
        # there's a problem we can't handle -- let the caller handle it.
        fp, pathname, description = imp.find_module(name)
        logger.debug("fp:%s, path:%s, desc:%s", fp, pathname, description)
    except ImportError as err:
        logger.error("Faild to import plugin:'%s'", err)
        raise err

    try:
        mod = imp.load_module(name, fp, pathname, description)
    finally:
        # Since we may exit via an exception, close fp explicitly.
        if fp:
            fp.close()

    return mod

def add_plugin(ccd, name):
    """ The plugin's register method is called to get some basic
        properties. It also sets up the plugin's ID. Afterwards,
        the categories are created and plugin is linked.
    """
    logger.info("adding plugin from %s", name)
    db = ccd._db.conn

    # import module
    try:
        mod = __import__(name)
        new = mod.main.register()
    except Exception as e:
        print 'Error loading plugin %s: %s' % (name, str(e))

    ccd.plugins.append(new)

    # get hash to set as id
    new.id = get_plugin_hash(ccd, name)
    logger.debug("new.id=%s", new.id)

    # set up categories
    setup_plugin_categories(ccd, new)

    # add to database
    try:
        ccddb.add_plugin(db, **new.__dict__)

    except ccddb.AlreadyExistingError:
        # if we have an integrity error, we need to check whether
        # the plugin in database has the same id. if not, the new
        # plugin is an update of the old one in the database. Hence,
        # we delete the old one and add the new. otherwise pass
        if not ccddb.get_plugin_name_by_id(db, new.id):

            # delete old one
            logger.debug("deleting old plugin %s", new.name)
            ccddb.delete_plugin_by_name(db, new.name)

            # add new one
            try:
                logger.debug("adding new one")
                ccddb.add_plugin(db, **new.__dict__)

            except ccddb.AlreadyExistingError:
                # if there is an integrity error, here, the plugin
                # already is in database but marked als deleted.
                # this might happen, if the main.py is of a previous
                # version. if so we undelete it.
                ccddb.undelete_plugin_by_id(db, new.id)

        else:
            logger.debug("plugin %s already in database", new.name)

    except Exception as e:
            logger.error("Failed to store plugin (%s) in database:'%s'",
                         new.name, e)


def get_plugin_hash(ccd, name):
    """ Function returns a hash. The hash ought to constructed over the
        content of the plugin's main.py. If an error occurs, it hashes
        the time.
    """
    logger.debug("Calculating hash.")

    try:
        path = os.path.join(ccd.config.plugindir, name)
        main = "main.py"
        with open(os.path.join(path, main)) as f:
            toHash = f.read()
    except Exception as e:
        logger.error("Failed to calculate plugin hash:'%s'.'", str(e))
        toHash = str(time.time())

    return ccdCrypto.genPID(toHash)


def get_plugin_dir(ccd, sid, plg_id):
    """ returns the path to the plugins directory """
    user, _ = ccd.get_user_and_workgroup(sid)

    path_user = os.path.join(ccd.config.userdir, user.name)
    if not os.path.exists(path_user):
        raise Exception("fatal: User dir does not exist %s!", path_user)

    path_dst = os.path.join(path_user, plg_id)
    return path_dst


def get_fd_dir(ccd, sid, plg_id):
    """ returns the path to the plugins directory """

    # get plugin directory
    path_plg = get_plugin_dir(ccd, sid, plg_id)

    user, _ = ccd.get_user_and_workgroup(sid)

    path_fd = os.path.join(path_plg, user.FD_DIR)
    if not os.path.exists(path_fd):
        raise Exception("fatal: User dir does not exist %s!", path_fd)

    return path_fd
