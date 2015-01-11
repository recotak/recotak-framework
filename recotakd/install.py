#!/bin/sh

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
# -*- mode: Python -*-

""":"
# https://github.com/apache/cassandra/blob/trunk/bin/cqlsh
# bash code here; finds a suitable python interpreter and execs this file.
# prefer unqualified "python" if suitable:
python -c 'import sys; sys.exit(not (0x02070000 < sys.hexversion < 0x03000000))' 2>/dev/null \
    && exec python "$0" "$@"
which python2.7 > /dev/null 2>&1 && exec python2.7 "$0" "$@"
echo "No appropriate python interpreter found." >&2
exit 1
":"""
python_interpreter = "/usr/bin/python2.7"
#python_interpreter = "python"

import os
import locale
import shutil
import sys
import imp
import random
import string
import tempfile
import urllib
import tarfile
import zipfile
from pwd import getpwnam
from grp import getgrnam
import ConfigParser
import stat

try:
    import argparse
except ImportError:
    print("Invalid python version! Need python2.7.")
    sys.exit(1)

import subprocess
import logging
from getpass import getpass

__author__ = "curesec"
__email__ = "recotak@curesec.com"
__version__ = 0.65

__credits__ = """
ooooooooo.   oooooooooooo   .oooooo.     .oooooo.   ooooooooooooo       .o.       oooo    oooo
`888   `Y88. `888'     `8  d8P'  `Y8b   d8P'  `Y8b  8'   888   `8      .888.      `888   .8P'
 888   .d88'  888         888          888      888      888          .8"888.      888  d8'
 888ooo88P'   888oooo8    888          888      888      888         .8' `888.     88888[
 888`88b.     888    "    888          888      888      888        .88ooo8888.    888`88b.
 888  `88b.   888       o `88b    ooo  `88b    d88'      888       .8'     `888.   888  `88b.
o888o  o888o o888ooooood8  `Y8bood8P'   `Y8bood8P'      o888o     o88o     o8888o o888o  o888o
"""


config = "ccd/ccd/config/productive.conf"
config_socksy = "supply/socksy/socksy.conf"
cfg = None


opsys = " ".join(os.uname()).lower()
arch = "arch" in opsys
debian = "debian" in opsys
kali = "kali" in opsys
ubuntu = "ubuntu" in opsys

if kali:
    debian = True

if ubuntu:
    debian = True


ccd_dir = "/srv/recon"
venv_dir = "recotak_venv"

socksy_location = "supply/socksy/socksy.py"
ccd_location = "ccd/ccd/ccd.py"
shared_location = "shared"

no_confirm = False
db_init = False

mods = [
    "psycopg2",
    "M2Crypto",
    "pycrypto",
    "ecdsa",
    "SQLAlchemy",
    "SQLAlchemy-Utils",
    "iptools",
    "paramiko",
    "odfpy",
    "BeautifulSoup",
    "psutil",
    "psutil --upgrade",
    "exrex",
    "SQLAlchemy-Utils",
]

ext_dir = "./3rdParty"
ext_mods = [
    "impacket",
]

# users
USER_CCD = "ccdplugin"
GROUP_CCD = "ccdplugin"
USER_SOCKSY = "socksy"

# directories
DIR_SOCKSY = "/var/log/socksy/"

# credentials file
REK_CRED = "recotak_credentials"

cert = "ccd/ccd/connection/ccdcert.pem"
cert_key = "ccd/ccd/connection/ccdkey.pem"

# to provide an installation from scratch, we need to install
# all required programs. at the moment, there are two distributions
# supported
ARCH = "arch"
DEBIAN = "debian"
packets = [
    dict(arch="gcc", debian="gcc"),
    dict(arch="python2", debian="python2.7-dev"),
    dict(arch="python2-pip", debian="python-pip"),
    dict(arch="python2-virtualenv", debian="python-virtualenv"),
    dict(arch="postgresql", debian="postgresql"),
    dict(arch="python2-psycopg2", debian="python-psycopg2"),
    dict(arch="python2-m2crypto", debian="python-m2crypto"),
    dict(arch="python2-crypto", debian="python-crypto"),
    dict(arch="python2-sqlalchemy", debian="python-sqlalchemy"),
    dict(arch="texlive-latexextra", debian="texlive-latex-extra")
]
daemons = [
    dict(arch="postgresql", debian="postgresql"),
    dict(arch="socksy", debian="socksy"),
    dict(arch="ccd", debian="ccd")
]
venv_cmds = [
    'virtualenv', 'virtualenv-2.7', 'virutalenv2'
]

COLOR_HEADER = "\033[95m"
COLOR_OKBLUE = "\033[94m"
COLOR_OKGREEN = "\033[92m"
COLOR_WARNING = "\033[93m"
COLOR_FAIL = "\033[91m"
COLOR_END = "\033[0m"


def _print_section(section):
    CHAR = ":"
    COUNT = 60
    l = (COUNT - len(section)) / 2
    CHAR_S = " " * l
    print("\n%s" % (CHAR * COUNT))
    print(CHAR_S + section)
    print(CHAR * COUNT)


def _print_yellow(to_print="already installed"):
    sys.stdout.write("%s%s%s\n" % (COLOR_WARNING, to_print, COLOR_END))
    sys.stdout.flush()

def _print_green(to_print="done"):
    sys.stdout.write("%s%s%s\n" % (COLOR_OKGREEN, to_print, COLOR_END))
    sys.stdout.flush()

def _print_red(to_print="failed"):
    sys.stderr.write("%s%s%s\n" % (COLOR_FAIL, to_print, COLOR_END))
    sys.stderr.flush()

def _ask_user(question, interactive=False, pwd_mode=False, default="y"):
    """
    Ask user whether to perform specific action. If not in no_confirm mode,
    always assume user answers 'y'. If interactive, return the users answer.

    input:
        question    question to ask user
        interactive if set, return users answer
        pwd_mode    if in pwd mode, then do not print input
        default     the default answer

    output
        if interactive, return answer, otherwise return True is question is
        answered with 'y' else False

    """
    global no_confirm

    appendix = " (default='%s'): " % default
    try:
        if not pwd_mode and not no_confirm:
            answer = raw_input(question + appendix)
        elif not no_confirm:
            answer = getpass(question + appendix)
        elif no_confirm:
            print(question + appendix)
            answer = default

    except (KeyboardInterrupt, EOFError):
        print("cancelling installation!")
        sys.exit(1)

    if interactive:
        return answer if answer else default

    if not answer or answer == "y":
        return True
    elif answer == "n":
        return False
    else:
        return False


def install(mod):
    """ Executes the install primitive. """
    if arch:
        cmd = "pip2 install %s" % mod
    elif debian:
        cmd = "pip install  %s" % mod
    else:
        sys.stderr.write("wrong operating system!")
        return

    logging.debug("installing %s.. " % mod)

    if os.system("%s>/dev/null" % cmd) == 0:
        _print_green()
    else:
        _print_red()


def install_extern_modules(to_install):
    """ Checks whether python module is available. If not, install the module.

    Keyword arguments:
    to_install -- list of modules to install

    """
    if not _ask_user("Install required python modules?"):
        return

    for mod in to_install:
        sys.stdout.write("module %s.. " % mod)
        sys.stdout.flush()

        try:
            fp, pathname, description = imp.find_module(mod)
            imp.load_module(mod, fp, pathname, description)
            _print_yellow()
        except ImportError:
            install(mod)


def _create_user(to_create):
    sys.stdout.write("creating user %s.. " % to_create)
    sys.stdout.flush()

    # if user exists
    if _execute_shell_cmd(["id", to_create], success_output=False,
                          error_output=False)[0]:
        _print_yellow()
        return

    # create
    cmd = ["useradd", "-M", "-r", "-s", "/bin/false", to_create]
    _execute_shell_cmd(cmd)


def _create_group(to_create):
    sys.stdout.write("creating group %s.. " % to_create)
    sys.stdout.flush()

    # if user exists
    if os.system("id -G %s>/dev/null" % to_create) == 0:
        _print_yellow()
        return

    # create
    cmd = ["groupadd", "-r", to_create]
    _execute_shell_cmd(cmd)


def create_socksy_user():
    """
    Checks whether user is available. If not, create user.

    """
    global USER_SOCKSY

    # ccd socksy user
    USER_SOCKSY = _ask_user("Enter user name to execute socksy proxy as",
                            default=USER_SOCKSY, interactive=True)

    _create_user(USER_SOCKSY)


def setup_logging():
    global cfg
    SECTION = "Logging"
    ccd_log_dir = "/var/log/ccd/"
    ccd_log_level = 10

    _print_section(SECTION)

    # log level
    ccd_log_level = _ask_user("Enter log level, e.g. 10=debug, 20=info, "
                              "30=warning, 40=error",
                              default=ccd_log_level, interactive=True)

    # ccd logging directory
    ccd_log_dir = _ask_user("Enter logging directory",
                            default=ccd_log_dir, interactive=True)

    _create_dir(ccd_log_dir, "root", "root")

    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "level", ccd_log_level)
        cfg.set(SECTION, "file", ccd_log_dir)


def _create_dir(dst, user, group, force=False, quiet=False):
    """
    create a directory

    input:
        dst     directory to create
        user    chown to user
        group   chown to group
        force   overwrite existing directory

    """

    if not quiet:
        sys.stdout.write("creating directory %s.. " % dst)
        sys.stdout.flush()

    # check whether dir exists
    if not force and os.path.exists(dst):
        if not quiet:
            _print_yellow()
        return

    try:
        # create directory
        if os.path.isfile(dst):
            dirname = os.path.dirname(dst)
        else:
            dirname = dst
        os.makedirs(dirname)

        # set owner
        uid = getpwnam(user).pw_uid
        gid = getgrnam(group).gr_gid

        logging.debug("chown to %s (uid=%d), group %s (gid=%d)",
                      user, uid, group, gid)
        os.chown(dst, uid, gid)

    except Exception as e:
        logging.warning(e)
        if not quiet:
            _print_red()
        return

    if not quiet:
        _print_green()


def create_socksy_dir():
    """
    Checks whether dir exists. If not, create directory.

    """
    global DIR_SOCKSY

    # socksy directory
    DIR_SOCKSY = _ask_user("Enter directory to write socksy log output",
                           default=DIR_SOCKSY, interactive=True)

    _create_dir(DIR_SOCKSY, USER_SOCKSY, USER_SOCKSY)


def setup_connection():
    global cfg, cert, cert_key
    SECTION = "Connection"
    bind = "127.0.0.1:2401"
    listenmax = 32
    usesocks = True
    socksserver = "127.0.0.1:8081"
    cert = os.path.join(ccd_dir, "ccd/ccd/connection/ccdcert.pem")
    cert_key = os.path.join(ccd_dir, "ccd/ccd/connection/ccdkey.pem")
    ssl_enabled = False
    ssl_version = 3
    client_fingerprint = "11136388152A71F97EA1AEDA8418029B4163FE97"

    _print_section(SECTION)

    # bind
    bind = _ask_user("Enter bind address",
                     default=bind, interactive=True)

    # listenmax
    listenmax = _ask_user("Enter max amount of connections to listen to",
                          default=listenmax, interactive=True)

    # usesocks
    usesocks = _ask_user("Use a socksserver?",
                         default=usesocks, interactive=True)

    # sockserver
    if usesocks:
        socksserver = _ask_user("Address of socks server",
                                default=socksserver, interactive=True)

    # ssl enabled
    ssl_enabled = _ask_user("Enable SSL?",
                            default=ssl_enabled, interactive=True)

    if ssl_enabled:
        # cert
        cert = _ask_user("The connection to the ccd client is TLS encrypted. \n"
                         "Path to ccd server certificate",
                         default=cert, interactive=True)

        # set certificate permissions
        os.chmod(cert, stat.S_IRUSR | stat.S_IWUSR)

        # cert key
        cert_key = _ask_user("Path to certificate private key",
                             default=cert_key, interactive=True)

        # set certificate key permissions
        os.chmod(cert_key, stat.S_IRUSR | stat.S_IWUSR)

        # ssl version
        ssl_version = _ask_user("Enter SSL version to use, e.g. 0=SSLv2, 1=SSLv3, "
                                "2=SSLv23, 3=TLSv1",
                                default=ssl_version, interactive=True)

        # client fingerprint
        client_fingerprint = _ask_user("To authenticate the client, enter sha1 "
                                       "fingerprint \n of the client certificate",
                                       default=client_fingerprint, interactive=True)

    # store settings
    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "bind", bind)
        cfg.set(SECTION, "listenmax", listenmax)
        cfg.set(SECTION, "usesocks", usesocks)
        cfg.set(SECTION, "socksserver", socksserver)
        cfg.set(SECTION, "cert", cert)
        cfg.set(SECTION, "key", cert_key)
        cfg.set(SECTION, "ssl_enabled", ssl_enabled)
        cfg.set(SECTION, "ssl_version", ssl_version)
        cfg.set(SECTION, "client_fingerprint", client_fingerprint)


def copy_recon():
    logging.debug("copying recon directories to %s.." % ccd_dir)
    pwd = os.getcwd()
    #TODO no hardcoded directories
    srcs = ("ccd", "supply", "plugins")
    dst = ccd_dir
    copied_all = True

    # nothing to copy if destination directory is base directory
    if dst == pwd:
        logging.debug("destination=source, so skipping")
        return

    # create destination directory
    if not os.path.exists(dst):
        os.makedirs(dst)

    # copy ccd directories
    for directory in srcs:
        if not os.path.exists(directory):
            sys.stderr.write("Failed install recon! Directory does not "
                             "exist:%s" % directory)
            copied_all = False
            continue

        try:
            _src = os.path.join(pwd, directory)
            _dst = os.path.join(dst, directory)
            logging.debug("copying %s to %s", _src, _dst)
            shutil.copytree(_src, _dst)
        except OSError as e:
            # file exist error
            if e.errno == 17:
                pass
            else:
                raise(e)

    if not copied_all:
        sys.exit(1)

def _chown_directory(directory, uid, gid, quiet=False):
    for root, dirs, files in os.walk(directory):
        for d in dirs:
            if not quiet:
                print("chowning %s" % d)
            os.chown(os.path.join(root, d), uid, gid)
            _chown_directory(os.path.join(root, d), uid, gid, quiet=quiet)

        for f in files:
            if not quiet:
                print("chowning %s" % f)
            os.chown(os.path.join(root, f), uid, gid)


def setup_user():
    global cfg
    SECTION = "User"
    user_dir = os.path.join(ccd_dir, "user")
    shared_dir = os.path.join(ccd_dir, "shared")

    _print_section(SECTION)

    # user directory
    user_dir = _ask_user("Enter ccd user home directory",
                         default=user_dir, interactive=True)
    _create_dir(user_dir, USER_CCD, GROUP_CCD)

    # shared directory
    # copy shared directory to where the ccd share directory should be
    shared_dir = _ask_user("Enter ccd shared directory",
                           default=shared_dir, interactive=True)

    uid = getpwnam(USER_CCD).pw_uid
    gid = getgrnam(GROUP_CCD).gr_gid

    src = shared_location
    dst = shared_dir
    cmd = ["cp", "-r", src, dst]

    if _execute_shell_cmd(cmd, success_output=False):
        os.chown(shared_dir, uid, gid)
        _chown_directory(shared_dir, uid, gid)

    # store settings
    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "dir", user_dir)
        cfg.set(SECTION, "shared", shared_dir)


def random_password(min_length=6, max_length=16, chars=string.ascii_letters + string.digits):
    pw_length = random.randint(min_length, max_length)
    ran_pass = ''.join(random.choice(chars) for x in range(pw_length))
    return ran_pass


def setup_superadmin():
    global cfg
    SECTION = "Superadmin"
    user = "recotak"
    pwd_sha256 = "494c43f90eafad31302685932a982c0778b919aa97152140cddc60872f79221e"
    mail = "mail@dev.null"
    password = random_password()

    # user name
    user = _ask_user("The ccd superadmin is a user to configure and \n"
                     "maintain the ccd (e.g. managing work groups and \n"
                     "users). Although, the user is not able to execute \n"
                     "any plugins it is the most powerful user. \n"
                     "Enter name of that user",
                     default=user,
                     interactive=True)

    while True:
        # password
        answer = _ask_user("Enter password",
                           default=password,
                           interactive=True,
                           pwd_mode=True)

        answer_re = _ask_user("Repeat password:",
                              default=password,
                              interactive=True,
                              pwd_mode=True)

        if answer == answer_re:
            print 'Password: %s' % answer
            fp = open(REK_CRED, 'w')
            fp.write('User: %s\nPassword: %s\n' % (user, answer))
            fp.close()
            print 'Superadmin credentials stored in ./%s' % REK_CRED
            break
        else:
            print(">> Inputs do not match.")

    if answer:
        try:
            from Crypto.Hash import SHA256
        except ImportError:
            _print_red("Missing python module. Make sure required modules are "
                       "installed (via -m).")
            return

        logging.debug("generating sha256 of password..")
        sha = SHA256.new(answer)
        pwd_sha256 = sha.hexdigest()

     # mail
    mail = _ask_user("Enter superadmin's mail address",
                     default=mail,
                     interactive=True)

    # store settings
    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "name", user)
        cfg.set(SECTION, "password", pwd_sha256)
        cfg.set(SECTION, "mail", mail)


def setup_plugins():
    global cfg, USER_CCD, GROUP_CCD
    SECTION = "Plugins"
    plugin_dir = os.path.join(ccd_dir, "plugins/")
    bind = "127.0.0.1:3002"
    listenmax = 32

    _print_section(SECTION)

    # runas_user
    USER_DIR = _ask_user("Plugins should run as non-priviledged user. Enter "
                         "user name to run as",
                         default=USER_CCD,
                         interactive=True)

    _create_user(USER_DIR)

    # runas_group
    GROUP_CCD = _ask_user("Enter user group to run as",
                          default=GROUP_CCD, interactive=True)

    _create_group(GROUP_CCD)

    # plugin directory
    plugin_dir = _ask_user("Enter plugin directory",
                           default=plugin_dir, interactive=True)

    _create_dir(plugin_dir, USER_CCD, GROUP_CCD)

    # bind
    bind = _ask_user("Enter bind address",
                     default=bind, interactive=True)

    # listenmax
    listenmax = _ask_user("Enter max amount of connections to plugins o listen "
                          "to", default=listenmax, interactive=True)

    # store settings
    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "dir", plugin_dir)
        cfg.set(SECTION, "bind", bind)
        cfg.set(SECTION, "listenmax", listenmax)
        cfg.set(SECTION, "runas_user", USER_CCD)
        cfg.set(SECTION, "runas_group", GROUP_CCD)

    return plugin_dir


def get_remote_data(plugin_dir):

    if not _ask_user("Fetch remote data for plugins?"):
        return

    if not plugin_dir:
        plugin_dir = os.path.join(ccd_dir, "plugins/")

        plugin_dir = _ask_user("Enter plugin directory",
                               default=plugin_dir, interactive=True)

    uid = getpwnam(USER_CCD).pw_uid
    gid = getgrnam(GROUP_CCD).gr_gid

    # get remote data requirements from plugin description
    remote_data = _get_remote_data_desc(plugin_dir)
    for plugin, data_spec in remote_data.items():

        # check if plugin  config dir exists, if not, create it
        plg_config_dir = os.path.join(plugin_dir, plugin, 'config/')
        # create_dir checks if directory exists and handles exceptions
        _create_dir(plg_config_dir, USER_CCD, GROUP_CCD, quiet=True)

        for dst, desc in data_spec.items():
            src = desc['src']
            extract_dir = ''
            try:
                extract_dir = desc['extract_dir']
            except KeyError:
                pass

            if not _ask_user("Download %s to %s/%s?" % (src, plg_config_dir, dst)):
                continue

            dst_dir = plg_config_dir
            dst_file = dst
            # create destination directories, if needed
            path_bits = dst.split('/')
            if len(path_bits) > 1:
                dst_dir = os.path.join(plg_config_dir, *path_bits[:-1])
                dst_file = path_bits[-1]
                _create_dir(dst_dir, USER_CCD, GROUP_CCD, quiet=True)
            try:
                _get_remote_data(dst_dir, dst_file, src)
            except Exception as e:
                _print_red('Failed to fetch %s: %s' % (src, e))
                continue
            else:
                _print_green('Saved %s to %s' % (src, os.path.join(plg_config_dir, dst)))

            if extract_dir:

                if extract_dir != '.':
                    extract_dir = os.path.join(plg_config_dir, extract_dir)
                else:
                    extract_dir = plg_config_dir

                if not _ask_user("Extract %s to %s?" % (os.path.join(plg_config_dir, dst), extract_dir)):
                    continue

                _create_dir(extract_dir, USER_CCD, GROUP_CCD, quiet=True)

                try:
                    _extract_data(os.path.join(plg_config_dir, dst), extract_dir)
                except Exception as e:
                    _print_red('Failed to extract: %s' % str(e))

        _chown_directory(plg_config_dir, uid, gid, quiet=True)


def _extract_data(path, to_directory='.'):
    """ from http://code.activestate.com/recipes/576714-extract-a-compressed-file/ THX """

    if path.endswith('.zip'):
        opener, mode = zipfile.ZipFile, 'r'
    elif path.endswith('.tar.gz') or path.endswith('.tgz'):
        opener, mode = tarfile.open, 'r:gz'
    elif path.endswith('.tar.bz2') or path.endswith('.tbz'):
        opener, mode = tarfile.open, 'r:bz2'
    else:
        raise ValueError("Could not extract `%s` as no appropriate extractor is found" % path)

    cwd = os.getcwd()
    os.chdir(to_directory)

    try:
        file = opener(path, mode)
        try:
            file.extractall()
        finally:
            file.close()
    finally:
        os.chdir(cwd)


def _get_remote_data_desc(plugin_dir):
    remote_data = {}

    # get current directory
    cwd = os.getcwd()

    sys.path.append('.')
    try:
        # change into plugin directory
        os.chdir(plugin_dir)

        plugin_subdirs = os.walk('.').next()[1]
        for plg in plugin_subdirs:
            try:
                plg_module_desc = __import__(
                    plg + '.main',
                    #os.path.join(plugin_dir, plg),
                    fromlist=['']
                ).desc
            except ImportError:
                # plugin does not have a description
                continue
            except AttributeError:
                # plugin does not have a description
                continue

            try:
                # get remote data field from plugin description
                # format:
                #       desc = {
                #       ...
                #           'remote_data': {
                #               'GeoLite2-City-CSV.zip': {
                #                   'src': 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City-CSV.zip',
                #                   'dst': '.',
                #                   'extract': True,
                #               },
                #               'GeoLite2-Country-CSV.zip': {
                #                   'src': 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip',
                #                   'dst': '.',
                #                   'extract': True,
                #               }
                #           }
                #       ...
                #       }
                remote_data[plg] = plg_module_desc['remote_data']
            except KeyError:
                # plugin description has no remote_data field
                continue
    finally:
        # change back into working directory
        os.chdir(cwd)

    return remote_data


def print_progress(count, blockSize, totalSize):
    percent = 0

    try:
        percent = float(count * blockSize) / float(totalSize)
        percent *= 100
    except ZeroDivisionError:
        pass

    sys.stdout.write('\rFetching data ... %d%%' % int(percent))
    sys.stdout.flush()


def _get_remote_data(dst_dir, dst_file, src):
    cwd = os.getcwd()
    tmp_dir = ''
    # make tempdir for downloads
    try:
        tmp_dir = tempfile.mkdtemp()  # create dir
        os.chdir(tmp_dir)

        # get resource
        urllib.urlretrieve(src, dst_file, reporthook=print_progress)
        print ''

        # copy resource to destination
        shutil.copy(dst_file, dst_dir)

    finally:
        # change back
        if cwd:
            os.chdir(cwd)

        if tmp_dir:
            shutil.rmtree(tmp_dir)  # delete directory


def _set_db_user_password(url, db_user, db_pwd):
    """
    set the database user password

    input:
        url     resource of database
        db_user user to set the password
        db_pwd  password to set

    output:
        return true if succeeded otherwise false

    """
    import sqlalchemy as sql

    try:
        logging.debug("connecting to database %s", url)
        engine = sql.create_engine(url, echo=False)
        conn = engine.connect()

        sql = "ALTER USER %s WITH ENCRYPTED PASSWORD '%s'"
        logging.debug(sql, db_user, "******")
        conn.execute("commit")
        conn.execute(sql % (db_user, db_pwd))

        conn.close()
    except Exception as err:
        logging.error("Failed to set database password:'%s'.", err)
        return False

    return True


def init_postgres_cluster():
    """
    Before PostgreSQL can function correctly the database cluster must be
    initialized by the postgres user
    """
    global db_init

    if arch and not db_init:
        logging.debug("Initializing database cluster .. ")
        try:
            sysloc = locale.getdefaultlocale()
            loc = '.'.join(sysloc)
        except TypeError:
            loc = "en_US.UTF-8"

        cmd = ["su", "postgres", "-c", "initdb --locale %s "
               "-D \'/var/lib/postgres/data\'" % loc]
        suc, _ = _execute_shell_cmd(cmd, error_output=False,
                                    success_output=False)
        db_init = suc

    _start_daemon("postgresql")


def setup_db():
    """
    create database and database user

    """
    global cfg
    SECTION = "Database"
    sys_user_db = "postgres"
    dbname = "recon"
    dbscheme = "postgresql+psycopg2"
    dburi = "127.0.0.1:5432"
    dbuser = "ccd"
    dbpwd = 'oRrmP'

    _print_section(SECTION)

    # set database scheme/dialect
    dbscheme = _ask_user("Enter database dialect",
                         default=dbscheme,
                         interactive=True)

    # create db as sys_user_db
    dbname = _ask_user("Enter database name",
                       default=dbname,
                       interactive=True)

    # first, check whether db exists, to do so, try to connect to
    # database
    sys.stdout.write("creating database %s.." % dbname)
    sys.stdout.flush()
    cmd = ["su", sys_user_db, "-c", "psql -d %s -c '\q'" % dbname]
    if not _execute_shell_cmd(cmd, error_output=False,
                              success_output=False)[0]:
        # create database
        cmd = ["su", sys_user_db, "-c", "createdb %s" % dbname]
        _execute_shell_cmd(cmd, error_output=False)
    else:
        _print_yellow()

    # set database location
    dburi = _ask_user("Enter database location",
                      default=dburi,
                      interactive=True)

    # create user
    dbuser = _ask_user("Enter database user",
                       default=dbuser,
                       interactive=True)

    # set password
    dbpwd = _ask_user("Enter database password",
                      default=dbpwd,
                      interactive=True)

    sys.stdout.write("creating database user %s.. " % dbuser)
    sys.stdout.flush()
#    cmd = [ "su", sys_user_db, "-c", "createuser -l -i -s -R %s" % dbuser ]
    cmd = ["su", sys_user_db, "-c",
           "psql -c \"CREATE USER %s WITH ENCRYPTED PASSWORD %s "
           "CREATEDB CREATEROLE;\"" % (dbuser, repr(dbpwd))
           ]
    if "already exists" in _execute_shell_cmd(cmd, error_output=False)[1]:
        _print_yellow()

    # store configuration in config file
    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "dialect", dbscheme)
        cfg.set(SECTION, "user", dbuser)
        cfg.set(SECTION, "password", dbpwd)
        cfg.set(SECTION, "location", dburi)
        cfg.set(SECTION, "database", dbname)


def _check_whether_callable(to_install):
    #to_install = packet[ARCH]
    if not to_install:
        return False

    cmd_check = ["which", to_install]
    succ = _execute_shell_cmd(cmd_check,
                              success_output=False,
                              error_output=False)[0]
    return succ

def _check_whether_installed(packet):
    if arch:
        to_install = packet[ARCH]
        if not to_install:
            return False, None

        # check whether packet installed
        cmd_check = ["pacman", "-Qs", to_install]

        # install packet
        cmd_install = ["pacman", "--noconfirm", "-S", to_install]

    elif ubuntu or kali:
        to_install = packet[DEBIAN]
        if not to_install:
            return False, None

        # check whether packet installed
        cmd_check = ["dpkg", "-l", to_install]

        # install packet
        cmd_install = ["apt-get", "install", "-y", to_install]

    elif debian:
        to_install = packet[DEBIAN]
        if not to_install:
            return False, None

        # check whether packet installed
        cmd_check = ["dpkg", "-l", to_install]

        # install packet
        cmd_install = ["aptitude", "install", "-y", to_install]

    else:
        sys.stderr.write("wrong operating system!")
        return False, None

    # execute check whether packet is installed. if so,
    # skip packet and continue
    succ = _execute_shell_cmd(cmd_check,
                              success_output=False,
                              error_output=False)[0]
    return succ, to_install, cmd_install


def install_os_packets(no_update=False):
    """
    install the required unix packets
    """
    if not _ask_user("Install required programs?"):
        return

    if not no_update:
        sys.stdout.write("Updating sources ... ")
        sys.stdout.flush()
        if debian:
            cmd_update = ["apt-get", "update"]
        elif arch:
            cmd_update = ["pacman", "-Syu", "--noconfirm"]
        else:
            sys.stderr.write("wrong operating system!")
            return

        succ = _execute_shell_cmd(cmd_update,
                                  success_output=False,
                                  error_output=False)[0]
        if not succ:
            _print_red()
        else:
            _print_green()

    for packet in packets:
        # check whether packet is already installed
        succ, to_install, cmd_install = _check_whether_installed(packet)

        sys.stdout.write("installing %s.. " % to_install)
        sys.stdout.flush()

        #if succ:
        #    try:
        #        if arch:
        #            succ = _check_whether_callable(packet[ARCH])
        #        else:
        #            succ = _check_whether_callable(packet[DEBIAN])
        #    except KeyError:
        #        return
        #    if succ:
        #        _print_yellow()
        #        continue

        # install
        _execute_shell_cmd(cmd_install, error_output=False,
                           success_output=False)

        # since packet manager do not return with errorcode > 0
        # in case of failed installation, we need to check
        # whether packet is successfully installed
        succ, _, _ = _check_whether_installed(packet)
        if not succ:
            _print_red()
        else:
            _print_green()


def start_daemons():
    """
    start all required background daemons

    """
    if not _ask_user("Start required daemons?"):
        return

    for d in daemons:
        if arch:
            _start_daemon(d[ARCH])
        elif debian:
            _start_daemon(d[DEBIAN])
        else:
            sys.stderr.write("wrong operating system!")
            return


def _start_daemon(daemon):
    """
    start the daemon. First try to start daemon via systemd. If this is not
    working, try /etc/init.d.

    input:
        daemon  name of the daemon to start

    """
    sys.stdout.write("starting %s.." % daemon)
    sys.stdout.flush()

    if arch:
        try:
            cmd = ["systemctl", "enable", daemon]
            _execute_shell_cmd(cmd, success_output=False, error_output=False)

            cmd = ["systemctl", "start", daemon]
            if _execute_shell_cmd(cmd, error_output=False)[0]:
                return
        except Exception as e:
            _print_red(to_print='Failed to enable/start daemon %s: %s' % (daemon, str(e)))

    elif debian:
        try:
            cmd = ["update-rc.d", daemon, "defaults"]
            _execute_shell_cmd(cmd, success_output=False, error_output=False)

            cmd = ["service", daemon, "start"]
            if _execute_shell_cmd(cmd, error_output=False)[0]:
                return
        except Exception as e:
            _print_red(to_print='Failed to enable/start daemon %s: %s' % (daemon, str(e)))

    _print_red()


def _execute_shell_cmd(cmd, success_output=True, error_output=True):
    """
    execute a shell command and print whether execution succeeded. Stdout is
    piped to dev/null, stderr is read to check whether execution was
    successfull.

    input:
        cmd             array that contains the shell command in subprocess.Popen
                        compatible notation
        success_output  boolean to indicate whether output should be printed on
                        success
        error_output    boolean to indicate whether output should be printed on
                        failure

    return:
        succ    indicate whether execution succeeded
        output  stderr + stdout as concatenated string

    """
    logging.debug("Executing '%s'..", " ".join(cmd))
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    p.wait()

    stderr = p.stderr.read()
    stdout = p.stdout.read()
    succ = False

    logging.debug(stderr)
    logging.debug(stdout)

    if p.returncode == 0:
        succ = True

        if success_output:
            _print_green()

    else:
        if error_output:
            logging.warning(stderr)
            _print_red()

    logging.debug("returncode %d", p.returncode)
    output = stderr + stdout
    return succ, output

def install_3rdParty():
    if not _ask_user("Install 3rdParty modules?"):
        return

    sys.stdout.write("module 3rdParty.. ")
    sys.stdout.flush()

    #right now only impacket
    cmd = "cd 3rdParty/impacket && "
    cmd_build = cmd + python_interpreter + " setup.py build"
    cmd_install = cmd + python_interpreter + " setup.py install"

    if os.system("%s>/dev/null" % cmd_build) == 0 and \
       os.system("%s>/dev/null" % cmd_install) == 0:
        _print_green()
    else:
        _print_red()


def install_ctools():
    if not _ask_user("Install ctools modules?"):
        return

    sys.stdout.write("module ctools.. ")
    sys.stdout.flush()

    cwd = os.getcwd()
    cmd = "cd ctools && "
    cmd_build = cmd + python_interpreter + " setup.py build"
    if debian:
        # see this: http://ubuntuforums.org/archive/index.php/t-1121501.html
        cmd_install = cmd + python_interpreter + " setup.py install --install-layout=deb"
    else:
        cmd_install = cmd + python_interpreter + " setup.py install"

    if os.system("%s>/dev/null" % cmd_build) == 0 and \
       os.system("%s>/dev/null" % cmd_install) == 0:
        _print_green()
    else:
        _print_red()

    os.chdir(cwd)


def install_recotak():
    if not _ask_user("Install recotak module?"):
        return

    sys.stdout.write("module recotak.. ")
    sys.stdout.flush()

    cwd = os.getcwd()
    cmd = "cd ccd/recotak && "
    cmd_build = cmd + python_interpreter + " setup.py build"
    cmd_install = cmd + python_interpreter + " setup.py install"

    if os.system("%s>/dev/null" % cmd_build) == 0 and \
       os.system("%s>/dev/null" % cmd_install) == 0:
        _print_green()
    else:
        _print_red()
    os.chdir(cwd)


def install_ccdClases():
    if not _ask_user("Install ccdClasses module?"):
        return

    sys.stdout.write("module ccdClasses.. ")
    sys.stdout.flush()

    cwd = os.getcwd()
    cmd = "cd ccd/modules && "
    cmd_build = cmd + python_interpreter + " setup.py build"
    cmd_install = cmd + python_interpreter + " setup.py install"

    if os.system("%s>/dev/null" % cmd_build) == 0 and \
       os.system("%s>/dev/null" % cmd_install) == 0:
        _print_green()
    else:
        _print_red()
    os.chdir(cwd)

def copy_socksy_config_files():
    global config_socksy
    if not _ask_user("Move socksy config to /etc?"):
        return

    # socksy
    config_socksy = os.path.join(ccd_dir, config_socksy)
    src = config_socksy
    dst = "/etc/socksy.conf"
    cmd = ["cp", src, dst]
    if _execute_shell_cmd(cmd, success_output=False):
        os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR)
        config_socksy = dst

def copy_ccd_config_files():
    global config, cert, cert_key
    BASE_DIR = "/etc/ccd"

    if not _ask_user("Move ccd config to /etc?"):
        return

    # ccd
    _create_dir(BASE_DIR, "root", "root")

    # ccd config
    config = os.path.join(ccd_dir, config)

    src = os.path.join(ccd_dir, config)
    dst = os.path.join(BASE_DIR, "ccd.conf")
    cmd = ["cp", src, dst]
    if _execute_shell_cmd(cmd, success_output=False):
        os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR)
        config = dst

    # cert
    src = cert
    dst = os.path.join(BASE_DIR, os.path.split(cert)[1])
    cmd = ["cp", src, dst]
    if _execute_shell_cmd(cmd, success_output=False):
        os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR)
        cert = dst

    # cert key
    src = cert_key
    dst = os.path.join(BASE_DIR, os.path.split(cert_key)[1])
    cmd = ["cp", src, dst]
    if _execute_shell_cmd(cmd, success_output=False):
        os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR)
        cert_key = dst

    if cfg:
        try:
            cfg.read(config)
            cfg.set("Connection", "cert", cert)
            cfg.set("Connection", "key", cert_key)
            with open(config, "w") as f:
                cfg.write(f)
        except:
            sys.stderr.write("Failed to update ccd configuration with "
                             "updated cert/key paths.")
            sys.stderr.flush()

def copy_socksy_init_script():
    if not _ask_user("Create socksy init script?"):
        return

    sys.stdout.write("copying socksy init script..")
    sys.stdout.flush

    if arch:
        src = "supply/socksy/socksy.service"
        dst = "/usr/lib/systemd/system/socksy.service"
        cmd = ["cp", src, dst]
        if _execute_shell_cmd(cmd, success_output=False):
            os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR)

    elif debian:
        src = "supply/socksy/socksy"
        dst = "/etc/init.d/socksy"
        cmd = ["cp", src, dst]
        if _execute_shell_cmd(cmd, success_output=False):
            os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)

    else:
        _print_red("Not available for your operating system!")
        return

    # we need to update the daemon service file with respect to the
    # config file passed at startup
    venv_option = ''
    if venv_dir and os.path.exists(venv_dir):
        venv_option = "--venv %s" % venv_dir
    with open(dst, "r") as f:
        content = f.read().format(
            python_interpreter=python_interpreter,
            socksy_location=os.path.join(ccd_dir,
                                         socksy_location),
            venv_option=venv_option,
            config_file=config_socksy)

    with open(dst, "w") as f:
        f.write(content)

    # update system
    if arch:
        cmd = ["systemctl", "daemon-reload"]
        _execute_shell_cmd(cmd)

    elif debian:
        cmd = ["update-rc.d", "socksy", "defaults"]
        _execute_shell_cmd(cmd)


def copy_ccd_init_script():
    if not _ask_user("Create ccd init script?"):
        return

    sys.stdout.write("copying ccd init script..")
    sys.stdout.flush

    if arch:
        src = "ccd/ccd/config/ccd.service"
        dst = "/usr/lib/systemd/system/ccd.service"
        cmd = ["cp", src, dst]
        if _execute_shell_cmd(cmd, success_output=False):
            os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR)

    elif debian:
        src = "ccd/ccd/config/ccd"
        dst = "/etc/init.d/ccd"
        cmd = ["cp", src, dst]
        if _execute_shell_cmd(cmd, success_output=False):
            os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)

    else:
        _print_red("Not available for your operating system!")
        return

    # we need to update the daemon service file with respect to the
    # config file passed at startup
    venv_option = ''
    if venv_dir and os.path.exists(venv_dir):
        venv_option = "--venv %s" % venv_dir
    with open(dst, "r") as f:
        content = f.read().format(
            python_interpreter=python_interpreter,
            ccd_location=os.path.join(ccd_dir,
                                      ccd_location),
            venv_option=venv_option,
            config_file=config)

    with open(dst, "w") as f:
        f.write(content)

    # update system
    if arch:
        cmd = ["systemctl", "daemon-reload"]
        _execute_shell_cmd(cmd)

    elif debian:
        cmd = ["update-rc.d", "ccd", "defaults"]
        _execute_shell_cmd(cmd)


def versiontuple(v):
        return tuple(map(int, (v.split("."))))


def create_venv():

    if os.path.exists(venv_dir):
        _print_yellow("%s already exists" % venv_dir)
        return

    base_dir = filter(lambda t: t, venv_dir.split('/'))
    base_dir = '/' + '/'.join(base_dir[:-1])
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    venv_cmd = ''
    for vc in venv_cmds:
        if _check_whether_callable(vc):
            venv_cmd = vc
            break

    if not venv_cmd:
        _print_red('virtualenv binary not found')
        return

    cmd = [venv_cmd, "--system-site-packages", "-p%s" % python_interpreter, venv_dir]
    _execute_shell_cmd(cmd, success_output=False)


def activate_venv():

    if not os.path.exists(venv_dir):
        _print_red("%s does not exists" % venv_dir)
        return

    global python_interpreter
    python_interpreter = os.path.join(venv_dir, "bin/python")
    activate_this_file = os.path.join(venv_dir, "bin/activate_this.py")
    execfile(activate_this_file, dict(__file__=activate_this_file))


def check_monitor():
    """
    some distros ship deprecated psutil modules, which breaks the monitoring module
    """
    SECTION = "Monitoring"
    _print_section(SECTION)

    if not _ask_user("Enable CPU/RAM monitor?"):
        return False

    print 'Checking if Monitoring can be enabled ...'
    try:
        import psutil
        if versiontuple(psutil.__version__) > versiontuple('0.6.0'):
            _print_green('Monitoring enabled')
            return True
        _print_red('Psutil version to old (%s, need >= 0.6.0), disabling monitor', psutil.__version__)
        return False
    except:
        _print_red('Psutil not found, disabling monitor')
        return False


if __name__ == "__main__":
    nothing = True
    db_init = False
    parser = argparse.ArgumentParser(
        description="prepare system to use ccd v%s" %
                    __version__
    )

    parser.add_argument("-venv",
                        action="store_true",
                        default=False,
                        help="create a virtual environment for the recotak server")

    parser.add_argument("-m",
                        action="store_true",
                        default=False,
                        help="install required python modules")

    parser.add_argument("-u",
                        action="store_true",
                        default=False,
                        help="setup user section")

    parser.add_argument("-no-update",
                        action="store_true",
                        default=False,
                        dest='nu',
                        help="do _not_ update packet sources")

    parser.add_argument("-os",
                        action="store_true",
                        default=False,
                        help="install required os packets")

    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        help="start required background daemons (e.g. postgres)")

    parser.add_argument("-v",
                        action="store_true",
                        default=False,
                        help="verbosity")

    parser.add_argument("-db",
                        action="store_true",
                        default=False,
                        help="create postgres database")

    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        help="setup logging configuration")

    parser.add_argument("-c",
                        action="store_true",
                        default=False,
                        help="setup connection configuration")

    parser.add_argument("-p",
                        action="store_true",
                        default=False,
                        help="setup plugin configuration")

    parser.add_argument("-f",
                        action="store_true",
                        default=False,
                        help="fetch plugin data")

    parser.add_argument("-sa",
                        action="store_true",
                        default=False,
                        help="setup ccd superadmin")

    parser.add_argument("-so",
                        action="store_true",
                        default=False,
                        help="setup socksy requirements")

    parser.add_argument("--dst",
                        default="",
                        help="destination directory to install recon to")

    parser.add_argument("--all",
                        action="store_true",
                        default=False,
                        help="activate all options")

    parser.add_argument("--no-confirm",
                        action="store_true",
                        default=False,
                        help="no questions to answer (use default instead)")

    args = parser.parse_args()

    print(__credits__)

    if args.all:
        args.m = True
        args.l = True
        args.db = True
        args.sa = True
        args.so = True
        args.d = True
        args.u = True
        args.p = True
        args.venv = True
        # this just takes way too long
        #args.f = True
        args.os = True
        args.c = True
        args.a = False
        nothing = False

    # does the user explicitly configuring ccd relevant stuff or only system
    # things
    configuring_recon = (args.c or
                         args.p or
                         args.l or
                         args.db or
                         args.u or
                         args.sa or
                         args.venv or
                         args.so)

    # verbosity
    if args.v:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)

    # no questions to user
    if args.no_confirm:
        no_confirm = True

    # install os packets
    if args.os:
        install_os_packets(no_update=args.nu)
        nothing = False

    # configure destination directory
    if args.dst:
        ccd_dir = args.dst

    if configuring_recon:
        # get information on where to copy recon base directory
        ccd_dir = _ask_user("Path to install recon to",
                            default=ccd_dir,
                            interactive=True)

        copy_recon()

        # init config parser
        config = os.path.join(ccd_dir, config)
        cfg = ConfigParser.RawConfigParser()

    if args.venv:
        venv_dir = _ask_user("Name of recotak virutal environment folder (will be placed in %s)" % ccd_dir,
                             default=venv_dir,
                             interactive=True)
        venv_dir = os.path.join(ccd_dir, venv_dir)
        create_venv()
        activate_venv()
        nothing = False
    else:
        venv_dir = ''

    # install python modules
    if args.m:
        install_extern_modules(mods)
        install_ctools()
        #install_3rdParty()
        install_ccdClases()
        install_recotak()
        nothing = False

    # create socksy requirements
    if args.so:
        copy_socksy_config_files()
        copy_socksy_init_script()
        create_socksy_user()
        create_socksy_dir()
        nothing = False

    # connection section
    if args.c:
        setup_connection()
        nothing = False

    # plugin section
    plugin_dir = ''
    if args.p:
        setup_plugins()
        nothing = False

    # plugin section
    if args.f:
        # scan plugins for additional remote data to be fetched
        get_remote_data(plugin_dir)
        nothing = False

    # setup logging configurations
    if args.l:
        setup_logging()
        nothing = False

    # create database
    if args.db:
        # postgres won't start without that
        # maybe we should add a dependency to the background deamons
        init_postgres_cluster()
        setup_db()
        nothing = False

    # user section
    if args.u:
        setup_user()
        nothing = False

    # superadmin
    if args.sa:
        setup_superadmin()
        nothing = False

    if args.d:
        nothing = False

    if nothing:
        parser.print_help()
        print
        _print_green('\nDocumentation: http://recotak.org/documentation/index.html\n')
        sys.exit(0)

    if cfg:
        # check if monitoring is supported
        cfg.add_section("Monitoring")
        if check_monitor():
            cfg.set("Monitoring", "activated", True)
        else:
            cfg.set("Monitoring", "activated", False)
            _print_red('Monitoring deactivated')

        # get config file information
        config = _ask_user("Path to ccd config file to store settings",
                           default=config,
                           interactive=True)

        if venv_dir and os.path.exists(venv_dir):
            cfg.add_section("Virtualenv")
            cfg.set("Virtualenv", "Path", venv_dir)

        _create_dir(os.path.dirname(config), USER_CCD, GROUP_CCD, quiet=True)
        with open(config, "wb") as f:
            cfg.write(f)

        # create ccd service files
        copy_ccd_config_files()
        copy_ccd_init_script()

    # start background daemons
    if args.d:
        # postgres won't start without that
        init_postgres_cluster()
        start_daemons()

    _print_green('\nDocumentation: http://recotak.org/documentation.html\n')
    _print_green('\nIn case this is a fresh installation, use the credentials stored in ./%s to connect to the recotak server\n' % REK_CRED)
