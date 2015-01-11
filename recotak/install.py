#!/bin/sh
# -*- mode: Python -*-
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

import os
import sys
from getpass import getpass
import argparse
import imp
import stat
import shutil
import logging
import ConfigParser
import subprocess
from pwd import getpwnam
from grp import getgrnam

__author__ = "curesec"
__email__ = "ping@recotak.org"
__version__ = 0.5

__credits__ = """
ooooooooo.   oooooooooooo   .oooooo.     .oooooo.   ooooooooooooo       .o.       oooo    oooo
`888   `Y88. `888'     `8  d8P'  `Y8b   d8P'  `Y8b  8'   888   `8      .888.      `888   .8P'
 888   .d88'  888         888          888      888      888          .8"888.      888  d8'
 888ooo88P'   888oooo8    888          888      888      888         .8' `888.     88888[
 888`88b.     888    "    888          888      888      888        .88ooo8888.    888`88b.
 888  `88b.   888       o `88b    ooo  `88b    d88'      888       .8'     `888.   888  `88b.
o888o  o888o o888ooooood8  `Y8bood8P'   `Y8bood8P'      o888o     o88o     o8888o o888o  o888o
"""

config = "config/client.conf"
try:
    username = os.getenv("SUDO_USER")
    home_dir = "/home/" + username
except TypeError:
    home_dir = os.path.expanduser("~")

try:
    user_uid = int(os.getenv("SUDO_UID"))
except TypeError:
    user_uid = int(os.getuid())

try:
    user_gid = int(os.getenv("SUDO_GID"))
except TypeError:
    user_gid = int(os.getgid())

cli_dir = os.path.join(home_dir, ".recon")
def_cli_dir = os.getcwd()

bin_dst = '/bin'
venv_dir = "recotak_venv"
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


no_confirm = False


ext_dir = "./3rdParty"
ext_mods = [
    "argcomplete_patched",
]


COLOR_HEADER = "\033[95m"
COLOR_OKBLUE = "\033[94m"
COLOR_OKGREEN = "\033[92m"
COLOR_WARNING = "\033[93m"
COLOR_FAIL = "\033[91m"
COLOR_END = "\033[0m"


# to provide an installation from scratch, we need to install
# all required programs. at the moment, there are two distributions
# supported
ARCH = "arch"
DEBIAN = "debian"
packets = [
    dict(arch="python2", debian="python2.7-dev"),
    dict(arch="python2-pip", debian="python-pip"),
    dict(arch="python2-m2crypto", debian="python-m2crypto"),
    dict(arch="python2-crypto", debian="python-crypto"),
    dict(arch="python2-virtualenv", debian="python-virtualenv"),
]
mods = []


venv_cmds = [
    'virtualenv', 'virtualenv-2.7', 'virutalenv2'
]

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
        try:
            uid = int(user)
        except:
            uid = getpwnam(user).pw_uid

        try:
            gid = int(group)
        except:
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


def copy_recon_client_bin(bin_dst):
    logging.debug("copying recon_client.py to %s ..." % bin_dst)
    try:
        shutil.copy('recotak_client.py', bin_dst)
    except IOError as e:
        if e.errno == 13:
            # perm denied
            _print_red('need root to copy recon_client.py to %s' % bin_dst)


def copy_recon_client(cli_dir):
    logging.debug("copying recon client directories to %s.." % cli_dir)
    pwd = os.getcwd()
    #TODO no hardcoded directories
    srcs = ("config", "3rdParty", "reco_client", "recotak_client.py")
    dst = cli_dir
    copied_all = True

    # nothing to copy if destination directory is base directory
    if dst == pwd:
        logging.debug("destination=source, so skipping")
        return

    # create destination directory
    if not os.path.exists(dst):
        os.makedirs(dst)
    _chown_directory(dst, user_uid, user_gid, quiet=True)

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
            elif e.errno == 20:
                # not a dir
                shutil.copy(_src, _dst)
            else:
                raise(e)

    _chown_directory(cli_dir, user_uid, user_gid, quiet=True)
    if not copied_all:
        sys.exit(1)


def _chown_directory(directory, uid, gid, quiet=False):
    os.lchown(directory, uid, gid)
    for root, dirs, files in os.walk(directory):
        for d in dirs:
            path = os.path.join(root, d)
            if os.path.islink(path):
                continue
            if not quiet:
                print("chowning %s" % d)
            os.lchown(path, uid, gid)
            _chown_directory(path, uid, gid, quiet=quiet)

        for f in files:
            path = os.path.join(root, f)
            if os.path.islink(path):
                continue
            if not quiet:
                print("chowning %s" % f)
            os.lchown(path, uid, gid)


def install_3rdParty():
    if not _ask_user("Install 3rdParty modules?"):
        return

    sys.stdout.write("module 3rdParty.. ")
    sys.stdout.flush()

    cwd = os.getcwd()
    for mod in ext_mods:
        #right now only impacket
        cmd = "cd 3rdParty/%s && " % mod
        cmd_build = cmd + python_interpreter + " setup.py build"
        cmd_install = cmd + python_interpreter + " setup.py install"

        if os.system("%s>/dev/null" % cmd_build) == 0 and \
           os.system("%s>/dev/null" % cmd_install) == 0:
            _print_green()
        else:
            _print_red()
    os.chdir(cwd)


def install_client_modules():
    if not _ask_user("Install client modules?"):
        return

    sys.stdout.write("module reco_client ... ")
    sys.stdout.flush()

    cwd = os.getcwd()
    cmd = "cd reco_client && "
    cmd_build = cmd + python_interpreter + " setup.py build"
    cmd_install = cmd + python_interpreter + " setup.py install"

    if os.system("%s>/dev/null" % cmd_build) == 0 and \
       os.system("%s>/dev/null" % cmd_install) == 0:
        _print_green()
    else:
        _print_red()

    os.chdir(cwd)

def install_os_packets(no_update=False):
    """
    install the required unix packets
    """

    SECTION = "OS Packets"
    _print_section(SECTION)

    if not _ask_user("Install required programs?"):
        return

    if not no_update:
        sys.stdout.write("Updating sources ... ")
        sys.stdout.flush()
        if debian:
            cmd_update = ["apt-get", "update"]
        elif arch:
            cmd_update = ["pacman", "-Syu"]
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
        #    _print_yellow()
        #    continue

        # install
        _execute_shell_cmd(cmd_install,
                           error_output=False,
                           success_output=False)

        # since packet manager do not return with errorcode > 0
        # in case of failed installation, we need to check
        # whether packet is successfully installed
        succ, _, _ = _check_whether_installed(packet)
        if not succ:
            _print_red()
        else:
            _print_green()


def install_extern_modules(to_install):
    """ Checks whether python module is available. If not, install the module.

    Keyword arguments:
    to_install -- list of modules to install

    """

    SECTION = "External Python modules"
    _print_section(SECTION)

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


def setup_connection():
    SECTION = "Connection"
    _print_section(SECTION)

    global cfg, cert, cert_key
    cert = os.path.join(cli_dir, "connection/clicert.pem")
    cert_key = os.path.join(cli_dir, "connection/clikey.pem")
    ssl_version = 3
    ssl_enabled = False
    ccd_cert_fingerprint = "1FF0460E5E1D7662665279780EFC3D146E7A7195"

    # ssl enabled
    ssl_enabled = _ask_user("Enable SSL?",
                            default=ssl_enabled, interactive=True)

    if ssl_enabled:
        # cert
        cert = _ask_user("The connection to the ccd client is TLS encrypted. \n"
                         "Path to ccd client certificate",
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

        # ccd_cert_fingerprint
        ccd_cert_fingerprint = _ask_user("To authenticate the client, enter sha1 "
                                         "ccd_cert_fingerprint \n of the client certificate",
                                         default=ccd_cert_fingerprint, interactive=True)

    # store settings
    if cfg:
        # create section
        if not cfg.has_section(SECTION):
            cfg.add_section(SECTION)

        # store configuration
        cfg.set(SECTION, "cert", cert)
        cfg.set(SECTION, "key", cert_key)
        cfg.set(SECTION, "ssl_enabled", ssl_enabled)
        cfg.set(SECTION, "ssl_version", ssl_version)
        cfg.set(SECTION, "ccd_cert_fingerprint", ccd_cert_fingerprint)


def _check_whether_callable(to_install):
    #to_install = packet[ARCH]
    if not to_install:
        return False

    cmd_check = ["which", to_install]
    succ = _execute_shell_cmd(cmd_check,
                              success_output=False,
                              error_output=False)[0]
    return succ


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


if __name__ == "__main__":
    nothing = True
    parser = argparse.ArgumentParser(
        description="prepare system to use recotak client v%s" % (__version__))

    parser.add_argument("-v",
                        action="store_true",
                        default=False,
                        help="verbosity")

    parser.add_argument("-venv",
                        action="store_true",
                        default=False,
                        help="create a virtual environment for the recotak client")

    parser.add_argument("-no-update",
                        action="store_true",
                        default=False,
                        dest='nu',
                        help="do _not_ update packet sources")

    parser.add_argument("-os",
                        action="store_true",
                        default=False,
                        help="install required os packets")

    parser.add_argument("-m",
                        action="store_true",
                        default=False,
                        help="install required python modules")

    parser.add_argument("-c",
                        action="store_true",
                        default=False,
                        help="setup connection configuration")

    parser.add_argument("-iu",
                        default=False,
                        action='store_true',
                        help="setup recotak directory and copy files to %s" % cli_dir)

    parser.add_argument("-i",
                        default=False,
                        action="store_true",
                        help="install recon_client.py to %s" % bin_dst)

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
        args.os = True
        args.m = True
        args.c = True
        args.iu = True
        args.i = True
        args.venv = True
        nothing = False

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
        if not os.getuid() == 0:
            _print_red('Need root to install os packages')
        else:
            install_os_packets(no_update=args.nu)
            nothing = False

    if args.venv:
        venv_dir = _ask_user("Name of recotak virutal environment folder (will be placed in %s)" % cli_dir,
                             default=venv_dir,
                             interactive=True)
        venv_dir = os.path.join(cli_dir, venv_dir)
        create_venv()
        activate_venv()
        nothing = False
    else:
        venv_dir = ''

    # install python modules
    if args.m:
        if not os.getuid() == 0 and not venv_dir:
            _print_red('Need root to install python packages')
        else:
            install_extern_modules(mods)
            install_3rdParty()
            install_client_modules()
            nothing = False

    if args.iu:
        # get information on where to copy recon base directory
        cli_dir = _ask_user("Path to install recotak client to",
                            default=cli_dir,
                            interactive=True)

        copy_recon_client(cli_dir)
        def_cli_dir = cli_dir
        nothing = False

    if args.i:
        bin_dst = _ask_user("Path to install recotak_client.py binary to",
                            default=bin_dst,
                            interactive=True)

        copy_recon_client_bin(bin_dst)
        nothing = False

    if args.c or args.venv:
        # init config parser
        config = os.path.join(def_cli_dir, config)
        cfg = ConfigParser.RawConfigParser()

        # connection section
        setup_connection()
        nothing = False

    if nothing:
        parser.print_help()
        _print_green('\nDocumentation: http://recotak.org/documentation.html\n')
        sys.exit(1)

    if cfg:
        # get config file information
        config = _ask_user("Path to ccd config file to store settings",
                           default=config,
                           interactive=True)

        if venv_dir and os.path.exists(venv_dir):
            cfg.add_section("Virtualenv")
            cfg.set("Virtualenv", "Path", venv_dir)

        with open(config, "wb") as f:
            cfg.write(f)

    _print_green('\nDocumentation: http://recotak.org/documentation.html\n')
