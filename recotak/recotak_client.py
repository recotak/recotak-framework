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
python -c 'import sys; sys.exit(not (0x02070000 < sys.hexversion <\
        0x03000000))' 2>/dev/null && exec python "$0" "$@"
which python2.7 > /dev/null 2>&1 && exec python2.7 "$0" "$@"
echo "No appropriate python interpreter found." >&2
exit 1
":"""

import argparse
import os.path
import logging
import sys
import os

__credits__ = """
ooooooooo.   oooooooooooo   .oooooo.     .oooooo.   ooooooooooooo       .o.       oooo    oooo
`888   `Y88. `888'     `8  d8P'  `Y8b   d8P'  `Y8b  8'   888   `8      .888.      `888   .8P'
 888   .d88'  888         888          888      888      888          .8"888.      888  d8'
 888ooo88P'   888oooo8    888          888      888      888         .8' `888.     88888[
 888`88b.     888    "    888          888      888      888        .88ooo8888.    888`88b.
 888  `88b.   888       o `88b    ooo  `88b    d88'      888       .8'     `888.   888  `88b.
o888o  o888o o888ooooood8  `Y8bood8P'   `Y8bood8P'      o888o     o88o     o8888o o888o  o888o
"""


HOMEDIR = os.path.expanduser("~/.recon")
LOGDIR = os.path.join(HOMEDIR, "logs")
LOGFILE = os.path.join(LOGDIR, "client.log")
CONFDIR = os.path.join(os.path.expanduser('~'), '.recon/config/')
CONFFILE = os.path.join(CONFDIR, "client.conf")


###############################################################################
#                           logging
###############################################################################
logger = logging.getLogger("client")
logger.setLevel(logging.DEBUG)


def add_logging(debug=False):
    """ add rotating file handler """

    # write to file
    if not os.path.exists(LOGDIR):
        print("creating %s" % LOGDIR)
        os.makedirs(LOGDIR)
    else:
        print("existing %s" % LOGDIR)

    fh = logging.handlers.RotatingFileHandler(LOGFILE,
                                              maxBytes=20000000,
                                              backupCount=5)
    fh.setFormatter(logging.Formatter('<%(process)s, %(threadName)s, %(asctime)s> '
                                      '%(name)s (%(funcName)s) [%(levelname)s] '
                                      '%(message)s '))
    logger.addHandler(fh)

    if debug:
        print 'debug output enabled'
        # channel that prints to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        ch.setFormatter(logging.Formatter('%(name)s [%(levelname)s] %(message)s'))
        logger.addHandler(ch)

logging.getLogger("client.connection.ccdlib").setLevel(logging.DEBUG)
logging.getLogger("client.connection").setLevel(logging.INFO)
logging.getLogger("client.remote.category").setLevel(logging.WARNING)
logging.getLogger("client.main.window").setLevel(logging.DEBUG)
logging.getLogger("client.main.session").setLevel(logging.DEBUG)

###############################################################################
#                           client
###############################################################################

def activate_venv(venv_dir):

    if not os.path.exists(venv_dir):
        logger.error("%s does not exists" % venv_dir)
        print("ERROR: %s does not exists" % venv_dir)
        return

    activate_this_file = os.path.join(venv_dir, "bin/activate_this.py")
    execfile(activate_this_file, dict(__file__=activate_this_file))


def processArguments(args):
    global LOGDIR
    global LOGFILE
    global CONFDIR
    global CONFFILE

    parser = argparse.ArgumentParser(description="recotak client")
    parser.add_argument(
        'recotakd',
    )
    parser.add_argument(
        '-v', '--verbose',
        help='enable verbose output',
        default=False,
        action='store_true',
        dest='verbose'
    )
    parser.add_argument(
        '-a', '--account',
        help='login with <username>:<password>',
        default=None,
        dest='account'
    )
    parser.add_argument(
        '-p', '--project',
        help='set project <number>',
        default=0,
        type=int,
        dest='project'
    )
    parser.add_argument(
        '-c', '--create',
        help='process create config to create new wgroups/users and '
             'add all plugins',
        default=None,
        dest='create'
    )
    parser.add_argument(
        '-e', '--exec',
        help="/path/to/plugin parameter e.g. -e '/Plugins/scanner/dns"
             "/whois.plg 8.8.8.8'",
        default=None,
        dest='execute'
    )

    parser.add_argument(
        "-l", "--logs",
        help="change logging directory (default %s)" % LOGDIR)

    parser.add_argument(
        "-cnf", "--config",
        help="change config directory (default %s)" % CONFDIR)

    parser.add_argument("--venv",
                        help="overwrite virtual environment folder from config")

    parser.add_argument("--debug", "-d",
                        action="store_true",
                        help="enable debug output")

    if not args:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_known_args(args)[0]

    if args.logs:
        LOGDIR = args.logs
        LOGFILE = os.path.join(LOGDIR, "client.log")

    if args.config:
        CONFDIR = args.config
        CONFFILE = os.path.join(CONFDIR, "client.conf")

    return args.account, args.project, args.create,\
        args.execute, args.recotakd, args.venv, \
        args.debug


def chk(fatal):
    def chk_dec(func):
        def chk_wrap(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except errors.ClientError as e:
                logger.exception(e)
                logger.warning('Request: %s', ccdlib.pkt2str(e.request))
                logger.warning('Response: %s', ccdlib.pkt2str(e.response))
                print str(e)
            except Exception as e:
                logger.exception(e)
                print 'something went wrong ...'
            if fatal:
                sys.exit(1)
        return chk_wrap
    return chk_dec


def _get_uid_by_name(ses, name):
    pld = sendpacket(ses, op=ccdlib.OP_SHOWUSER, pld=dict(uid=None))[-1]
    for user in pld:
        if user["name"] == name:
            return int(user["uid"])
    raise errors.NotFoundError(message='user name: %s' % name)

def _add_user(ses, name, mail, password):
    """
    creates a new user and returns its uid. if user already in database return
    the uid.

    input:
        name    name of the new user
        mail    mail address of user
        password    password of the user

    output:
        uid     user id of the user

    """
    return int(ses.new_user(name, mail, password))

@chk(fatal=True)
def _get_or_add_user(ses, name, mail, password):
    try:
        return _add_user(ses, name, mail, password)
    except errors.AlreadyExistingError:
        print 'Warning: User %s already exists' % name
        return _get_uid_by_name(ses, name)

def _get_wid_by_name(ses, name):
    wgroups = workgroup.get_workgroups(ses, "all")
    for wgroup in wgroups:
        if wgroup["name"] == name:
            return int(wgroup["wid"])
    raise errors.NotFoundError(message='wgroup name: %s' % name)


def _add_wgroup(ses, name):
    """
    creates a new wgroup and returns its wid. if wgroup already in database
    return the wid.

    input:
        name    name of the new wgroup

    output:
        wid     user id of the wgroup

    """
    return int(workgroup.new_workgroup(ses, name))

@chk(fatal=True)
def _get_or_add_wgroup(ses, name):
    try:
        return _add_wgroup(ses, name)
    except errors.AlreadyExistingError:
        print 'Warning: workgroup %s already exists' % name
        return _get_wid_by_name(ses, name)


def _get_pid_by_name(ses, name):
    projects  = sendpacket(ses, op=ccdlib.OP_SHOWPROJ)[-1]
    for project in projects:
        if project["name"] == name:
            return int(project["pid"])
    raise errors.NotFoundError(message='project name: %s' % name)


def _add_project(ses, name, ptype="1", desc=""):
    """
    creates a new project and returns its pid. if project already in database
    return the pid.

    input:
        name    name of the new project
        ptype   type of the project
        desc    description of the project

    output:
        pid     user id of the project

    """
    return int(ses.new_project(name, ptype, desc))

@chk(fatal=True)
def _get_or_add_project(ses, name):
    try:
        return _add_project(ses, name)
    except errors.AlreadyExistingError:
        print 'Warning: project %s already exists' % name
        return _get_pid_by_name(ses, name)


def create_option(ses, addr, fn):
    """
    creates a user, project and workgroup and adds plugins to the workgroup
    and project. details are configured in a separate config file whichs file
    name is passed via fn

    input:
        ses     session object if already established
        addr    ip, port tuple the ccd listens to
        fn      name of the create config file

    """

    # start session
    if not ses:
        ses = Session(addr=addr, config=CONFFILE)
        if not ses.authenticateUser():
            die("failed to authenticate user", code=2)

    orig_stdout = sys.stdout
    sys.stdout = open('client.stdout', 'w')
    config = ConfigParser.ConfigParser()
    config.readfp(open(fn))

    # create user
    username = config.get('user', 'username')
    password = config.get('user', 'password')
    mail = config.get('user', 'mail')
    uid = _get_or_add_user(ses, username, mail, password)
    orig_stdout.write('user %s:%s (id %d)\n' %
                      (username, password, uid))

    # create workgroup
    wgroup = config.get('wgroup', 'wgname')
    wid = _get_or_add_wgroup(ses, wgroup)
    orig_stdout.write('workgroup %s (id %d)\n' %
                      (wgroup, wid))

    # add user to workgroup
    try:
        workgroup.workgroup_add_member(ses, wid, uid, 2)
        orig_stdout.write('added user to wgroup\n')
    except errors.AlreadyExistingError:
        orig_stdout.write('user already member of wgroup')
    except Exception as e:
        sys.stderr.write('could not add user %d to workgroup %d:%s' %
                         (uid, wid, str(e)))

    # create project
    ses = Session(addr=addr,
                  account=(username, ccdCrypto.hashPassword(password)),
                  config=CONFFILE)

    if not ses.authenticateUser():
        die("failed to authenticate user", code=2)

    projectname = config.get('project', 'pname')
    pid = _get_or_add_project(ses, projectname)
    orig_stdout.write('project %s (id %d)\n' %
                      (projectname, pid))

    ses.set_project(pid)

    plugin_ids = config.get('project', 'plugin_ids')
    if plugin_ids.rstrip() == "all":
        plugin_ids = ses.get_all_plugin_ids()
    else:
        plugin_ids = plugin_ids.split(',')
    orig_stdout.write('Adding Plugins:\n')
    for plg_id in plugin_ids:
        try:
            orig_stdout.write('\t%s\n' % plg_id)
            ses.project_add_plugin(pid, plg_id)
        except:
            pass

    orig_stdout.write('\n')
    orig_stdout.write('To start the client:\n\trecotak_client.py '
                      '-a %s:%s -p %d %s:%d\n' %
                      (username, password, pid, addr[0], int(addr[1])))
    orig_stdout.write('\n')
    sys.exit(0)

def execute_option(ses, addr, account, project, execute):
    """ execute plugin in case of --exec """
    if not account:
        die('No credentials', code=1)
    if not project:
        die('No project', code=1)

    logger.debug("Connecting... using account information")
    ses = Session(addr=addr,
                  account=account,
                  config=CONFFILE)
    if not ses.authenticateUser():
        die("failed to authenticate user", code=2)

    ses.set_project(project)

    argv = execute.split(' ')
    dirname = os.path.dirname(argv[0])
    basename = os.path.basename(argv[0])

    print("dirname=%s" % dirname)
    print("basedir=%s" % basename)
    changedir(ses, dirname)
    result = plg.execute(ses, basename, argv[1:])
    print result

    sys.exit(0)

if __name__ == "__main__":
    args = sys.argv[1:]
    account, project, create, execute, addr, venv, debug = processArguments(args)

    if venv:
        activate_venv(venv)
    else:
        import ConfigParser
        try:
            config = ConfigParser.RawConfigParser()
            config.read(CONFFILE)
            venv_dir = config.get("Virtualenv", "Path")
            activate_venv(venv_dir)
        except:
            pass

    try:
        import argcomplete_patched
    except ImportError:
        print '3rd Party modules not installed'
        print 'Searching for ./3rdParty'
        if os.path.exists('./3rdParty/argcomplete_patched'):
            sys.path.append('./3rdParty/argcomplete_patched')
        else:
            print('fatal: 3rd Party not found')
            sys.exit(1)

    try:
        import reco_client
    except ImportError:
        print 'Rekotak client modules not installed'
        print 'Searching for ./reco_client'
        if os.path.exists('./reco_client'):
            sys.path.append('./reco_client')
        else:
            print('fatal: reco_client not found')
            sys.exit(1)

    import logging.handlers
    import ConfigParser
    from reco_client.remote.category import changedir
    from reco_client.connection.comm import sendpacket
    from reco_client.core.session import Session
    from reco_client.core.session import die
    from reco_client.connection import ccdCrypto
    from reco_client.connection import ccdlib
    from reco_client.remote import plugin as plg
    from reco_client.remote import workgroup
    from reco_client.core.session import errors

    #errors.debug = debug

    add_logging(debug)

    print(__credits__)

    ses = None
    addr = addr.split(":")
    if len(addr) == 2:
        addr = (addr[0], int(addr[1]))
    else:
        die("invalid address to bind to!", code=2)

    if account:
        acc = account.split(":")
        if len(acc) == 2 and acc[0] and acc[1]:
            _user = acc[0]
            _pwd = ccdCrypto.hashPassword(acc[1])
        else:
            die("invalid account data!", code=2)

        logger.debug("Connecting... using account information")
        ses = Session(addr=addr,
                      account=(_user, _pwd),
                      config=CONFFILE)

        if not (create or execute):
            ses.start(project)

        else:

            if not ses.authenticateUser():
                die("failed to authenticate user", code=2)

            if project:
                ses.set_project(project)

    if execute:
        execute_option(ses, addr, (_user, _pwd), project, execute)

    if create:
        create_option(ses, addr, create)

    if not ses:
        logger.debug("Connecting... ")
        ses = Session(addr=addr, config=CONFFILE)
        ses.start()

    print("Exiting main thread")
    #FIXME just a workaround due to illegal file descriptor window working
    # damn error failures bugs
    os.kill(os.getpid(), 9)


#if __name__ == "__main__":
#    main(sys.argv[1:])
