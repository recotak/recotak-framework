#!/usr/bin/env python2

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
import threading
import Queue
import sys
from datetime import datetime
import logging
import socket
from ctools import cUtil
from ctools import cTuples
import argparse

import ccdClasses as ccd


__version__ = '0.1'
__author__ = 'curesec'


# logging
LOG = "/tmp/smtp_userenum.log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def testusername(target, username):
    logger.info('Trying %s on %s', username, target)
    reply = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(testusername.timeout)
        s.connect(target)

        # grab banner
        data = s.recv(1024)

        s.send("HELO a\r\n")
        data = s.recv(1024)

        if testusername.command == "VRFY":
            s.send("VRFY " + username + "\r\n")
        elif testusername.command == "EXPN":
            s.send("EXPN " + username + "\r\n")
        else:  # RCPT
            s.send("MAIL FROM:example@mail.com\r\n")
            data = s.recv(1024)
            s.send("RCPT TO:" + username + "\r\n")
        data = s.recv(1024)
        reply = data
    except socket.error as e:
        logger.debug("socket.error: " + str(e))
    finally:
        if s:
            s.close()

    if reply.startswith("2"):
        yield (target, username)
    raise StopIteration


class SmtpWorker(threading.Thread):
    def __init__(self, in_q, out_q, timeout=2):
        super(SmtpWorker, self).__init__()
        self.stopEvent = threading.Event()
        self.in_q = in_q
        self.out_q = out_q
        self.timeout = timeout

    def run(self):
        while not self.stopEvent.is_set():
            try:
                thost, command, user = self.in_q.get(True, 0.1)
                try:
                    if self.testusername(thost, command, user):
                        self.out_q.put((thost, command, user, True))
                    else:
                        self.out_q.put((thost, command, user, False))
                except Exception, e:
                    logger.debug(e)
                    self.out_q.put((thost, command, user, False))
                    # repeat?
                finally:
                    self.in_q.task_done()
            except Queue.Empty:
                continue

    def join(self, timeout=None):
        self.stopEvent.set()
        super(SmtpWorker, self).join()

    def testusername(self, thost, command, username):
        reply = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((thost[0], int(thost[1])))

            # grab banner
            data = s.recv(1024)

            s.send("HELO a\r\n")
            data = s.recv(1024)

            if command == "VRFY":
                s.send("VRFY " + username + "\r\n")
            elif command == "EXPN":
                s.send("EXPN " + username + "\r\n")
            else:  # RCPT
                s.send("MAIL FROM:example@mail.com\r\n")
                data = s.recv(1024)
                s.send("RCPT TO:" + username + "\r\n")
            data = s.recv(1024)
            reply = data
        except socket.error as e:
            logger.debug("socket.error: " + str(e))
        finally:
            if s:
                s.close()

        if reply.startswith("2"):
            return True
        return False


class SmtpUserEnum():
    def __init__(self, args, dbhandler=None):

        """ Initialise SMTP UserEnumr.

            dbhandler: handler to store data persistently (e.g. via ccd)
        """

        self.dbhandler = dbhandler
        self.tasks_waiting = 0
        self.in_q = Queue.Queue()
        self.out_q = Queue.Queue()
        self.smtp_workers = []
        self.usernames = []

        self.thosts     = []
        self.rport      = []
        self.command    = []
        self.userfile   = []
        self.timeout    = []
        self.hits       = []
        self.users      = []
        self.nthreads   = []

        self.parse(args)

    def parse(self, args):
        description = "### SMTP user enumeration ###\n" + \
                      "It is based on the SMTP commands: VRFY, EXPN, RCPT.\n" + \
                      "Results may be inaccurate (false positives) as not all SMTP servers act the same.\n" +\
                      "Furthermore, this script does not support StartTLS or authentication.\n" +\
                      "To inspect the server's resonse, use the -v verbosity switch.\n" +\
                      "Output of valid usernames are in the form of: [username]\n\n"
        epilog = """Examples:
            smtp_user_enum.plg -command ALL -U users.txt -t 192.168.1.136
            """

        parser = argparse.ArgumentParser(
            description=description,
            epilog=epilog,
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument("-command", action="store", dest="command", required=True, help="choose VRFY, EXPN, RCPT or ALL")
        parser.add_argument('-T',
                            help='files containing host:port entries',
                            default='',
                            dest='target_fn'
                            )
        parser.add_argument('-t',
                            help='target hosts',
                            default=[],
                            nargs='+',
                            dest='targets',
                            )
        parser.add_argument('-port',
                            help='target port (default 25)',
                            dest='port',
                            default=25,
                            type=int
                            )
        parser.add_argument('-delay',
                            help='delay in between requests',
                            dest='delay',
                            default=0.0,
                            type=float
                            )
        parser.add_argument('-u',
                            help='usernames',
                            default=[],
                            nargs='+',
                            dest='users',
                            )
        parser.add_argument('-U',
                            help='file containing one username per line',
                            default='',
                            dest='user_fn',
                            )
        parser.add_argument('-nt',
                            help='number of threads (default 100)',
                            dest='nthreads',
                            type=int,
                            default=100
                            )
        parser.add_argument('-to',
                            help='Server timeout (default 3s)',
                            dest='timeout',
                            type=int,
                            default=3
                            )
        parser.add_argument('-no_check',
                            help='disable host check',
                            action='store_true',
                            dest='no_check',
                            )

        if not args:
            parser.print_help()
            sys.exit(1)

        opt = parser.parse_args(args)

        testusername.command = opt.command
        testusername.timeout = opt.timeout

        if opt.command != "VRFY" and opt.command != "EXPN" and opt.command != "RCPT" and opt.command != "ALL":
            parser.print_help()
            print("command must either be 'VRFY', 'EXPN', 'RCPT' or 'ALL'")
            sys.exit(1)

        try:
            ig_targets = cTuples.cInputGenerator(data=opt.targets,
                                                 filename=opt.target_fn,
                                                 circle=False,
                                                 prepare_cb=cUtil.isUp,
                                                 expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                 ports=[opt.port],
                                                                                 noResolve=True,
                                                                                 ),
                                                 maxthreads=opt.nthreads
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        try:
            ig_users = cTuples.cInputGenerator(data=opt.users,
                                               filename=opt.user_fn,
                                               circle=True)
        except cTuples.ENoInput:
            print 'Error: No Usernames specified, please use the -u/U parameter to set usernames(s)'
            sys.exit(1)

        ig_targets.start()
        ig_users.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets, ig_users], prep_callback=testusername, delay=opt.delay)
        self.tuples.start()

    def start(self):

        start_time = datetime.now()

        for target, username in self.tuples.tuple_q:
            print('Found user %s@%s:%d' %
                  (username, target[0], int(target[1])))
                    # now, store result entry in data
            if self.dbhandler:
                br = ccd.SmtpUserEnumResult(
                    ip=target[0],
                    port=int(target[1]),
                    username=username,
                    command=testusername.command
                )
                self.dbhandler.add(br)

        self.tuples.join()
        print("\nfinished in %fs" % cUtil.secs(start_time))
