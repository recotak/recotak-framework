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
from __future__ import with_statement
import threading
import Queue
import argparse
import sys
import os
import time
import logging
import __builtin__
from datetime import datetime
from ctools import cUtil
from ctools import cComm
import ccdClasses as ccd

__plgname__ = "dir_bruteforce"
__version__ = 0.3

# logging
LOG = "/tmp/" + __plgname__ + ".log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)
#
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


QUEUE_TIMEOUT = 0.3
REQ_TIMEOUT = 3
SEPERATOR = ','

tested = []


class DirWorker(threading.Thread):
    def __init__(self, in_q, out_q, base_url, wait):
        """
        input:
            in_q:       task input queue (kind, path, depth)
            out_q:      result output queue (kind, code, path, depth)
            base_url:   base for bruteforce
            wait:       wait between requests (only per thread)
        """
        super(DirWorker, self).__init__()
        self.stopEvent = threading.Event()
        self.in_q = in_q
        self.out_q = out_q
        self.base_url = base_url
        self.wait = wait

    def join(self, timeout=None):
        self.stopEvent.set()
        super(DirWorker, self).join(timeout)

    def run(self):
        while not self.stopEvent.isSet():
            try:
                args = self.in_q.get(True, timeout=QUEUE_TIMEOUT)
                kind, path, depth = args
                code, reloc = self.__get_code(self.base_url, path)
                logger.debug('%s -> %d' % (
                    self.base_url.hostname + path,
                    code))
                # if HTTP OK -> put result in out queue
                if code == 200:
                    self.out_q.put((kind, code, path, depth + 1))
                else:
                    self.out_q.put((DirBruteforce.NONE, code, None, 0))
                self.in_q.task_done()
                time.sleep(self.wait)
            except Queue.Empty:
                continue

    def __getLoc(self, headers):
        """ Get the reloc header entry"""
        loc_key = None
        if ('Location' in headers):
            loc_key = "Location"
        elif ('location' in headers):
            loc_key = "location"
        else:
            return None
        return headers[loc_key]

    def __get_code(self, base_url, path="/"):
        """
        Request path from host using HEAD.
        Relocations are resolved.

        input:
            base_url: urlparse.SplitResult
            path:     path to check for

        """
        r = cComm.Comm.fetch(base_url, path, follow=True)
        return (int(r[0]), r[1])


class DirBruteforce():

    DIR, FILE, NONE = range(3)

    def __init__(self,
                 base_url,
                 dirs,
                 files,
                 known_paths,
                 recurse,
                 negative,
                 maxdepth,
                 nthreads,
                 wait,
                 dbhandler=None,
                 socks=False):
        logger.debug('Init DirBruteforce plugin')
        self.base_url = cComm.Mark(base_url)
        self.dirs = dirs
        self.files = files
        self.known_paths = known_paths
        self.recurse = recurse
        self.maxdepth = maxdepth
        self.wait = wait
        self.nthreads = nthreads
        self.in_q = Queue.Queue()
        self.found = []
        self.threads = []
        self.dbh = dbhandler

        print
        print 'Directory Bruteforcer v%f' % __version__
        print

    def make_new_paths(self, path, depth):
        parts = path.split('/')
        for d in self.dirs:
            if d in parts:
                continue
            if not d:
                continue
            new_path = os.path.join(path, d)
            if new_path == path or new_path == '/' or new_path in tested:
                return
            tested.append(new_path)
            logger.info('\tIncluding dir: %s' % new_path)
            self.in_q.put((DirBruteforce.DIR,
                           new_path,
                           depth + 1))
            self.tasks_waiting += 1
        for f in self.files:
            if f in parts:
                continue
            if not f:
                continue
            new_path = os.path.join(path, f)
            if new_path == path or new_path == '/' or new_path in tested:
                return
            tested.append(new_path)
            logger.info('\tIncluding file: %s' % os.path.join(path, f))
            self.in_q.put((DirBruteforce.FILE,
                           os.path.join(path, f),
                           depth + 1))
            self.tasks_waiting += 1

    def read_robots(self):

        print '-' * 80
        print 'Reading robots.txt ...'

        r = cComm.Comm.fetch(self.base_url, "/robots.txt", follow=True)
        robots = r[1]
        for line in robots.splitlines():
            line = line.lower()
            if 'disallow' in line or \
                    'allow' in line or \
                    'sitemap'in line:
                try:
                    path = line.split(':', 1)[1]
                    while path.startswith(' '):
                        path = path[1:]
                    if path:
                        try:
                            path.index('.')
                            if 'http' in path:
                                path = path.split('/', 3)[3]
                            print '[+] Got file path %s' % path
                            self.files.append(path)
                        except:
                            print '[+] Got directory path %s' % path
                            self.dirs.append(path)
                except:
                    pass

    def scan(self):

        start = datetime.now()

        # read robots.txt
        self.read_robots()

        self.out_q = Queue.Queue()

        self.tasks_waiting = 0
        for path in self.known_paths:
                self.make_new_paths(path, 1)

        self.threads = [DirWorker(self.in_q, self.out_q, self.base_url, self.wait)
                        for _ in range(self.nthreads)]
        for t in self.threads:
            t.setDaemon(True)
            t.start()

        self._printResults()

        print '-' * 80
        print 'Finished in %fseconds' % cUtil.secs(start)

    def _printResults(self):
        """ print results and write them to database. First we need to get the
            table from the database handler. Afterwards, we add every entry to
            that table
        """

        print '-' * 80
        print 'Searching Directories ...'

        while self.tasks_waiting > 0:
            try:
                kind, status, new_path, depth = \
                    self.out_q.get(True, timeout=QUEUE_TIMEOUT)
                self.tasks_waiting -= 1
                if status == 200:
                    print '[+] %s' % (new_path)
                if kind != DirBruteforce.NONE and self.dbh:
                    filename = new_path.split('/')[-1]
                    dr = ccd.DirBruteforceResult(
                        netloc=self.base_url.ident,
                        status=status,
                        path=new_path,
                        filename=filename,
                        info='TODO')
                    self.dbh.add(dr)
                if (self.recurse and
                        status == 200 and
                        kind == DirBruteforce.DIR and
                        depth < self.maxdepth):
                    self.make_new_paths(new_path, depth)
            except (KeyboardInterrupt, IOError, AssertionError), e:
                logger.debug(e)
                break
            except Queue.Empty:
                pass

        # stop threads
        for w in self.threads:
            w.join()


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description='dir_bruteforce.py checks HTTP response codes for several path- & file-names one one specified host',
        epilog='Ex: dir_bruteforce.py -nt 1 -t www.curesec.com -i input.txt -r -d 4 -w 2')

    parser.add_argument('-nt',
                        dest='nthreads',
                        type=int,
                        default=1,
                        help='Number of threads ex: -t 20 (default 1)')
    parser.add_argument('-t',
                        dest='base_url',
                        required=True,
                        help='Target host ex: -t www.curesec.com')
    parser.add_argument('-i',
                        dest='pathlist_fn',
                        required=True,
                        help='Path file, containing newline seperated paths ex: -i input.txt')
    parser.add_argument('-r',
                        dest='recurse',
                        action='store_true',
                        help='Recursively add new paths to search (default off)')
    parser.add_argument('-d',
                        dest='depth',
                        type=int,
                        default=0,
                        help='Maximum recursion depth (default 0)')
    parser.add_argument('-w',
                        dest='wait',
                        type=int,
                        default=1,
                        help='Wait x seconds between requests - only enforced per thread (default 2)')

    # print help and exit
    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    files = []
    dirs = []

    # read dirs and filenames
    if args.pathlist_fn:
        fd = None
        try:
            fd = __builtin__.openany(args.pathlist_fn, 'r')
        except:
            fd = open(args.pathlist_fn, 'r')

        for line in fd.read().splitlines():
            # if string contains a '.' -> assume its a filename
            # TODO ...
            try:
                line.index('.')
                files.append(line)
            # otherwise it is a directory
            except:
                dirs.append(line)

    return args.base_url, files, dirs, args.nthreads, args.recurse, args.depth, args.wait, None
