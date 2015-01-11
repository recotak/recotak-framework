#!/usr/bin/python

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
from ctools import cUtil
from datetime import datetime
import os
import re
import sys
import argparse
import logging
from ctools import cTuples
from ctools import cComm
import db_test
import ccdClasses as ccd
import __builtin__


__version__ = '0.1'
__author__ = 'feli'
__plgname__ = 'cureto'


# logging
LOG = "/tmp/" + __plgname__ + ".log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class config():
    def __init__(self, conf_file):
        self.var = {}
        fd = None
        try:
            fd = __builtin__.openany(conf_file, 'r')
        except Exception as e:
            print 'Error opening %s' % conf_file
            sys.exit(1)

        for l in fd.readlines():
            l = l.rstrip('\n')
            idx = l.find('#')
            if idx >= 0:
                l = l[0:idx].rstrip()
            if not l:
                continue
            k, v = l.split('=')
            self.var[k] = v.split(' ')

    def __getitem__(self, key, **args):
        if key in self.var.keys():
            return self.var[key]
        else:
            raise KeyError

    def __iter__(self):
        return iter(self.var)

    def keys(self):
        return self.var.keys()

    def values(self):
        return self.var.values()

    def items(self):
        return self.var.items()


class dbparser(object):

    """ Parser for nikto database files """

    def __init__(self, filename, expansions={}, filter_callback=None):

        """
        input:
            filename:           Name of database file
            filter_callback:    Callback to filter funtkion,
                                which will be applied to every line
         """

        self.filename = filename
        self.filter_cb = filter_callback
        self.expansions = expansions

    def _clean(self, line, cComment='#'):

        """ Removes cComments from line """

        has_cComment = line.find(cComment)
        if has_cComment < 0:
            if self.filter_cb:
                return self.filter_cb(line, has_cComment).rstrip()
            return line.rstrip()
        else:
            if self.filter_cb:
                return self.filter_cb(line, has_cComment).rstrip()
            return line[0:has_cComment].rstrip()

    def expand(self, line, pos=0):
        e = False
        for k, exp in self.expansions.items():
            idx = line.find(k)
            if idx > 0:
                e = True
                for e in exp:
                    eline = line.replace(k, e)
                    for l in self.expand(eline, pos + 1):
                        yield l
        if not e:
            yield line

    def lines(self):

        """ Iterates over non cComment lines of a db file """

        try:
            #db_file = codecs.open(self.filename, 'r', 'utf-8')
            db_file = __builtin__.openany(self.filename, 'r')
        except Exception, e:
            logger.error('Failed to open database. Exception %s' % e)
            raise StopIteration

        for line in db_file:
            cline = self._clean(line)
            if cline:
                if not self.expansions:
                    yield cline.encode('utf-8')
                else:
                    for l in self.expand(line, 0):
                        yield l.encode('utf-8')

        db_file.close()
        raise StopIteration


def expand(line, pos=0):
    if line[0] == '#':
        raise StopIteration
    e = False
    for k, exp in expand.expansions.items():
        idx = line.find(k)
        if idx > pos:
            e = True
            for e in exp:
                eline = line.replace(k, e)
                for l in expand(eline, pos + 1):
                    yield l
    if not e:
        yield line
    raise StopIteration


def cComments_allowed(line, has_cComment):
    if not line or line[0] == '#':
        return ''
    return line


def db_404str_filter(line, has_cComment):
    line = line[0:has_cComment].rstrip()
    m = re.match(line, '@CODE=')
    if m:
        return ''
    else:
        return line


# TODO
def db_404code_filter(line, has_cComment):
    line = line[0:has_cComment].rstrip()
    m = re.match(line, '@CODE=')
    if m:
        return line[6:]
    else:
        return ''


class cureto(object):

    def __init__(self,
                 args,
                 dbh=None):

        opt = parse(args)
        self.dbh = dbh
        self.dbpath = opt.dbpath
        # read config
        self.config = config(opt.config)
        # which tests to perform
        self.plugins = ['db_tests']
        self.fof = {}
        self.fof['okay'] = {}
        self.fof['okay']['response'] = ('200', )

        # ssl
        self.ssl = opt.ssl
        self.nossl = opt.nossl
        # TODO
        self.key = None
        self.crt = None

        # general config
        self.timeout = opt.timeout

        # load cCommon databases
        self.variables = (dbparser(os.path.join(self.dbpath, 'db_variables')).lines())
        self.expansions = {}
        for v in self.variables:
            k, exp = v.split('=')
            self.expansions[k] = exp.split()
        self.expansions['@RFIURL'] = ['http://cirt.net/rfiinc.txt?', ]
        # TODO, thats probably not how its supposed to be handled
        for k, v in self.config.items():
            self.expansions['@' + k] = v

        expand.expansions = self.expansions
        db_test.test.parked_strings = (dbparser(
            os.path.join(self.dbpath, 'db_parked_strings')
        ).lines())
        db_test.test.errcodes = (dbparser(
            os.path.join(self.dbpath, 'db_404_strings'),
            filter_callback=db_404code_filter).lines()
        )
        db_test.test.errstrings = (dbparser(
            os.path.join(self.dbpath, 'db_404_strings'),
            filter_callback=db_404str_filter).lines()
        )
        #self.outdated = (dbparser(self.dbpath + 'db_outdated').lines())

        cComm.Comm.SSL = opt.ssl
        cComm.Comm.NOSSL = opt.nossl

        cComm.Mark.MAX_CON = opt.maxcon
        cComm.Mark.FIX_PORT = opt.port
        cComm.Mark.TIMEOUT = opt.timeout

        def mark_wrapper(*args):
            mark = cComm.Mark(*args)
            if not mark.test:
                raise StopIteration
            yield mark
            raise StopIteration

        try:
            self.ig_targets = cTuples.cInputGenerator(data=opt.target,
                                                      filename=opt.target_fn,
                                                      circle=False,
                                                      expand_cb=mark_wrapper,
                                                      #prepare_cb=cComm.Mark,
                                                      maxthreads=opt.nthreads
                                                      )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        try:
            self.ig_tests = cTuples.cInputGenerator(data=[],
                                                    filename=os.path.join(self.dbpath, 'db_tests'),
                                                    circle=True,
                                                    expand_cb=expand,
                                                    prepare_cb=lambda t: t.rstrip(),
                                                    maxthreads=opt.nthreads
                                                    )
            #self.ig_tests.setDaemon(True)
        except cTuples.ENoInput:
            print 'Error: No test database specified, please set -dbpath'
            sys.exit(1)

    def scan(self):
        self.results = {}

        start = datetime.now()
        self.tuples = cTuples.cTuples(inputs=[self.ig_targets, self.ig_tests], prep_callback=db_test.test)
        #self.tuples.setDaemon(True)
        self.tuples.start()
        self.ig_tests.start()
        self.ig_targets.start()

        for status, mark, result in self.tuples.tuple_q:
            if status:
                try:
                    self.results[mark.ident].append(result)
                except KeyError:
                    self.results[mark.ident] = []
                    self.results[mark.ident].append(result)
                    self._add_mark(mark)
                message, nikto_id, request, response, osvdb, method, uri = result
                self._add_vulnerability(
                    mark,
                    message,
                    nikto_id,
                    request,
                    response,
                    osvdb,
                    method,
                    uri
                )
        self.tuples.join()

        print 'Finished in %f seconds' % cUtil.secs(start)

    def _add_mark(self, mark):
        print '-' * 80
        print '+ Target IP:\t\t%s' % mark.ip
        print '+ Target Hostname:\t%s' % mark.hostname
        print '+ Target Port:\t\t%s' % mark.port
        print '+ Target Banner:\t\t%s' % mark.banner
        print '-' * 80
        try:
            if self.dbh:
                logger.info('Adding FingerprintResult to Database')
                drr = ccd.FingerprintResult(
                    ip=mark.ip,
                    fqdn=mark.fqdn,
                    port=mark.port,
                    banner=mark.banner
                )
                self.dbh.add(drr)
        except Exception, e:
            logger.error('Warning: Failed to add Vulnerability to database')
            logger.error(e)

    def _add_vulnerability(self,
                           mark,
                           message,
                           nikto_id,
                           request,
                           response,
                           osvdb=0,
                           method='GET',
                           uri='/'):

        #self.results.append((mark, message, nikto_id, request, response, osvdb, method, uri))
        print '+ OSVDB-%s: %s: %s' % (osvdb, uri, message)
        try:
            if self.dbh:
                logger.info('Adding DirscanResult to Database')
                drr = ccd.DirscanResult(
                    int(osvdb),
                    uri,
                    message,
                    mark.ip,
                    int(mark.port),
                    fqdn=mark.hostname,
                )
                self.dbh.add(drr)
        except Exception, e:
            logger.error('Warning: Failed to add Vulnerability to database')
            logger.error(e)


def parse(args):
    """ parse cmd line options sys.argv[1:].
        Also checks if provided options are valid.

        Input:
            args        cmd line without argv[0]
            rootpath    path to be prepanded to paths

        Output:
            parsed args
    """

    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description="Directory scanner",
        epilog=
        """Examples:
        cureto.plg -t www.curesec.com
        cureto.plg -T hosts.txt
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-t',
                        help='Target hostnames[:port] or ips[:port].',
                        dest='target',
                        nargs='+',
                        )
    parser.add_argument('-T',
                        help='Files containing target hostname[:port] or ip[:port]',
                        dest='target_fn',
                        nargs='+',
                        )
    parser.add_argument('-timeout',
                        help='Target timeout',
                        dest='timeout',
                        type=int,
                        default=30,
                        )
    parser.add_argument('-config',
                        help='Path to config file',
                        default='cureto.conf'
                        )
    parser.add_argument('-dbpath',
                        help='Path to database directory',
                        default='databases'
                        )
    parser.add_argument('-port',
                        help='Target port to use if not specified along with target',
                        type=int,
                        default=0,
                        )
    parser.add_argument('-maxcon',
                        help='Maximum parallel connections per host (default: unlimited)',
                        type=int,
                        default=0,
                        )
    parser.add_argument('-nt',
                        help='Maximum number of threads to scan with, each host gets a new thread',
                        dest='nthreads',
                        default=10,
                        type=int
                        )
    parser.add_argument('-ssl',
                        help='Force ssl connection',
                        dest='ssl',
                        action='store_true',
                        default=False
                        )
    parser.add_argument('-nossl',
                        help='Force plain http connection',
                        dest='nossl',
                        action='store_true',
                        default=False
                        )

    # print help if no cmd line parameters are provided
    if not args:
        parser.print_help()
        sys.exit(1)

    # parse arguments
    opt = parser.parse_args(args)

    # we need at least one targetname to work with
    if not (opt.target_fn or opt.target):
        parser.print_help()
        print 'Please specify at least one targetname via -T or -t'
        sys.exit(1)

    return opt

if __name__ == '__main__':
    opt = parse(sys.argv[1:])

    cComm.Comm.SSL = opt.ssl
    cComm.Comm.NOSSL = opt.nossl

    config = config('./config/nikto.conf')

    # load cCommon databases
    variables = (dbparser(os.path.join(opt.dbpath, 'db_variables')).lines())
    expansions = {}
    for v in variables:
        k, exp = v.split('=')
        expansions[k] = exp.split()
    # TODO, thats probably not how its supposed to be handled
    for k, v in config.items():
        expansions['@' + k] = v
    expand.expansions = expansions

    cComm.Mark.MAX_CON = opt.maxcon
    cComm.Mark.FIX_PORT = opt.port
    ig_targets = cTuples.cInputGenerator(data=opt.target,
                                         filename=opt.target_fn,
                                         circle=False,
                                         prepare_cb=cComm.Mark,
                                         maxthreads=opt.nthreads
                                         )
    ig_targets.start()
    ig_tests = cTuples.cInputGenerator(filename='db_tests',
                                       circle=True,
                                       expand_cb=expand,
                                       maxthreads=opt.nthreads
                                       )
    ig_tests.start()
    tuples = cTuples.cTuples(inputs=[ig_targets, ig_tests], prep_callback=db_test.test)
    tuples.start()

    for status, mark, test in tuples.tuple_q:
        #print test
        if status:
            print mark.ident
            print test
    tuples.join()
