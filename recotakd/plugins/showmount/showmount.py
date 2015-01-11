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
import sys
from datetime import datetime
from ctools import cUtil
import ccdClasses as ccd
import argparse
from ctools import cTuples
from ctools import cRpc
import __builtin__
import logging
import logging.handlers

__plgname__ = "showmount"

# logging
LOG = "/tmp/showmount.log"
FORMAT = '%(asctime)s - %(name)s - ' + \
    '%(levelname)s - %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


CRLF = '\r\n'


def showmount(target):
    ip = ''
    port = None
    try:
        ip, port = target
    except:
        ip = target
    dirs = []
    try:
        rpc = cRpc.Rpc(ip)
        # more comfy like this, because rpc does all the work of
        # getting port info n co
        if not port:
            dirs = rpc.call2('MOUNTD', 'EXPORT')
        else:
            # but this works as well
            dirs = rpc.call('MOUNTD', showmount.version, 'EXPORT', port, cRpc.PROTO['TCP'])
        yield (ip, port, dirs)
    except Exception, e:
        logger.debug(e)
    finally:
        if rpc:
            rpc.close()
    raise StopIteration


class Showmount():

    def __init__(self,
                 args,
                 dbh=None):

        logger.debug('Init %s' % __name__)

        # database handle
        self.dbh = dbh
        opt = self.parse(args)

        if opt.fn_rpc:
            cRpc.RPC_PATH = opt.fn_rpc

        # check if rpc file is readable
        try:
            fd = __builtin__.openany(cRpc.RPC_PATH, "r")
            fd.close()
        except:
            print 'Error: Could not open RPC program number data base %s' % cRpc.RPC_PATH
            sys.exit(1)

        showmount.version = 1

        try:
            ig_targets = cTuples.cInputGenerator(filename=opt.target_fn,
                                                 data=opt.targets,
                                                 maxthreads=opt.nthreads,
                                                 circle=False,
                                                 expand_cb=lambda t: cUtil.mkIP2(t,
                                                                                 ports=[opt.port],
                                                                                 noResolve=True
                                                                                 ),
                                                 )
        except cTuples.ENoInput:
            print 'Error: No Targets specified, please use the -t/T parameter to set target(s)'
            sys.exit(1)

        ig_targets.start()
        self.tuples = cTuples.cTuples(inputs=[ig_targets],
                                      prep_callback=showmount,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def parse(self, args):
        parser = argparse.ArgumentParser(
            prog=__plgname__,
            description='showmount  queries  the mount daemon on a remote host' +
            'for information about the state of the NFS server on that machine..',
            epilog="""Examples:
            showmount.plg -t 192.168.1.0/24
            """,
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument("-T",
                            dest='target_fn',
                            default='',
                            help="path to file with a newline seperated list of ips (or ranges or masks)," +
                                 " e.g -i targets.txt")
        parser.add_argument("-t",
                            dest='targets',
                            default=[],
                            nargs='+',
                            help="list of IPs or IP ranges to resolve, e.g. -t 8.8.8.0/24 82.165.197.1")

        parser.add_argument('-delay',
                            help='delay in between requests',
                            dest='delay',
                            default=0.0,
                            type=float
                            )
        parser.add_argument("-nt",
                            dest='nthreads',
                            help="number of threads to scan with (default 50)",
                            type=int,
                            default=50)

        parser.add_argument('-P',
                            help='target port (default as req. by rpcinfo)',
                            dest='port',
                            default=None,
                            type=int
                            )
        parser.add_argument('-rpc',
                            help='File containing RPC numbers, '
                                 'if the path does start with \'/\', '
                                 'it is interpreted as absolute and not redirected into the user directory',
                            default='rpc',
                            dest='fn_rpc',
                            )

        if not args:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args(args)

        return args

    def start(self):
        start = datetime.now()

        row_fmt = '{:30}{:}'

        for ip, port, dirs in self.tuples.tuple_q:
            if dirs:
                print '\nExport list for %s:' % ip
                for d in dirs:
                    groups = d[1]
                    for client in groups:
                        print row_fmt.format(d[0], client)
                        if self.dbh:
                            br = ccd.ShowmountResult(
                                ip=ip,
                                port=port,
                                export=d[0],
                                client=client,
                            )
                            self.dbh.add(br)

        print 'Finished in %f seconds' % cUtil.secs(start)
