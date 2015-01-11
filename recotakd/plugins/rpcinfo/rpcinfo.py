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
import argparse
import sys
import ccdClasses as ccd
from datetime import datetime
from ctools import cUtil
from ctools import cRpc
import __builtin__
import logging
import logging.handlers
from ctools import cTuples

__plgname__ = "rpc_scanner"

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


def rpcinfo(target):
    ip, port = target
    try:
        rpc = cRpc.Rpc(ip)
        reply = rpc.call('PORTMAPPER', 2, 'DUMP', port, cRpc.PROTO['TCP'])
        yield (ip, port, reply)
    except Exception, e:
        logger.warning(e)
    raise StopIteration


class RpcScanner():
    def __init__(self,
                 args,
                 dbh=None):

        logger.debug('Init RpcScanner')
        opt = parse(args)
        # file containing RPC program
        if opt.fn_rpc:
            cRpc.RPC_PATH = opt.fn_rpc

        # check if rpc file is readable
        try:
            fd = __builtin__.openany(cRpc.RPC_PATH, "r")
            fd.close()
        except:
            print 'Error: Could not open RPC program number data base %s' % cRpc.RPC_PATH
            sys.exit(1)

        self.port = opt.port
        # database handle
        self.dbh = dbh

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
                                      prep_callback=rpcinfo,
                                      maxthreads=opt.nthreads,
                                      delay=opt.delay)
        self.tuples.start()

    def start(self):
        start = datetime.now()

        row_fmt = "{:>9}{:>8}{:>8}{:>8}{:>16}"

        for ip, port, reply in self.tuples.tuple_q:
            print '-' * len(ip)
            print ip
            print '-' * len(ip)
            print row_fmt.format('program', 'vers', 'proto', 'port', 'service')
            print ''
            for program in reply:
                print row_fmt.format(
                    str(program[0]),
                    str(program[1]),
                    cRpc.RPROTO[str(program[2])],
                    str(program[3]),
                    str(program[4])
                )
                if self.dbh:
                    br = ccd.RpcinfoResult(
                        ip=ip,
                        port=int(program[3]),
                        program=program[4],
                        program_id=int(program[0]),
                        version=int(program[1]),
                        protocol=cRpc.RPROTO[str(program[2])],
                    )
                    self.dbh.add(br)

        print 'Finished in %f seconds' % cUtil.secs(start)


def parse(args):
    parser = argparse.ArgumentParser(
        prog=__plgname__,
        description='rpcinfo makes an RPC call to an RPC server and reports what it finds.',
        epilog="""Examples:
        rpcinfo.plg -t 192.168.1.136
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
                        help="list of IPs or IP ranges to resolve, e.g. -t 192.168.1.0/24")
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
                        help='target port (default 111)',
                        dest='port',
                        default=111,
                        type=int
                        )
    parser.add_argument('-rpc',
                        help='File containing RPC numbers, '
                             'if the path does start with \'/\', '
                             'it is interpreted as absolute and not redirected into the user directory',
                        default='rpc',
                        dest='fn_rpc',
                        )

    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    return args
