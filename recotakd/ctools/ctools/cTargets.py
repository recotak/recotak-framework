"""
This module generates scan targets (tuples of ip,port).
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

"""

import socket
import threading
import multiprocessing
import struct
import logging
from random import randint, uniform
from time import sleep
from ctools import getNetmask, isIP, isDomain
import os.path, os
import argparse
import sys
import signal

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
logger.addHandler(logging.NullHandler())

# socket timeout fuer host check
TIMEOUT = 2

# type of targets
TYPE_IP = 0x01
TYPE_IP_PORT = 0x02
TYPE_RANGE = 0x03
TYPE_MASK = 0x04

WAIT_APPEND = 0.8

PRETARGETS = "pretargets"
TARGET = "targets"
MAX_FAILS = 10
TMP = "/tmp"
THREADS = 250
SUBSIZE = 1

def _sigterm_handler(signum, frame):
    """ commit suicide """
    logger.warning("handling SIGINT. shutting down..")
    os.killpg(0, signal.SIGTERM)
    sys.exit()

class TargetGenerator(object):

    def __init__(self,
                 # list of target ips, netmasks, ranges or domain names
                 hosts,
                 # ports to be used, if not specified via target:port
                 ports,
                 # output file for generated targets
                 output,
                 # file containing target ips, netmasks, ranges or domain names
                 host_fn,
                 # callback to check if hosts are up (e.g. targets.check or
                                                      # targets.check_ssl)
                 check_hosts=None,
                 # size of subnet to shuffle
                 subnet_size=SUBSIZE,
                 # directory to store pretarget file
                 tmp_dir=TMP,
                 # number of threads to use for target generation
                 threads=THREADS):
        self.hosts = hosts
        self.ports = ports
        if not self.ports:
            self.ports = [-1]
        self.output_fn = output
        self.tmp_dir = tmp_dir
        self.max_threads = threads
        self.host_fn = host_fn
        self.subnet_size = subnet_size
        self.check_hosts = check_hosts

        signal.signal(signal.SIGINT, _sigterm_handler)

    def get(self):
        return self.output_fn.get()

    def generate(self, blocking=True):
        """
        set up the queue with targets. a target is a tuple
        (ip, port). function resolves hostnames to ips. result
        is shuffled.

        input:
            blocking    if blocking, wait for generation to finish

        output:
            num         the amount of targets generated

        """
        logger.info("generating targets..")

        counter = multiprocessing.Value('l', 0)
        pretargets_fn = os.path.join(self.tmp_dir, PRETARGETS)
        logger.debug("pretargets:%s", pretargets_fn)

        # files
        pretargets_f_w = open(pretargets_fn, "w")
        pretargets_f_r = open(pretargets_fn, "r")
        if self.output_fn:
            if isinstance(self.output_fn, str):
                targets_f_w = open(self.output_fn, "w")
            else:
                targets_f_w = self.output_fn
                targets_f_w.name = 'queue'
        else:
            targets_f_w = sys.stdout

        # locks
        lock_write_pretargets = multiprocessing.Lock()
        lock_read_pretargets = multiprocessing.Lock()
        lock_write_targets = multiprocessing.Lock()

        try:
            # First, start the preprocessor, that iterates over
            # the users' input and the host file names and counts
            # the targets.
            logger.info("generating pretargets (%s)..", pretargets_f_w.name)
            _prepareTargets(pretargets_f_w, self.hosts, self.host_fn)

            # Second, start the generator thread, that generates every
            # single target (IP-Port tuple). It also resolves dns names
            # and randomises the list.
            logger.info("generating targets (%s) with %d threads..",
                        targets_f_w.name, self.max_threads)
            generator = threading.Thread(target=self._generate_targets,
                                         args=(
                                             (pretargets_f_w, lock_write_pretargets),
                                             (pretargets_f_r, lock_read_pretargets),
                                             (targets_f_w, lock_write_targets),
                                             self.check_hosts,
                                             counter
                                         ))
            generator.start()

            if blocking:
                generator.join()

        finally:
            if blocking:
                pretargets_f_w.close()
                pretargets_f_r.close()
                if not targets_f_w == sys.stdout:
                    targets_f_w.close()

        if blocking:
            # delete temporary files
            try:
                os.remove(pretargets_f_w.name)
            except Exception as err:
                logger.error("Failed to delete pretargets:'%s'", err)

        sleep(1.0)

        return counter, generator

    def _generate_targets(self, pretargets_w, pretargets_r , targets, check_hosts, counter):
        logger.info('generating target list')
        thread_list = []
        try:
            while len(thread_list) < self.max_threads:
                thread = threading.Thread(
                    target = _generateTargetList,
                    args = (
                        self.ports,
                        pretargets_w,
                        pretargets_r,
                        targets,
                        self.subnet_size,
                        check_hosts,
                        counter
                    )
                )
                thread_list.append(thread)
                thread.start()
        except (KeyboardInterrupt, Exception) as err:
            logger.error("Failure while generating:'%s'", err)
            for thread in thread_list:
                thread.terminate()

        thread_list = filter(lambda t: t.is_alive(), thread_list)
        for thread in thread_list:
            thread.join()


def __append(f, item, check_host, lock):
    sleep(uniform(0, WAIT_APPEND))

    toappend_str = ",".join(map(str, item))
    if toappend_str[-3:] == ',-1':
        toappend_str = toappend_str[:-3]
    try:
        if isinstance(f, file):
            if lock and not lock.acquire():
                logger.error("Error while acquiring lock to access:'%s'", f)

            logger.debug('appending %s' % (toappend_str))
            f.write("%s\n" % toappend_str)
            f.flush()
            if lock:
                lock.release()
        else:
            # resources are limited by maxsize of queue
            f.put((item[0], int(item[1])))
            pass

    except ValueError:
        """ e.g. I/O operation on closed file"""
        pass


def check_ssl(target):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    con_open = False
    try:
        sock = ssl.wrap_socket(sock)
        sock.connect(target)
        con_open = True
    except Exception, e:
        logger.debug('Could not connect to %s:%d -> %s' % (target[0], int(target[1]), e))
    finally:
        sock.close()
        return con_open


def check(target):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    con_open = False
    try:
        sock.connect((target[0], int(target[1])))
        con_open = True
    except Exception, e:
        logger.debug('Could not connect to %s:%d -> %s' % (target[0], int(target[1]), e))
    finally:
        sock.close()
        return con_open


def __append_thread(f, item, check_host=None, lock=None):
    """ appends an item to a list """

    if check_host:
        if not check_host(item):
            return

    t = threading.Thread(target=__append, args=(f, item, check_host, lock))
    t.start()


def _prepareTargets(output_f, hosts, host_fn=None):
    """ extracts ip-ranges, netmasks und single ips or domains from hosts
        list and/or file and puts them into a list; counts total no of targets.

        input:
            hosts       the list of hosts (e.g. ["cureblog.de",
                        "friendface.co.uk"])
            host_fn     file to read from. If fn is set, hosts will be read from
                        file and merged with hosts.

    """
    EOF = False
    host = ""
    host_f = None

    # first, we try to open the file
    if host_fn:
        host_f = open(host_fn,"r")

    try:
        while True:

            # If we successfully opened the file, lets get the
            # hosts. If no more hosts are available since EOF,
            # continue with hosts list input.
            if host_f:
                host = host_f.readline().rstrip()
                if not host:
                    EOF = True

            # take hosts list input
            if EOF or not(host_fn and host_f):
                if not hosts:
                    break
                try:
                    host = hosts.pop()
                except IndexError:
                    """ poping from empty list is not possible """
                    logger.debug("Hostfile is empty.")
                    break

            # Now, we check whether the hosts is a netrange, a netmask
            # or just an IP.
            entry = None
            if not entry and  "-" in host:
                h = host.split("-")
                ip_start = h[0]
                ip_end = h[1]

                if isIP(ip_start) and isIP(ip_end):
                    entry = [TYPE_RANGE, ip_start, ip_end]

            if not entry and "/" in host:
                h = host.split("/")
                try:
                    bit = int(h[1])
                except ValueError:
                    logger.warning("Invalid prefix declared: %s ", host)
                    continue

                ip = h[0]
                if isIP(ip):
                    entry = [TYPE_MASK, ip, bit]

            if not entry and ":" in host:
                h = host.split(":")
                ip = h[0]
                port = h[1]
                if isIP(ip):
                    entry = [TYPE_IP_PORT, ip, port]

            if not entry and (isIP(host) or isDomain(host)):
                entry = [TYPE_IP, host]

            if entry:
                line = ",".join(map(str, entry))
                output_f.write("%s\n" % line)
                logger.debug('Added: ' + line)
            else:
                logger.warning("invalid host:'%s'", host)

        output_f.flush()
    except Exception as err:
        logger.error("Failure while generating pretargets:'%s'", err)
    finally:
        if host_f:
            host_f.close()

    logger.debug("pre-target preprocessor has finished.")

def _adjustSize(start, end, size, pretargets_w):
    """
    adjusts size to not be greater than size.
    input:
        start       ip as long(!) to start
        end         ip as long(!) to originally end
    output:
        start       ip as long(!)
        end         new end as long(!)

    """
    if end-start > size:
        # extract subnet
        old_start = start
        old_end = end
        start = randint(start, end-size)
        end = start+size

        # recall for new subnets
        if not start == old_start:
            future_start2 = socket.inet_ntoa(struct.pack(">I", old_start))
            future_end2 = socket.inet_ntoa(struct.pack(">I", start-1))
            __append_thread(pretargets_w[0],
                     [TYPE_RANGE, future_start2, future_end2],
                     lock=pretargets_w[1])

        if not end == old_end:
            future_start1 = socket.inet_ntoa(struct.pack(">I", end+1))
            future_end1 = socket.inet_ntoa(struct.pack(">I", old_end))
            __append_thread(pretargets_w[0],
                     [TYPE_RANGE, future_start1, future_end1],
                     lock=pretargets_w[1])

    return start, end, size+1


def _generateTargetList(ports, pretargets_w, pretargets_r, targets_w,
                       size, check_hosts, target_counter):
    """
    create a list with all targets. To do so, it takes the list of
    pretargets targets and generates for every item its IPs. A prepared
    item can be a netrange, a net mask oder a single ip.

    input:
        ports           list of ports, the targets a scanned at
        pretargets_w    tuple containing file object to write pretargets
                        to and lock to access file with
        pretargets_r    tuple containing file object to read pretargets
                        from and lock to access file with
        targets_w       tuple containing file object to write targets to
                        and lock to access file with
        size            size of subnet to extract
        target_counter  target counter to increase for new generated target

    """
    fail_counter = 0

    while True:
        # get pretarget
        with pretargets_r[1]:
            try:
                item = pretargets_r[0].readline().rstrip()
            except Exception, e:
                break

        if not item:
            fail_counter += 1
            if fail_counter >= MAX_FAILS:
                break
            sleep(0.5)
            continue

        fail_counter = 0
        item = item.split(",")
        t = int(item[0])
        entry = item[1:]

        # classic ip e.g. '127.0.0.1'
        if t == TYPE_IP:
            ip = entry[0]
            num = 0
            for p in ports:
                __append_thread(targets_w[0], [ip, p], check_hosts, targets_w[1])
                num += 1

        elif t == TYPE_IP_PORT:
            num = 1
            ip = entry[0]
            port = entry[1]
            __append_thread(targets_w[0], [ip, port], check_hosts, targets_w[1])

        # bit mask e.g. '127.0.0.1/16'
        elif t == TYPE_MASK:
            net = entry[0]
            bit = entry[1]
            start, end = getNetmask(net, int(bit))

        # ip rage e.g. '127.0.0.1-127.0.0.16'
        elif t == TYPE_RANGE:
            start_dotted = entry[0]
            end_dotted = entry[1]
            start = struct.unpack(">I", socket.inet_aton(start_dotted))[0]
            end = struct.unpack(">I", socket.inet_aton(end_dotted))[0]

        # invalid type
        else:
            logger.warning("Got invalid pre-target type while generating "
                           "target list:'%s'", t)
            continue

        if not t == TYPE_IP and not t == TYPE_IP_PORT:
            # get start end end ip and add to target file
            start, end, num = _adjustSize(start, end, size, pretargets_w)
            ip = start
            while ip <= end:
                ip_dotted = socket.inet_ntoa(struct.pack(">I", ip))
                #print ip_dotted
                for p in ports:
                    __append_thread(targets_w[0], [ip_dotted, p], check_hosts, targets_w[1])

                ip += 1

        # increase counter
        target_counter.value += num

        if __name__ == "__main__":
            sys.stdout.write("\rtarget count:%d" % target_counter.value)
            sys.stdout.flush()

    logger.debug("target generator finished. bye.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                prog="python2.7 targets.py",
                description="target generator v%s" % __version__
             )
    parser.add_argument("-o",
                        help="file to output targets to")
    parser.add_argument("-i",
                        help="input file")
    parser.add_argument("--hosts", default="",
                        help="hosts to scan (maybe in addition to -i)")
    parser.add_argument("--threads", default=THREADS, type=int,
                        help="the amount of threads to use")
    parser.add_argument("--ports", default="80",
                        help="ports to scan at the targets")
    parser.add_argument("--subnet", default=1, type=int,
                        help="the subnet size to extract targets with")
    parser.add_argument("--tmp", default="/tmp",
                        help="the temporary directory to use")

    if not sys.argv[1:]:
        parser.print_help()
        sys.exit(0)
    try:
        args = parser.parse_args()
        ports = map(int, args.ports.split(","))
        hosts = args.hosts.split(",")
    except Exception as err:
        print("Failed to parse argumennts:'%s'" % str(err))
        sys.exit(1)

    generator = TargetGenerator(hosts,
                                ports,
                                args.o,
                                args.i,
                                args.subnet,
                                args.tmp,
                                args.threads)
    num = generator.generate()
    print("generated %d targets" % num)

