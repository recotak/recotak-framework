"""
This module implements a cScanner, which is inherited from, if a object wants
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
to scan a target. It creates a new process that is basically a wrapper to other
ctool libraries.

"""
from threading import Thread
from cUtil import mkIPrandom
from Queue import Queue
import multiprocessing
import __builtin__
import errno
import time
import os

PID_FILE = "/var/log/cScanner_%s.pid"

__author__ = "curesec"

if not hasattr(__builtin__, 'openany'):
    __builtin__.openany = open
    __builtin__.openhome = open
    __builtin__.openshared = open

class cScannerError(Exception):
    pass

class PortError(cScannerError):
    pass

def scan_thread(queue, cb_scan):
    """
    acts as scanning thread and calls scanning callback function for every
    element in the queue

    input:
        queue   queue containing the elements to scan
        cb_scan callback that processes the targets

    """
    while not queue.empty():
        target = queue.get()
        cb_scan(target)

class cScanner(multiprocessing.Process):
    """
    Scanner process that is responsible for scanning a list of targets. It
    abstracts calls to other ctool libraries.
    onsider you want to write a short port scanner. Either your scanner
    inherits from cScanner or you use cScanner directly. In the constructor, the
    callback function(cb_scan) needs to be set in order to the actual scan. In
    this example it is a tcp connection to the target, but it might also be a
    whois check or a dns resolve. Before scanning targets should be added.

    from ctools import cScanner
    import socket

    TARGETS = [127.0.0.1, 192.168.170.1/16, 127.0.1.0-127.0.1.50]
    PORTS = [80]

    def scan(addr, hostname):
        if instance(addr, tuple):
            ip = addr[0]
            port = addr[1]
        else:
            ip = addr
            port = 80

        # the actual scan for a passed target
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.sendall("my data")
        response = s.recv()

    portscanner = cScanner(cb_scan=scan)
    portscanner.add_targets(TARGETS)
    porscannner.set_ports(PORTS)
    portscanner.start()
    portscanner.join()

    """

    def __init__(self, cb_scan, name=None, dns_resolve=True, max_threads=64):
        """
        create a cScanner object.

        input:
            cb_scan     the callback function that is called for every target
            name        you can name the scanner in order to find its pid file
                        in /var/log. if no name given, takes current time in
                        milliseconds
            dns_resolve resolve dns names (optional)
            max_threads the amount of threads that actually call cb_scan

        """
        super(cScanner, self).__init__()
        self.name = name if name else str(round(time.time()))
        self.pid_fn = PID_FILE % self.name
        self.dns_resolve = dns_resolve
        self.max_threads = max_threads
        self.randomness = 10

        self.__ports = []
        self.__targets = []
        self.__cb_scan = cb_scan
        self.__threads = []

    def set_randomness(self, randomness):
        """
        sets the randomness of scanning. the higher the randomness, the more
        random are targets scanned and the lower is performance.

        input:
                randomness  an integer, that indicates the randomness.

                                1    no randomness
                                2    randomness
                                10   high randomness
                                100  ultra randomness
                                1000 incredible ranomness


        """
        self.randomness = randomness

    def set_ports(self, ports):
        """
        Add a string containing ports that ought to be scanned for each target.

        input:
            ports   a list containing ports to scan. supported types are:
                    single ports, port ranges

                    eg:
                        set_ports([21-23, 80, 443])

        """
        try:
            for port in ports:
                if "-" in port:
                    port_split = port.split("-")

                    if not len(port_split) == 2:
                        raise PortError("Invalid port range (%s)!" % str(port))

                    self.__ports.extend(range(int(port_split[0]),
                                              int(port_split[1])+1))
                else:
                    self.__ports.append(int(port))

        except ValueError:
            raise PortError("Port is not of type int!")

    def add_targets(self, targets):
        """
        In order to scan, we need targets. .

        input:
            targets     a list containing the targets to scan
                        supported types are: single ip, ip range,
                        ip mask, domain name

                        e.g.:

                         [127.0.0.1, 192.168.170.1/16, 127.0.1.0-127.0.1.50,
                          google.de]

        """
        self.__targets.extend(targets)

    def add_target_file(self, target_file):
        """
        In order to add targets that a stored in a file, you can pass the file
        name and the targets will be extracted in real time during scan. For
        each line, the add_targets function is called. See help(cScanner.
        add_target) for details about allowed target types.

        input:
            target_file     a file containg one target per line. add_targets is
                            applied to each line of the file

                            e.g.:

                             "/tmp/my_targets.txt"

        """

        with openany(target_file, "r") as f:
            self.add_targets(f.read().strip().split())

    def _write_pid(self):
        """ write pid to /var/run """
        try:
            with open(self.pid_fn, "w") as f:
                f.write(str(self.pid))

        except IOError as ioerror:
            if ioerror.errno == errno.EACCES:
                pass
            else:
                raise

    def _remove_pid(self):
        """ remove pid from /var/run """
        if os.path.isfile(self.pid_fn):
            os.remove(self.pid_fn)

    def __start_scan_thread(self, target):
        """
        Creates a new scan thread, if max_threads allows to.
        Every scan thread is assigned a queue that contains the targets to
        scan. For every element of the queue, the scan callback function is
        called.

        input:
            target  a new target to scan. basically the result of cUtil.mkIP2

        """
        self.__threads = filter(lambda t: t[0].is_alive(), self.__threads)
        func = self.__start_scan_thread.__func__

        def inc_counter():
            """
            in order to not constantly add a target to the first queue,
            we need a counter, that points to the next queue to add the
            target. as consequence, every queue should have round about the
            same qsize

            """
            try:
                if func.counter < len(self.__threads)-1:
                    func.counter += 1
                else:
                    func.counter = 0
            except AttributeError:
                func.counter = 0

        if len(self.__threads) < self.max_threads:
            # create a queue to be filled with targets
            q = Queue(maxsize=1000)
            q.put(target)

            # create a new thread to process targets
            t = Thread(target=scan_thread,
                       args=(q, self.__cb_scan))
            t.start()
            self.__threads.append((t, q))

        else:
            inc_counter()

            assigned = False # successfully assigned target to thread
            while not assigned:
                t, q = self.__threads[func.counter]
                if not q.full():
                    q.put(target)
                    assigned = True
                    break
                else:
                    inc_counter()


    def run(self):
        self._write_pid()

        try:
            for new in mkIPrandom(ips=self.__targets,
                                  ports=self.__ports,
                                  dns_resolve=self.dns_resolve,
                                  randomness=self.randomness):
                self.__start_scan_thread(new)

            for thread, queue in self.__threads:
                thread.join()

        finally:
            self._remove_pid()
