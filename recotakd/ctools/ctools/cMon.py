from __future__ import with_statement
#import sys
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
import time
import psutil
import multiprocessing as mp
import threading
import os

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())

MON_TIMEOUT = 3.0

#CPU_FREE_NOTIFICATION_LIMIT = 25.0
#RAM_FREE_NOTIFICATION_LIMIT = 25.0
RAM_LIMIT = 1024 * 1024 * 100  # 100 MB
CPU_LIMIT = 95.0

activated = False

with open('/proc/sys/kernel/threads-max', 'r') as fd:
    MAX_THREADS = int(fd.read().strip()) * 0.75

cpu_cond = mp.Condition()
cpu_load = mp.Value('f', 100.0)
ram_cond = mp.Condition()
ram_free = mp.Value('l', 0)


def ask_for_rampercent(perc=0.25, max_ram=0):

    if not activated:
        logger.warning('Monitoring disabled, using default limit %d', RAM_LIMIT)
        return RAM_LIMIT * perc

    if perc < 0.0 or perc > 1.0:
        logger.error('Percentage has to be between 0 and 1')
    perc = 0.25
    ram_free = psutil.virtual_memory().available
    r = ram_free * perc
    logger.info('%f bytes of ram free' % (ram_free))
    if max_ram:
        r = min(max_ram, int(r))
    logger.info('granting %d (max %d)' % (r, max_ram))
    return r


def ask_for_threads(wish):

    if not activated:
        logger.warning('Monitoring disabled, passing through %d', wish)
        return wish

    process = psutil.Process(os.getpid())
    nthreads = process.num_threads()
    free = MAX_THREADS - nthreads
    logger.info('Asked for %d threads, %d available' % (wish, free))
    if free <= 0:
        raise Exception('Too many threads running')
    return int(min(wish, free))


def _monitor():
    logger.info('monitor thread started')
    global _stop_ev
    psutil.cpu_percent()
    timeout = MON_TIMEOUT
    while not _stop_ev.is_set():
        all_ok = True
        ram_free.value = psutil.virtual_memory().available

        #logger.info('RAM free: %d' % ram_free.value)
        if ram_free.value > RAM_LIMIT:
            #logger.info('Releasing ram condititon')
            global ram_cond
            ram_cond.acquire()
            ram_cond.notify_all()
            ram_cond.release()
        else:
            all_ok = False

        time.sleep(timeout)

        global cpu_load
        cpu_load.value = psutil.cpu_percent()
        #logger.info('CPU load: %f' % cpu_load.value)
        if cpu_load.value < CPU_LIMIT:
            #logger.info('Releasing cpu condititon')
            global cpu_cond
            cpu_cond.acquire()
            cpu_cond.notify_all()
            cpu_cond.release()
        else:
            all_ok = False

        if all_ok:
            timeout = min(5.0, timeout * 2.0)
        else:
            timeout = max(0.1, 0.5 * timeout)

    logger.info('Resource monitor terminated')


class MonitorCPU(object):
    def __init__(self, f):

        """ Monitor CPU load """

        logger.info('Decorated %s with %s' % (repr(f), __name__))
        self.f = f

    def __call__(self, *args, **kwargs):
        #logger.info('Call through MonitorCPU args: %s, kwargs:  %s' % (repr(args), repr(kwargs)))
        global cpu_cond
        cpu_cond.acquire()
        while cpu_load.value > CPU_LIMIT:
            #logger.info('Waiting for cpu condititon')
            cpu_cond.wait()
            #logger.info('Cpu condititon acquired')
        cpu_cond.release()
        return self.f(*args, **kwargs)


class MonitorRAM(object):
    def __init__(self, f):

        """ Monitor RAM usage """

        logger.info('Decorated %s with %s' % (repr(f), __name__))
        self.f = f

    def __call__(self, *args, **kwargs):
        #logger.info('Call through MonitorRAM args: %s, kwargs:  %s' % (repr(args), repr(kwargs)))
        global cpu_cond
        ram_cond.acquire()
        while ram_free.value < RAM_LIMIT:
            #logger.info('Waiting for ram condititon')
            ram_cond.wait()
            #logger.info('Ram condititon acquired')
        ram_cond.release()
        return self.f(*args, **kwargs)


_stop_ev = threading.Event()
_mon = threading.Thread(target=_monitor)
_mon.setDaemon(True)

def start():
    if activated:
        _mon.start()
    else:
        logger.warning('Monitoring deactivated, not starting')


def stop():
    global _stop_ev
    _stop_ev.set()

if __name__ == "__main__":
    @MonitorCPU
    def testfunc():
        print 'testfunc exec'

    logger.info('started test')
    testfunc()
