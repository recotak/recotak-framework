from __future__ import with_statement
import multiprocessing as mp
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
import tempfile
import time
import logging

#LOG = "/tmp/data.log"
#FORMAT = '%(asctime)s - %(name)s - ' + \
#    '%(levelname)s - %(threadName)s - %(message)s'
#logging.basicConfig(filename=LOG,
#                    filemode="w",
#                    format=FORMAT,
#                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
logger.addHandler(logging.NullHandler())


RECACHE_THRESH = 0.25


#####################################################
## Exceptions
#####################################################
class EInvalidThreshold(Exception):
    """ ENoInput is raised when input is provided neither via file not list """

    def __init__(self, value=''):
        self.value = value

    def __str__(self):
        return repr(self.value)


def _read_worker(fd, data, stop_ev, re_read=True):

    """
    Read a file and place the lines into a circular buffer.

    Input:
        fd              file descriptor to be read
        data            Cash providing method put (e.g. cCircCash._circ_cash instance)
        stop_ev         Event to stop the reading process
        re_read         Boolean: restart reading the file if finished
    """

    logger.info('read_worker started')
    while not stop_ev.is_set():
        try:
            try:
                logger.debug('Starting/continuing read')
                for item in fd.readlines():
                    item = item.rstrip()
                    # skip empties
                    if not item:
                        continue
                    try:
                        data.put(tuple(item.split(_circ_cash.seperator)))
                    except:
                        data.put(item)
            except Exception, e:
                # sth went wrong, lets quit this reader
                logger.error('Error on read -> %s' % (e))
                break
            logger.info('Finished reading file')
            data.close()
            if not re_read:
                # we are done
                break
            # start reading again from the top
            fd.seek(0)
        except Exception, e:
            logger.error('Error on open -> %s' % (e))
            break
    logger.info('read_worker done')


class _circ_cash(object):

    SENTINEL = 'xxxxxx'
    seperator = '::'

    def __init__(self, threshold=0, maxsize=0, circle=False, SENTINEL=SENTINEL):

        """
        This class provides a size limited buffer.
        If maxsize is reached, attempts to place new elements inside the buffer will
        block until the number of elements falls below threshold.
        If the circle option is set, buffer contents will be cached inside a file, which
        is read on subsequent iterations.

        Input:
            threshold       If the number of buffered items falls below threshold, new items can
                            be inserted until capacity is reached again.
            maxsize         Capacity of the buffer. If reached put method will block.
            circle          Set to True if you want the buffer to be re-readable.
                            In which case, buffer contents will be cached on disk.
            SENTINEL        Marks end of data, just ignore
        """

        logger.info('Init circ_cache maxsize: %d, threshold: %d, circle: %s',
                    maxsize, threshold, circle)

        # cache size
        self.size = maxsize

        # indicates if cache is over capacity, i.e. n items > maxsize
        self.over_cap = False

        # read index, one way (increases steadily)
        self.r_idx = mp.Value('l', 0)
        # write index, one way (increases steadily)
        self.w_idx = mp.Value('l', 0)

        # conditions indicating, that data has be read/written
        self.read_cond = mp.Condition()
        self.write_cond = mp.Condition()

        if threshold == 0:
            self.threshold = int(RECACHE_THRESH * maxsize)
        elif threshold > maxsize:
            raise EInvalidThreshold('Threshold %d is over buffer capacity %d' % (threshold, maxsize))
        else:
            self.threshold = threshold

        logger.info('Recache threshold set to %d' % self.threshold)

        # write lock (we need this, because several threads will try to put
        # items into the buffer concurrently)
        self.write_lock = mp.Lock()

        # read lock (we need this, because several threads will try to get
        # items from the buffer concurrently)
        # even though we do have the conditions confirming, that there is at
        # least one item to be read for each thread that passes it,
        # items could be doubled
        self.read_lock = mp.Lock()

        # buffer holding the actual data
        self.data = []

        # if we want to re-read the data, we need a disk cache
        self.circle = circle
        if circle:
            logger.info('Creating temp file cache')
            self.disk_cache = tempfile.TemporaryFile()
            self.read_worker = None
            self.read_worker_stop_ev = None
            self.buffer_open = True
        else:
            self.disk_cache = None

        logger.info('%d item cache initialized' % self.size)

    def rewind(self):

        """ Rewind the buffer (start reading again from the start) """

        if not self.circle:
            # sorry but you should have said so, if you wanted rewindable
            # buffers
            return

        if self.r_idx.value < self.size:
            # if the read index is below capacity, we can just set it back to
            # zero
            logger.debug('rewind')
            self.r_idx.value = 0

            # Know we know, that we don't need this anymore
            self.disk_cache.close()

            # tell the readers(!), that they can start reading again
            self.write_cond.acquire()
            self.write_cond.notify()
            self.write_cond.release()
        else:
            # if its above the capacity, that means, that the buffer is "to
            # small", i.e. it can not hold all the data at once.
            # Which means we have to use the disk for storing the items,
            # which currently dont fit in the RAM.

            if self.read_worker:
                # if the read worker is already running ... we have a minor
                # problem i guess ... not sure TODO
                logger.warning('not rewinding')
                return

            self.r_idx.value = 0
            self.w_idx.value = 0

            self.write_cond.acquire()
            self.write_cond.notify()
            self.write_cond.release()

            self.read_cond.acquire()
            self.read_cond.notify()
            self.read_cond.release()

            # start the reader thread
            self.read_worker_stop_ev = mp.Event()
            self.read_worker = threading.Thread(
                target=_read_worker,
                args=(
                    self.disk_cache,
                    self,
                    self.read_worker_stop_ev,
                    True
                )
            )
            self.read_worker.setDaemon(True)
            self.read_worker.start()
            logger.info('Startet reading from disk')

    def close(self):
        self.put(_circ_cash.SENTINEL)

    # TODO: where to call this?
    def clean(self):

        """ close open file handles """

        if self.read_worker:
            # stop read worker thread
            self.read_worker_stop_ev.set()

        if self.disk_cache:
            # close disk cache file handle
            self.disk_cache.close()

    def put(self, item):

        """
        Place item in buffer.
        If the buffer is full (maxsize), put blocks until the recache threshold is passed.
        If item == None, it is not inserted.

        Input:
            item        Item to be stored

        """

        # skip empties
        if item is None:
            return

        logger.debug('Put ' + repr(item))

        # check if we have space to write
        self.read_cond.acquire()
        while (self.w_idx.value - self.r_idx.value) >= self.size:
            logger.debug('Buffer is full, waiting for read')
            self.read_cond.wait()
            logger.debug('can write now')
        self.read_cond.release()

        # sync because concurrency
        with self.write_lock:
            # now we can write new data at index i
            i = int(self.w_idx.value % self.size)
            #logger.debug('write index: %d (%d)' % (i, self.w_idx.value))
            if len(self.data) <= i:
                # append if we still have the space
                self.data.append(item)
            else:
                # otherwise replace an "old" item (which we already processed,
                # so it can be discarded)
                self.data[i] = item

            # up the write index
            self.w_idx.value += 1

            if self.w_idx.value == self.size:
                logger.info('Capacity exceeded, writing data to disk')
                if not self.over_cap:
                    # write all previous data into disk cache
                    for x in self.data:
                        stritem = _circ_cash.seperator.join(map(str, [x]))
                        logger.debug('Writing (all) %s' % stritem)
                        self.disk_cache.write(stritem + '\n')
                    self.over_cap = True

            # tell the other guys that there is new stuff to be read
            self.write_cond.acquire()
            self.write_cond.notify()
            self.write_cond.release()

            # so if we have a disk cache and the buffer is still open and the
            # current item does not indicate the end of the data stream
            # cache it
            #if self.disk_cache and self.buffer_open and item != _circ_cash.SENTINEL:
            if self.over_cap and self.buffer_open and item != _circ_cash.SENTINEL:
                stritem = _circ_cash.seperator.join(map(str, [item]))
                logger.debug('Writing %s' % stritem)
                self.disk_cache.write(stritem + '\n')

    def __iter__(self):

        """ blubb, its an iterator """

        return iter(self.get, _circ_cash.SENTINEL)

    def get(self):

        """ Get one item from buffer, blocks infinetly if there is nothing to be read """

        # do we have sth to read?
        self.write_cond.acquire()
        while self.r_idx.value >= self.w_idx.value:
            logger.debug('Buffer is empty, waiting for write')
            self.write_cond.wait()
        self.write_cond.release()

        with self.read_lock:
            # lets read it from i
            i = int(self.r_idx.value % self.size)
            #logger.debug('read index: %d (%d)' % (i, self.r_idx.value))
            item = self.data[i]
            logger.debug('get called ' + repr(item))

            # up the read index
            self.r_idx.value += 1

            # tell the other guys, that they can overwrite the old stuff
            # but only if the threshold is passed
            if (abs(self.r_idx.value % self.size - self.w_idx.value % self.size)) >= self.threshold:
                logger.info('Cash emptied enough, resuming ...')
                self.read_cond.acquire()
                self.read_cond.notify()
                self.read_cond.release()

            # if the current item is the SENTINEL, we are done
            # we can close the buffer (if not closed already) and
            # reset the disk cache (wait what: TODO)
            if item == _circ_cash.SENTINEL:
                if self.disk_cache and self.buffer_open:
                    self.buffer_open = False
                    #self.disk_cache.seek(0)
                self.rewind()
        return item


############################################################################
## TEST THQueue ############################################################
############################################################################

def take_from_cache(c, wait):
    logger.info('take_from_cache thread started')
    while True:
        time.sleep(wait)
        logger.info('Taking one element from Q')
        e = c.get()
        logger.info('Got %s', e)


def _test_cCircCash():
    logger.setLevel(logging.DEBUG)
    s = 10
    th = 4
    c = _circ_cash(maxsize=s + 1, threshold=th, circle=True)
    i = range(s)
    map(c.put, i)
    t = threading.Thread(target=take_from_cache, args=[c, 5])
    t.setDaemon(True)
    t.start()
    map(c.put, i)

############################################################################

if __name__ == "__main__":
    _test_cCircCash()
