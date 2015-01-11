from __future__ import with_statement
import cMon
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
import cCircCash
import multiprocessing as mp
import multiprocessing.dummy as mpd
import threading
import Queue
import os
import itertools as it
import time
import __builtin__

# This module offers various methods to generate input for
# scanner and bruteforce plugins

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


#####################################################
## Exceptions
#####################################################
class ENoInput(Exception):
    """ ENoInput is raised when input is provided neither via file not list """

    def __init__(self, value=''):
        self.value = value

    def __str__(self):
        return repr(self.value)


class cTHQueue(Queue.Queue):

    SENTINEL = 'xxxxxxx'

    def __init__(self, threshold=0, maxsize=0, sentinel=SENTINEL):

        """
        A Thresholded Queue.

        It provides the Condition object thesh_cond.
        Threads waiting on thresh_cond are notified
        whenever the number of elements (qsize)
        falls below the specified threshold.

        Input:

            threshold       threshold condition
            maxsize         maximum number of elements (put blocks if full)
        """

        # Queue is an old style class, we can not use super
        Queue.Queue.__init__(self, maxsize=maxsize)

        logger.info('Init queue maxsize: %d, threshold: %d',
                    maxsize, threshold)
        # the threshold
        self.threshold = threshold
        # condition object, wait on this
        self.thresh_cond = mp.Condition()
        self.sentinel = sentinel

    def kill(self):
        self.close()
        for item in self:
            pass

    def put(self, item):
        if item is not None:
            #logger.debug('Put ' + repr(item))
            try:
                Queue.Queue.put(self, item, block=False)
            except Queue.Full:
                logger.info('Input Queue is full, waiting for it to be emptied to threshold')
                self.thresh_cond.acquire()
                while not self.is_free():
                    self.thresh_cond.wait()
                self.thresh_cond.release()
                logger.info('Input Queue emptied enough, resuming ...')

    def close(self):
        logger.info('Queue closed')
        self.put(self.sentinel)

    def __iter__(self):
        #logger.info('iter called')
        return iter(self.get, self.sentinel)

    def get(self, block=True, timeout=None):

        """
        Wrapper for Queue.Queue.get.
        If the remaining number of elements falls below the threshold,
        the waiters are notified.
        """

        # Queue is an old style class, we can not use super
        item = Queue.Queue.get(self, block, timeout)
        #logger.debug('get called ' + repr(item))
        # check if threshold is reached
        if self.qsize() < self.threshold:
            #logger.debug('Thresh passed')
            # notify waiters
            self.thresh_cond.acquire()
            # we notify all, since it might well be that we are far below the
            # threshold already, if the waiting is done right, it won't cause
            # problems
            self.thresh_cond.notify_all()
            self.thresh_cond.release()
        return item

    def is_free(self):

        """ Check if the current number of queue element is below the threshold """

        return self.qsize() < self.threshold


class cInputGenerator(threading.Thread):
    """
    What is this class for? I have no idea, too! A doc string would be great
    though!
    """
    #FIXME doc string

    # maximum number of threads per poll
    MAXTHREADS = 64
    # maximum number of items per queue/buffer
    MAXITEMS = 5000
    # when to trigger queue/buffer refill
    ITEMTHRESH = 4900
    # marker for end of queue
    SENTINEL = 'asjhglag'

    def __init__(self,
                 filename='',
                 filenames=[],
                 data=[],
                 ie_size=42,
                 circle=False,
                 expand_cb=None,
                 prepare_cb=None,
                 maxthreads=MAXTHREADS,
                 sentinel=SENTINEL):

        """
        A class to abstract input generation and caching.

        Input:
            filename        Input file
            data            Input array
            ie_size         Estimated size of one element
            circle          I the buffer read more than once? Controls caching.
            expand_cb       Input expansion callback function, e.g. mkIP.
                            This callback should be an iterator and yield 0 or more tupes.
                            It gets input directly from the data array and the file content.
            prepare_cb      Input preparation callback.
                            It should modify the input in a way that the actual bruteforce function can work with it.
                            If one item is to be discarded from further processing, it should return None.
                            The prep. callback gets the return values from the expand callback as input.
            maxthreads      Maximum number of threads per pool, there are max. 2 pools active at the same time.
            sentinel        Marks the end of the queue/buffer
        """

        super(cInputGenerator, self).__init__()

        logger.debug('Init cInputGenerator %s + %s' % (filename, repr(data)))
        self.filename = filename
        self.filenames = filenames
        self.data = data
        self.ie_size = ie_size
        self.maxthreads = maxthreads

        try:
            self.datasize = len(data)
        except:
            self.datasize = 0

        if filename:
            self.filenames.append(filename)

        for filename in self.filenames:
            #print filename
            try:
                fd = __builtin__.openany(filename, 'r')
            except Exception as e:
                print '[!] WARNING: Can not open file \'%s\': %s' % (filename, e)
                self.items = data
            else:
                logger.debug('opened %s', fd.name)
                self.items = it.chain(fd.readlines(), data)
                #print repr(self.items)
                self.datasize += os.stat(fd.name).st_size
                logger.debug('size %d' % self.datasize)

        if not filenames:
            self.items = data

        #print repr(self.items)
        if not self.items:
            print 'No input specified'
            raise ENoInput('No input specified')

        if expand_cb:
            self.expand_cb = lambda i: map(i[0].put, expand_cb(i[1]))
        else:
            self.expand_cb = None

        if prepare_cb:
            prepare_cb = prepare_cb
            self.prepare_cb = prepare_cb
        else:
            self.prepare_cb = None

        qsize = cMon.ask_for_rampercent(
            perc=0.25,
            max_ram=cInputGenerator.MAXITEMS * self.ie_size
        )
        qsize = qsize / self.ie_size
        if circle:
            self.out = cCircCash._circ_cash(
                threshold=cInputGenerator.ITEMTHRESH,
                maxsize=cInputGenerator.MAXITEMS,
                circle=True)
        else:
            self.out = cTHQueue(
                threshold=cInputGenerator.ITEMTHRESH,
                maxsize=cInputGenerator.MAXITEMS)
        self.sentinel = sentinel

    def run(self):
        expand_pool = None
        prepare_pool = None

        #if self.datasize:
        #    psize_wish = max(min(self.maxthreads, self.datasize), 1)
        psize_wish = self.maxthreads

        rex = None
        if self.expand_cb:
            # i cant really guess how much data there will be in the end
            # since the input to be expanded might be sth like 0.0.0.0/0
            qsize = cMon.ask_for_rampercent(
                perc=0.25,
                max_ram=cInputGenerator.MAXITEMS * self.ie_size
            )
            qsize = qsize / self.ie_size
            multi_q_out = cTHQueue(
                threshold=qsize * 0.75,
                maxsize=qsize
            )
            psize = cMon.ask_for_threads(psize_wish)
            expand_pool = mpd.Pool(psize)
            #ex_items = expand_pool.imap(self.expand_cb, self.items)
            rex = expand_pool.imap(self.expand_cb, [(multi_q_out, item) for item in self.items])
            # the expanded item list is our new input
            #expand_pool.close()
            self.items2 = multi_q_out
        else:
            self.items2 = self.items

        # as i set, if items are expanded there is really no way to know, but
        # otherwise one thread per input element sounds like a good idea
        psize = cMon.ask_for_threads(self.maxthreads)
        prepare_pool = mpd.Pool(psize)
        if self.prepare_cb:
            #prepare_pool.imap(self.out.put, it.imap(self.prepare_cb, self.items2))
            prepare_pool.imap(lambda t: self.out.put(self.prepare_cb(t)), self.items2)
        else:
            # TODO: do i need this?? -> yes
            #for ex_item in ex_items:
            #    logger.debug('mapping ' + repr(ex_item))
            #    prepare_pool.imap(self.out.put, ex_item)
            #expand_pool.close()
            prepare_pool.imap(self.out.put, self.items2)

        if expand_pool:
            try:
                if rex:
                    for i in rex:
                        pass
            except Exception as e:
                logger.error('an error occurred: ', e)
                logger.error('filenames: ', self.filenames)
                logger.error('data: ', self.data)
                logger.error('expand_cb: ', self.expand_cb)

                #print repr(e)
                #print repr(self.filenames)
                #print repr(self.data)
                #print repr(self.expand_cb)

            expand_pool.close()
            logger.info('expand pool closed (%s, %s)', self.filename, self.data)
            expand_pool.join()
            logger.info('expand pool joined (%s, %s)', self.filename, self.data)
        try:
            self.items2.close()
            while self.items2.qsize() > 0:
                time.sleep(1)
        except:
            pass
        if prepare_pool:
            prepare_pool.close()
            logger.info('prepare pool closed (%s, %s)', self.filename, self.data)
            prepare_pool.join()
            logger.info('prepare pool joined (%s, %s)', self.filename, self.data)
            self.out.close()

    def __iter__(self):
        return iter(self.out)


def lazy_product(*inp):
    """
    lazy implementation of itetools product, that works with rewindable generators.
    The top level generator, does not have to be rewindable
    Input:
        *inp        list of lists, e.g. [[1,2,3],  [3,4,5,6], [2,3]]

    Ouput:
        product     [1,3,2], [1,3,3], [1,4,2], ...
    """

    # get first generator
    inp0 = inp[0]

    done = False
    if inp0 is not None:
        # iterate over all generator objects contained in the first generator
        for x in inp0:
            done = True
            # check if more generators are contained in the current gen object
            if inp[1:]:
                # if so evaluate lazy product on those
                inp1 = lazy_product(*inp[1:])
                # for each evaluated product return concatenation with
                # each element from the current generator
                for y in inp1:
                    yield (x,) + y
                    if lazy_product.delay > 0:
                        time.sleep(lazy_product.delay)
            else:
                # if this is the last generator in the list,
                # just yield the elements one by one
                yield (x,)
    else:
        done = True

    # if there is no element in the first queue we still need to iterate over
    # the rest in order to close the queues
    if not done:
        for i in inp[1:]:
            inp1 = lazy_product(*inp[1:])
            for y in inp1:
                pass

    raise StopIteration


# TODO: merge in map
def _count_tuples_single(args):

    if _count_tuples.prep_callback:
        for tup in _count_tuples.prep_callback(args):
            _count_tuples.q.put(tup)
    else:
        _count_tuples.q.put(args)


def _count_tuples(args):

    if _count_tuples.prep_callback:
        for tup in _count_tuples.prep_callback(*args):
            _count_tuples.q.put(tup)
    else:
        _count_tuples.q.put(args)


class cTuples(threading.Thread):
    """
    what is this class for? What is the difference between cInputGenerator
    and cTuples?

    """
    #FIXME doc string

    sentinel = ('xxxxx')
    MAXTHREADS = 64
    DELAY = 0.0

    def __init__(self,
                 inputs,
                 prep_callback=None,
                 maxthreads=MAXTHREADS,
                 single=True,
                 delay=0.0
                 ):

        """
        Generate a queue from Input Data.
        Input data is processed by prep_callback, before being added to the Queue.
        To stop the generation of queue elements, call stop().

        Input:
            prep_callback      prepares data before placing it into the queue
            inputs             input data, dict(
            maxthreads         max thread pool size
            single             single argument, do not try to unpack
            delay              delay to wait in between return of tuples
        """

        if not inputs:
            print 'No input specified'
            raise ENoInput('No input specified')

        super(cTuples, self).__init__()

        logger.debug(repr(inputs))
        self.single = single
        self.caches = inputs
        self.prep_callback = prep_callback
        if delay > 0:
            lazy_product.delay = delay
        else:
            lazy_product.delay = cTuples.DELAY

        self.maxthreads = maxthreads
        # TODO
        #self.tuple_q = cTHQueue(threshold=int(self.granted_items * 0.75),
        #                        maxsize=self.granted_items)
        self.tuple_q = cTHQueue(threshold=750,
                                maxsize=1000)

    def run(self):
        logger.debug('starting tuples')
        self.tuples_added = 0
        if len(self.caches) > 1:
            #data = it.product(*self.caches)
            data = lazy_product(*self.caches)
        else:
            data = self.caches[0]
        ps = cMon.ask_for_threads(self.maxthreads)
        logger.debug('starting pool of size: %d' % ps)
        pool = mpd.Pool(ps)
        _count_tuples.prep_callback = self.prep_callback
        _count_tuples.q = self.tuple_q
        if len(self.caches) == 1 and self.single:
            pool.imap(_count_tuples_single, data)
        else:
            pool.imap(_count_tuples, data)
        #res = []
        #for i in data:
        #    r = pool.imap(self._count_tuples, [(self, i), ])
        #    res.append(r)
        # join input generators
        for inp in self.caches:
            try:
                if hasattr(inp, 'join'):
                    inp.join()
                else:
                    print 'Unjoinable input: ' + repr(inp)
            except Exception as e:
                print 'Unjoinable input: ' + repr(inp)
                print repr(e)

        # all inputs are generated, so we can close the pool now
        pool.close()
        logger.debug('map done')
        pool.join()
        self.tuple_q.close()
        logger.debug('Done')


############################################################################
## TEST cInputGenerator ####################################################
############################################################################


def pcb(item):
    logger.debug('PCB %s', item)
    return ((item, 42))


def ecb(item):
    logger.debug('ECB %s', item)
    yield item
    time.sleep(5)
    yield item
    time.sleep(5)
    raise StopIteration

def ecb_None(item):
    yield None

def _test_cInputGenerator_None():
    ig = cInputGenerator(data=[None],
                         circle=True,
                         expand_cb=ecb_None,
                         )
    ig.start()
    for item in ig:
        print repr(item)

def _test_cInputGenerator():
    time.sleep(0.5)
    ig = cInputGenerator(data=range(10),
                         circle=True,
                         expand_cb=ecb,
                         prepare_cb=pcb)
    ig.start()
    for item in ig:
        print repr(item)
        time.sleep(0.2)
    print
    for item in ig:
        print repr(item)
        time.sleep(0.2)
    print
    for item in ig:
        print repr(item)
        time.sleep(0.2)
    ig.join()


############################################################################
## TEST cTuples ############################################################
############################################################################

def doubl(args):
    logger.info('DOUBL %s', args)
    r1 = [x * 2 for x in args[0]]
    r2 = [x * 2 for x in args[1]]
    yield r1 + r2
    raise StopIteration


def _test_cTuples():

    i1 = range(0, 4)
    i2 = range(5, 7)

    ig1 = cInputGenerator(data=i1,
                          circle=False,
                          expand_cb=ecb,
                          prepare_cb=pcb)
    ig1.start()
    logger.info('ig1 started')
    ig2 = cInputGenerator(data=i2,
                          circle=True,
                          expand_cb=ecb,
                          prepare_cb=pcb)
    ig2.start()
    logger.info('ig2 started')

    t = cTuples(inputs=[ig1, ig2], prep_callback=doubl)
    t.start()
    logger.info('t started')

    for item in t.tuple_q:
        print repr(item)
    t.join()


############################################################################
## TEST lazy_product #######################################################
############################################################################

def _test_lazy_product():

    i1 = range(0, 4)
    i2 = range(5, 7)
    i3 = range(8, 10)

    ig1 = cInputGenerator(data=i1,
                          circle=False)
    ig1.start()
    logger.info('ig1 started')

    ig2 = cInputGenerator(data=i2,
                          circle=True)
    ig2.start()
    logger.info('ig2 started')

    ig3 = cInputGenerator(data=i3,
                          circle=True)
    ig3.start()
    logger.info('ig3 started')

    product = lazy_product(ig1, ig2, ig3)

    ig1.join()
    ig2.join()
    ig3.join()

    cache = []
    for item in product:
        print repr(item)
        cache.append(item)
    print 'DONE'

    ref_product = it.product(i1, i2, i3)

    for item, ref in zip(ref_product, cache):
        if item != ref:
            print 'error %s != %s' % (repr(item), repr(ref))
        else:
            print 'OK %s == %s' % (repr(item), repr(ref))


############################################################################
## TEST THQueue ############################################################
############################################################################

def take_from_queue(q, wait):
    logger.info('take_from_queue thread started')
    while True:
        time.sleep(wait)
        logger.info('Taking one element from Q')
        e = q.get()
        logger.info('Got %s', e)


def _test_THQueue():
    logger.setLevel(logging.DEBUG)
    s = 10
    th = 4
    q = cTHQueue(
        threshold=th + 1,
        maxsize=s)
    i = range(s)
    map(q.put, i)
    t = threading.Thread(target=take_from_queue, args=[q, 5])
    t.setDaemon(True)
    t.start()
    map(q.put, i)

def _test_None():
    s = 10
    th = 4
    q = cTHQueue(
        threshold=th + 1,
        maxsize=s)
    q.put(None)
    q.close()
    item = q.get()
    print repr(item)

############################################################################

if __name__ == "__main__":
    # logging
    LOG = "/tmp/ctools.log"
    FORMAT = '%(asctime)s - %(name)s - ' + \
        '%(levelname)s - %(threadName)s - %(message)s'
    logging.basicConfig(filename=LOG,
                        filemode="w",
                        format=FORMAT,
                        level=logging.DEBUG)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    if not hasattr(__builtin__, 'openany'):
        __builtin__.openany = open
    _test_None()
    #_test_cInputGenerator()
    #_test_cTuples()
    #_test_lazy_product()
    #_test_THQueue()
