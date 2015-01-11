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
# @version 0.1
# @date 21.01.2014
# @author curesec, curesec
# @email curesec

from __future__ import with_statement
import argparse
import sys
from ctools import cUtil
import ccdClasses as ccd
import socket
import gzip
from datetime import datetime
import time
import ConfigParser
import re
import codecs
import multiprocessing
import Queue
import threading
import logging
import __builtin__


__version__ = '1.0'
__author__ = 'curesec'
__plgname__ = 'ripe_db_extractor'

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


def secs(start_time):
    dt = datetime.now() - start_time
    secs = (dt.days * 24 * 60 * 60 + dt.seconds * 1000 +
            dt.microseconds / 1000) / 1000.0
    return secs


row_fmt = "{:60} {:31}| {:27}"


def parse(argv):

    """ parse cmd line options sys.argv[1:].
        Also checks if provided options are valid.

        Input:
            argv        cmd line without argv[0]

        Output:
            parsed args
    """
    description = """### RIPE DB Extractor ###
                  A script to search through the RIPE database for a given search string
                  to retrieve network ranges and IP addresses.
                  Download and extract the database from: ftp://ftp.ripe.net/ripe/dbase/ripe.db.gz
                  (or from 85.114.142.136:32666)
                  Use the -update flag to load the newest version of the ripe database.
                  Be aware that this script might take over one minute to complete.
                  The search is full text search. Try to be specific. Search is case insensitive."""
    epilog = """examples:
                ripe_db_extractor -s curesec
                ripe_db_extractor -update"""

    parser = argparse.ArgumentParser(description=description,
                                     epilog=epilog,
                                     prog=__plgname__,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c",
                        dest='config',
                        default="ripe_db_extractor.conf",
                        required=False,
                        help="Path to configuration file (default ./ripe_db_extractor.conf)"
                        )
    parser.add_argument("-db",
                        default="ripe.db.gz",
                        dest="dbfile",
                        required=False,
                        help="Path to read from or write the ripe database to, can be gzipped or plain "
                        )
    parser.add_argument("-s",
                        action="store",
                        dest="searchstring",
                        nargs='+',
                        required=False,
                        help="The names of companies or whatever you want to search for " +
                             "(seperate with spaces)"
                        )
    parser.add_argument("-S",
                        action="store",
                        dest="searchfile",
                        required=False,
                        help="File containing search strings"
                        )
    parser.add_argument("-o",
                        action="store",
                        dest="extractfile",
                        required=False,
                        help="Write all found RIPE records in this file"
                        )
    parser.add_argument("-nt",
                        dest="nthreads",
                        type=int,
                        required=False,
                        default=16,
                        help="Number of threads to scan with. " +
                             "if you specify more than 1 thread the ripe database file is read in " +
                             "chunks of the specified batchsize, " +
                             "which are in turn processed by the specified number of "
                             "threads. (default 1)"
                        )
    parser.add_argument("-bs",
                        dest="batchsize",
                        type=int,
                        required=False,
                        default=15791394,
                        help="Batchsize (make sure you have enough ram)"
                        )
    parser.add_argument("-to",
                        dest="timeout",
                        type=int,
                        required=False,
                        default=30,
                        help="Socket timeout"
                        )
    parser.add_argument("-update",
                        dest="update",
                        required=False,
                        default=False,
                        action='store_true',
                        help="update ripe database"
                        )
    if not argv or not argv[0]:
        parser.print_help()
        sys.exit(1)

    opt = parser.parse_args(argv)
    return opt


def MatchWorker(data, pat, out_q, out_fh, out_lock):

    """
    Serach for patterns in a chunk of data and put results in a queue

    Input:
        data        data chunk to process
        pat         regex pattern
        out_q       output queue
        out_fh    filehandle to store matched entries
        out_lock    lock for output file access
    """
    match = pat.search(data)
    while match:
        span = match.span()
        entry_start = data[:span[0]].rfind('\n\n')
        if entry_start < 0:
            entry_start = 0
        entry_stop = span[1] + data[span[1]:].find('\n\n')
        if entry_stop <= 0:
            entry_stop = span[1]
        if out_fh and out_lock:
            with out_lock:
                out_fh.write(data[entry_start:entry_stop])
                out_fh.flush()
        for line in data[entry_start:entry_stop].splitlines():
            if line.startswith('inetnum'):
                num = line.strip().replace(" ", "").split(":")[1]
                msp0 = data[:span[0]].rfind('\n')
                if msp0 < 0:
                    msp0 = 0
                msp1 = span[1] + data[span[1]:].find('\n') - 1
                if msp1 <= 0:
                    msp1 = span[1]
                matchstr = data[msp0 + 1:msp1].encode('utf-8')
                rsnum = num.rstrip()
                rsmatchstr = matchstr.rstrip()
                print row_fmt.format(rsmatchstr, rsnum, '')
                out_q.put((match.group(), matchstr, num))
        data = data[entry_stop:]
        match = pat.search(data)


class RIPEDBExtractor(object):
    def __init__(self, args, dbh=None):

        """
        Search the RIPE database or save it to disk

        input:
            args:       cmd line arguments sys.argv[1:]
            dbh:        handler for result database
        """

        logger.info('starting plugin %s', __name__)
        start_time = datetime.now()

        # parse arguments
        opts = parse(args)

        self.extractfile = opts.extractfile
        self.dbfile = opts.dbfile
        self.timeout = opts.timeout
        self.nthreads = opts.nthreads
        self.batchsize = opts.batchsize

        # only update the database file, then quit, nothing else
        if opts.update:
            if not self.dbfile:
                print 'Please give me a location to save the data to (-dbfile)'
                sys.exit(1)

            # read config
            config = ConfigParser.ConfigParser()
            with __builtin__.openany(opts.config, 'r') as config_fd:
                config.readfp(config_fd)

            self.ripedb_mirror = config.get('mirror', 'ripedb_mirror').split(':')
            retry_interval = config.getfloat('mirror', 'retry_interval')
            max_retries = config.get('mirror', 'max_retries')

            retries = 0
            print 'Updating %s' % self.dbfile
            r = None
            while retries < max_retries:
                try:
                    r = self.update_db()
                except Exception as e:
                    logger.warning('Error updating ripe database: %s', e)
                if r:
                    print 'Update successful'
                    break
                else:
                    print 'Update failed'
                    print 'Automatic Retry in %fs ...' % retry_interval
                    retries += 1
                    time.sleep(retry_interval)
            if r is None:
                print 'Update failed, terminating %s' % __name__
                sys.exit(1)
        else:
            # do the search
            self.searchstrings = []
            if opts.searchstring:
                self.searchstrings = map(unicode.upper, map(unicode, opts.searchstring))
            if opts.searchfile:
                # lets just assume that there wont be huuuge amounts of search
                # strings, so we can load all of them without clogging up the ram
                with codecs.getreader('ISO-8859-1'(__builtin__.openany(opts.searchfile, 'r'))) as f:
                    self.searchstrings.extend(map(unicode.upper, f.read().splitlines()))

            # create dictionary searchstring -> results
            self.inetnums = {}

            self.dbh = dbh
            self.extract()
            self.processinetnums()
            self.output()

        print("\nfinished in %fs" % secs(start_time))

    def update_db(self):

        """ get the gzipped ripe database and save it to disk """

        try:
            f = __builtin__.openshared(self.dbfile, 'wb')
        except Exception as e:
            raise Exception("Can not open %s -> %s" % (self.dbfile, str(e)))
        s = socket.socket()
        s.settimeout(self.timeout)
        host, port = self.ripedb_mirror
        try:
            s.connect((host, int(port)))
        except Exception as e:
            raise Exception("Can not connect to %s:%d -> %s" % (host, int(port), str(e)))
        success = True
        l = 0
        while True:
            try:
                buf = s.recv(1024)
                if not buf:
                    break
                if "Sorry, we are out. Come back later!" in buf:
                    # repeat in 5 min
                    print 'Please try again later'
                    success = False
                    break
                f.write(buf)
                l += len(buf)
                sys.stdout.write('\rRecieved Bytes: %s' % l)
            except socket.timeout:
                break
        f.close()
        s.close()
        print ''
        return success

    def extract(self):

        """
        extract the inetnums, matching the searchterms, from the ripe database
        """

        fout = None
        if self.extractfile:
            fout = __builtin__.openany(self.extractfile, "w")
            fout = codecs.getwriter('ISO-8859-1')(fout)
            #fout = codecs.open(self.extractfile, "w", 'utf-8')

        f = __builtin__.openshared(self.dbfile, "r")

        # handle possible gzip compression:
        #   read magic byte
        #   first lines are just comments anyway so no one cares about 2 missing bytes
        mb = f.read(2)
        if mb == '\x1f\x8b':
            # probably a gzipped file
            # good enough check for our restricted case
            #f.close()
            #f = gzip.open(self.dbfile, 'r')
            f.seek(0)
            f = gzip.GzipFile(fileobj=f)
        else:
            #f.close()
            f.seek(0)
            f = codecs.getreader('ISO-8859-1')(f)
            #f = __builtin__.openany(self.dbfile, "r")
            #f = codecs.open(self.dbfile, "r", 'ISO-8859-1')

        # match any of the searchstrings
        pat = re.compile('|'.join(map(re.escape, self.searchstrings)), re.IGNORECASE)

        pos = 0
        # process ripe file in batches
        out_q = multiprocessing.Queue()
        data_buf = ''
        chunk = self.batchsize / self.nthreads
        done = False
        out_lock = None
        if self.extractfile:
            out_lock = threading.Lock()
        while not done:
            procs = []
            # read data to feed n threads
            for i in range(self.nthreads):
                # we may have some data buffered from the previous round
                data = data_buf
                l_buf = len(data_buf)
                data_buf = ''
                try:
                    data += f.read(chunk - l_buf)
                except:
                    done = True
                if not data:
                    done = True
                    break
                l_buf = 0
                # don't forget to clear the buffer
                # read until entry is complete, so we don't have
                # to deal with searching inet nums across
                # multiple data chunks
                while not done and data[-2:] != '\n\n':
                    try:
                        data_buf += f.read(1024)
                    except:
                        done = True
                        break
                    if not data_buf:
                        done = True
                        break
                    idx = data_buf.find('\n\n')
                    # we have found the end of our entry
                    if idx >= 0:
                        data += data_buf[:idx + 2]
                        data_buf = data_buf[idx + 2:]
                        break
                pos += len(data)
                if data:
                    sys.stdout.write(row_fmt.format('', '', 'processed: %d byte' % pos) + "\r")
                    sys.stdout.flush()
                    p = multiprocessing.Process(target=MatchWorker, args=[data, pat, out_q, fout, out_lock])
                    procs.append(p)
                    p.start()
                if done:
                    break
            # join threads so that we dont flood the ram
            for p in procs:
                p.join()
            # get results:
        while True:
            try:
                m, mstr, line = out_q.get(False)
                #self.inetnums[m.upper()].append(line)
                self.inetnums[mstr] = line
            except Queue.Empty:
                break
        if self.extractfile:
            fout.close()

    # self.inetnums contains entries which look like this: "111.222.111.0-111.222.111.256"
    # they need to be merged and ordered
    def processinetnums(self):
        pass
        #for s,num in self.searchstrings:
        #for s in self.inetnums.keys():
        #    self.inetnums[s] = self.mergeinetnums(self.inetnums[s])
        #    self.inetnums[s] = self.sortinetnums(self.inetnums[s])
        #print repr(self.inetnums)

    def mergeinetnums(self, inetnums):
        ilen = len(inetnums)
        i = 0
        while i < ilen - 1:
            j = i + 1
            while j < ilen:
                ip1range = inetnums[i]
                ip1_1 = ip1range.split("-")[0]
                ip1_2 = ip1range.split("-")[1]
                ip2range = inetnums[j]
                ip2_1 = ip2range.split("-")[0]
                ip2_2 = ip2range.split("-")[1]
                # check if they overlap
                if RIPEDBExtractor.isbetween(ip1_1, ip2_1, ip2_2) or \
                        RIPEDBExtractor.isbetween(ip1_2, ip2_1, ip2_2) or \
                        RIPEDBExtractor.isbetween(ip2_1, ip1_1, ip1_2) or \
                        RIPEDBExtractor.isbetween(ip2_2, ip1_1, ip1_2):
                    #print("Merge ranges: " + self.inetnums[i] + " ---- " + self.inetnums[j])
                    # create new network range
                    if RIPEDBExtractor.isgreater(ip1_1, ip2_1):
                        ip3_1 = ip2_1
                    else:
                        ip3_1 = ip1_1
                    if RIPEDBExtractor.isgreater(ip1_2, ip2_2):
                        ip3_2 = ip1_2
                    else:
                        ip3_2 = ip2_2
                    ip3range = ip3_1 + "-" + ip3_2
                    #print("New range: " + ip3range)
                    inetnums[i] = ip3range
                    # use self.inetnums.pop(j) alternatively
                    del inetnums[j]
                    j = j - 1
                    ilen = ilen - 1
                j = j + 1
            i = i + 1
        return inetnums

    # bubblesort
    def sortinetnums(self, inetnums):
        ilen = len(inetnums)
        if ilen == 1:
            return
        i = ilen - 1
        while i >= 1:
            j = 0
            while j < i:
                ip1range = inetnums[j]
                ip1_1 = ip1range.split("-")[0]
                #ip1_2 = ip1range.split("-")[1]
                ip2range = inetnums[j + 1]
                ip2_1 = ip2range.split("-")[0]
                #ip2_2 = ip2range.split("-")[1]
                if RIPEDBExtractor.isgreater(ip1_1, ip2_1):
                    temp = inetnums[j]
                    inetnums[j] = inetnums[j + 1]
                    inetnums[j + 1] = temp
                j = j + 1
            i = i - 1
        return inetnums

    def output(self):
        #print("Network ranges:")
        for s, inetnum in self.inetnums.items():
            if not inetnum or not isinstance(inetnum, str):
                logger.warning('Got empty inetnum for %s', s)
                continue
            if self.dbh:
                for ip_tup in cUtil.mkIP2(inetnum, noResolve=True, noSplit=True):
                    try:
                        ip = ip_tup[0]
                    except:
                        ip = ip_tup
                    self.dbh.add(ccd.RipescanResult(
                        ip=ip,
                        search=s))

    @staticmethod
    # return True if ipaddr1 > ipaddr2
    # an ipaddr looks like this: "111.222.111.0"
    def isgreater(ipaddr1, ipaddr2):
        i1_1 = int(ipaddr1.split(".")[0])
        i2_1 = int(ipaddr2.split(".")[0])
        if i1_1 < i2_1:
            return False
        elif i1_1 > i2_1:
            return True
        i1_2 = int(ipaddr1.split(".")[1])
        i2_2 = int(ipaddr2.split(".")[1])
        if i1_2 < i2_2:
            return False
        elif i1_2 > i2_2:
            return True
        i1_3 = int(ipaddr1.split(".")[2])
        i2_3 = int(ipaddr2.split(".")[2])
        if i1_3 < i2_3:
            return False
        elif i1_3 > i2_3:
            return True
        i1_4 = int(ipaddr1.split(".")[3])
        i2_4 = int(ipaddr2.split(".")[3])
        if i1_4 < i2_4:
            return False
        elif i1_4 > i2_4:
            return True
        return False

    @staticmethod
    def isgreaterthan(ipaddr1, ipaddr2):
        return not RIPEDBExtractor.isgreater(ipaddr2, ipaddr1)

    @staticmethod
    # Return True if ipaddr >= ipaddrlow and ipaddr <= ipaddrhigh
    def isbetween(ipaddr, ipaddrlow, ipaddrhigh):
        return RIPEDBExtractor.isgreaterthan(ipaddr, ipaddrlow) and RIPEDBExtractor.isgreater(ipaddrhigh, ipaddr)

    @staticmethod
    # iprange in the form "111.222.111.0-111.222.111.256"
    # http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
    def printiprange(iprange):
        start_ip = iprange.split("-")[0]
        end_ip = iprange.split("-")[1]
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        print(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i - 1] += 1
            yield (".".join(map(str, temp)))
        raise StopIteration


def checkiffileexists(path):
    try:
        __builtin__.openany(path, "r")
    except IOError:
        print("Unable to open " + path)
        exit(1)
