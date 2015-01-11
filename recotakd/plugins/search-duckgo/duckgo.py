#!/usr/bin/env python
"""This module executes a query on duckduckgo search engine"""
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

import __builtin__
import argparse
import threading
import os
import random
import time

import logging
import sys
import hashlib
import httpheader
import gzip

from io import BytesIO
from time import strftime
from multiprocessing import Queue

import ccdClasses as ccd

try:
    from bs4 import BeautifulSoup
except ImportError:
    from BeautifulSoup import BeautifulSoup
    BeautifulSoup.find_all = BeautifulSoup.findAll
from Queue import Empty
from urllib import quote_plus
from urlparse import urlparse
from urllib import urlencode
from httplib import HTTPConnection
from httplib import HTTPSConnection
from httplib import HTTPException
from httplib import IncompleteRead


__author__ = "curesec"
__version__ = "0.0.1"
__plgname__ = "duckgo"

#logging.basicConfig(filename="duckquery.log", level=logging.INFO)
logging = logging.getLogger(__name__)
#TODO add logging.FileHandler to write to duckquery.log file

LINKLIST = Queue()

SAVED_COUNT_LOCK = threading.Lock()
DUCKDUCKGO_HOST = "duckduckgo.com"
DUCKDUCKGO_URL = "http://duckduckgo.com/html"

HEADER_CONTENT_TYPE = "application/x-www-form-urlencoded"
HEADER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
SAVED_COUNT = 0


class DuckQuery(threading.Thread):
    """Class which implements the module functions"""

    def __init__(self, dbh=None, event=None):
        threading.Thread.__init__(self)
        self.query = None
        self.count = None
        self.stop = event
        self.event = event
        self.output_directory = None
        self.thread_count = None
        self.dbh = dbh
        self.query_id = None

    def set_query(self, query):
        """set the query string object attribute"""

        self.query = query

    def calc_query_id(self, query):
        """calculate the query od from timestamp and query string"""

        _time = strftime("%Y-%m-%d_%H:%M:%S")
        query_id_hash = hashlib.sha256(str(_time) + query.encode("utf-8"))
        query_id = query_id_hash.hexdigest()
        self.query_id = query_id

    def set_query_id(self, query_id):
        """set the pre calculated query id object attribute"""

        self.query_id = query_id

    def set_count(self, count):
        """set the count object attribute"""

        self.count = count

    def parse_arguments(self, args):
        """Parse all cli program arguments."""

        parser = argparse.ArgumentParser(
            prog=__plgname__,
            description="Examples: \n" +
            "\t" + __plgname__ + " -q 'hello world' -c 400 -o duck -t 6"
        )

        parser.add_argument(
            "-q",
            help = "search query",
            nargs = "+",
            required = True,
            )

        parser.add_argument(
            "-c",
            help = "query result count (default = 10)",
            nargs = 1,
            required = False,
            )

        parser.add_argument(
            "-o",
            help = "output directory name (default = output)",
            nargs = 1,
            required = False,
            )

        parser.add_argument(
            "-t",
            help = "thread count (default = 1)",
            nargs = 1,
            required = False,
            )

        if not args:
            parser.print_help()
            sys.exit(1)

        arguments, _ = parser.parse_known_args(args)

        self.query = ""

        if (arguments.q):
            for tmp_query in arguments.q:
                self.query += (str(tmp_query) + " ")

        if (arguments.c):
            self.count = int(arguments.c[0])
        else:
            self.count = 10

        if (arguments.o):
            self.output_directory = str(arguments.o[0])
        else:
            self.output_directory = "output"

        if (arguments.t):
            self.thread_count = int(arguments.t[0])
        else:
            self.thread_count = 1

    @staticmethod
    def get_http_header():
        """get header from http-header module"""

        random_index = random.randint(0, len(httpheader.http_header) - 1)

        return httpheader.http_header[random_index]

    def resolve_http_redirect(self, url, header, dc_anchor, duck_s, r_type,
                              depth=0):
        """send request to url and return result"""

        if (depth > 10):
            raise Exception("Redirected " + depth + " times, giving up.")

        header["Host"] = DUCKDUCKGO_HOST

        parsed_url = urlparse(url, allow_fragments=True)

        if (parsed_url.scheme == "http"):
            conn = HTTPConnection(parsed_url.netloc)
        elif (parsed_url.scheme == "https"):
            conn = HTTPSConnection(parsed_url.netloc)
        else:
            conn = HTTPConnection(parsed_url.netloc)

        path = parsed_url.path

        if parsed_url.query:
            path += "?" + parsed_url.query

        if (r_type == "POST"):
            if (dc_anchor == None and duck_s == None):
                params = urlencode({
                    "q" : self.query,
                    "kl" : "us-en",
                    "b" : ""
                    }
                    )
            else:
                params = urlencode([
                    ("q", self.query),
                    ("s", duck_s),
                    ("o", "json"),
                    ("dc", dc_anchor),
                    ("api", "d.js"),
                    ("kl", "us-en")
                    ]
                    )

            header["Content-type"] = HEADER_CONTENT_TYPE
            header["Accept"] = HEADER_ACCEPT

            try:
                conn.request("POST", path, params, header)
            except (UnicodeEncodeError, OSError):
                conn.close()
                logging.error("Timeout, OSError")
                raise Exception("oserror or unicodeencodeerror")

        else:
            try:
                conn.request("GET", path, None, header)
            except (UnicodeEncodeError, OSError):
                conn.close()
                logging.error("Timeout, OSError")
                raise Exception("oserror or unicodeencodeerror")

        try:
            res = conn.getresponse()
        except HTTPException:
            logging.error("HTTPException")
            raise Exception("HTTPException")

        if (conn.sock):
            conn.sock.close()
            conn.sock = None

        if (res != None):
            headers = dict(res.getheaders())
        else:
            raise Exception("no header")

        loc_key = None

        if ("Location" in headers):
            loc_key = "Location"
        elif ("location" in headers):
            loc_key = "location"

        if (loc_key != None and headers[loc_key] != url):
            if ("IndexRedirect" in headers[loc_key]):
                print("IndexRedirect, exiting")
                exit(1)


            return self.resolve_http_redirect(
                headers[loc_key],
                header,
                dc_anchor,
                duck_s,
                r_type,
                depth+1
                )
        else:

            return res, headers

    @staticmethod
    def filter_result(link):
        """filter the found results"""

        parsed_link = urlparse(link)

        if (parsed_link.netloc and ("duckgo" not in parsed_link.netloc)):
            return link

    def search(self, start=0):
        """execute the search"""

        try:
            self.output_directory = os.path.join(__builtin__.openhome.base_dir, self.output_directory)
        except:
            pass

        try:
            os.mkdir(self.output_directory)
        except OSError as err:
            logging.error("Error while creating output directory:'%s'", err)

        if not os.path.exists(self.output_directory):
            logging.error("Directory missing '%s'. Aborting.", self.output_directory)
            return

        stop = self.count
        query = self.query
        hashes = set()
        first_flag = True

        query = quote_plus(query)

        linklist_file = open(
            os.path.join(
                self.output_directory,
                "linklist_%s_%s" % (
                    query,
                    str(strftime("%Y-%m-%d_%H:%M:%S"))
                )),
            "w"
        )

        url = DUCKDUCKGO_URL

        duck_s = None
        dc_anchor = None

        while not stop or start < stop:
            if (not first_flag):
                time.sleep(3.0)

            header = self.get_http_header()
            response, headers = self.resolve_http_redirect(
                url,
                header,
                dc_anchor,
                duck_s,
                "POST"
                )

            contenc_key = None

            if ("Content-Encoding" in headers):
                contenc_key = "Content-Encoding"
            elif ("content-encoding" in headers):
                contenc_key = "content-encoding"

            if (contenc_key != None and
                    headers[contenc_key] == 'gzip'):
                gzip_file = gzip.GzipFile(
                    fileobj=BytesIO(response.read()),
                    mode="rb"
                    )
                html = gzip_file.read()
            else:
                html = response.read()

            response.close()

            soup = BeautifulSoup(html)

            try:
                dc_anchor_list = soup.find_all("input", {"name" : "dc"})
            except:
                dc_anchor_list = soup.findAll("input", {"name" : "dc"})

            for dc_elem in dc_anchor_list:
                dc_anchor = dc_elem["value"]

            a_anchors = []
            s_anchors = soup.find(id="links")
            if s_anchors:
                try:
                    a_anchors = s_anchors.find_all("a", "large")
                except:
                    a_anchors = s_anchors.findAll("a", "large")
            else:
                print('No links found')

            abort = soup.find("span", {"class" : "no-results"})

            for a_elem in a_anchors:
                if (start >= stop):
                    break

                try:
                    link = a_elem["href"]
                except KeyError:
                    continue

                link = self.filter_result(link)

                if (link != None):
                    link_hash = hash(link)

                    if (link_hash in hashes):
                        continue

                    hashes.add(link_hash)

                    name = hashlib.sha256(link.encode("utf-8")).hexdigest()

                    linklist_file.write("sha256: " + name +
                                        " link: " + link + "\n")
                    start += 1
                    LINKLIST.put(link)
                else:
                    continue

            if (abort != None):
                break

            if (first_flag):
                duck_s = 30
                first_flag = False
            else:
                duck_s += 50

    def _database_add_result(self, link, success):
        """method which saves a search result into database"""

        global SAVED_COUNT

        SAVED_COUNT_LOCK.acquire()

        try:
            SAVED_COUNT += 1

            if (success):
                logging.debug("%s saved: %s", str(SAVED_COUNT), link)
                print("%s saved: %s"% (str(SAVED_COUNT), link))
            else:
                logging.debug("%s not saved, see log: %s",
                              str(SAVED_COUNT), link)
                print("%s not saved, see log: %s"% \
                              (str(SAVED_COUNT), link))
        finally:
            SAVED_COUNT_LOCK.release()

        if (self.dbh):
            se_result = ccd.SELinkResult(
                qid = self.query_id,
                host = DUCKDUCKGO_HOST,
                query = self.query,
                count = self.count,
                link = link,
                success = success,
                )
            self.dbh.add(se_result)

    def run(self):

        while True:
            while(not self.stop.is_set()):
                success = True

                try:
                    link = LINKLIST.get(timeout=1)
                except Empty:
                    self.event.set()
                    continue

                link_orig = link

                try:
                    header = self.get_http_header()

                    response, headers = self.resolve_http_redirect(
                        link,
                        header,
                        None,
                        None,
                        "GET"
                        )

                except (IOError, HTTPException, Exception):
                    success = False
                    self._database_add_result(link_orig, success)

                    continue

                contenc_key = None

                if ("Content-Encoding" in headers):
                    contenc_key = "Content-Encoding"
                elif ("content-encoding" in headers):
                    contenc_key = "content-encoding"

                if (contenc_key != None and
                        headers[contenc_key] == 'gzip'):
                    try:
                        buf = BytesIO(response.read())
                        gzip_file = gzip.GzipFile(fileobj=buf, mode="rb")
                        data = gzip_file.read()
                    except IncompleteRead:
                        success = False
                        self._database_add_result(link_orig, success)

                        continue
                else:
                    try:
                        data = response.read()
                    except IncompleteRead:
                        success = False
                        self._database_add_result(link_orig, success)

                        continue

                link = hashlib.sha256(link.encode("utf-8")).hexdigest()

                self._database_add_result(link_orig, success)

                save = os.path.join(self.output_directory, link)
                fd_save = open(save, "wb")
                fd_save.write(data)
                fd_save.close()

            return
