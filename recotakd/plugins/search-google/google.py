#!/usr/bin/env python
"""This module executes a google query and saves the result's in an
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
output directory.

compatibility: python2.7/python3
"""

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
import socket
import gzip
import socks4
import config

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
from urlparse import parse_qs
from httplib import HTTPConnection
from httplib import HTTPSConnection
from httplib import HTTPException
from httplib import IncompleteRead

__author__ = "curesec"
__version__ = "0.0.2"

GOOGLE_URL_SEARCH = "http://www.google.%s/search?hl=%s&q=%s&btnG=Google+Search"
GOOGLE_URL_NEXT_PAGE = "http://www.google.%s/search?hl=%s&q=%s&start=%d"
GOOGLE_URL_SEARCH_NUM = "http://www.google.%s/search?hl=%s&q=%s&num=%d&btnG=Google+Search"
GOOGLE_URL_NEXT_PAGE_NUM = "http://www.google.%s/search?hl=%s&q=%s&num=%d&start=%d"
GOOGLE_URL_TLD = "com"
GOOGLE_URL_LANG = "en"
GOOGLE_HOST = "www.google.com"

LINKLIST = Queue()
logging.basicConfig(filename='googlequery.log', level=logging.INFO)
SAVED_COUNT_LOCK = threading.Lock()
SAVED_COUNT = 0

class GoogleQuery(threading.Thread):
    """Google Query Class"""

    def __init__(self, dbh=None, event=None):
        threading.Thread.__init__(self)
        self.query = None
        self.count = None
        self.output_directory = None
        self.stop = event
        self.event = event
        self.thread_count = None
        self.socks = None
        self.dbh = dbh
        self.query_id = None
        self.num = None

    def set_query(self, query):
        """set the query string object attribute"""

        self.query = query

    def calc_query_id(self, query):
        """calculate the query id from timestamp and query string"""

        self.query_id = hashlib.sha256(
            str(strftime("%Y-%m-%d_%H:%M:%S")) +
            query.encode("utf-8")
            ).hexdigest()

    def set_query_id(self, query_id):
        """set the pre calculated query id object attribute"""

        self.query_id = query_id

    def set_count(self, count):
        """set the count object attribute"""

        self.count = count

    def parse_arguments(self, args):
        """Parse all cli program arguments."""

        parser = argparse.ArgumentParser(
            prog="google",
            description = """
                example: ./googlequery.py -q "intitle: Live View" -c 500 -o
                intitlecams -t 10 -n 50
                """
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

        parser.add_argument(
            "-n",
            help = ("google results per page, possible values:"
                    "10,20,30,40,50,100 (default = 10)"),
            nargs = 1,
            required = False,
            )

        if (len(args) == 0):
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

        self.socks = None

        if (arguments.n):
            self.num = int(arguments.n[0])

            if (self.num != 10 and
                self.num != 20 and
                self.num != 30 and
                self.num != 40 and
                self.num != 50 and
                    self.num != 100):
                logging.error("Error: wrong -n argument, read --help")
                exit(1)
        else:
            self.num = 10

    def _resolve_http_redirect(self, url, header, depth=0):
        """this method sends http(s) requests and also resolves redirects"""

        if depth > 10:
            raise Exception("Redirected " + str(depth) + " times, giving up.")

        parsed_url = urlparse(url, allow_fragments=True)

        if (parsed_url.scheme == "http"):
            conn = HTTPConnection(parsed_url.netloc)
        elif (parsed_url.scheme == "https"):
            conn = HTTPSConnection(parsed_url.netloc)
        path = parsed_url.path

        if (parsed_url.query):
            path += "?" + parsed_url.query

        try:
            conn.request("GET", path, None, header)
        except (OSError, UnicodeEncodeError):
            conn.close()
            raise Exception("OSError or UnicodeEncodeError")

        try:
            res = conn.getresponse()
        except (HTTPException):
            logging.error("HTTPException")
            raise Exception("HTTPException")

        if (conn.sock):
            conn.sock.close()
            conn.sock = None

        if (res != None):
            headers = dict(res.getheaders())
        else:
            raise Exception("Response empty")

        loc_key = None

        if ("Location" in headers):
            loc_key = "Location"
        elif ("location" in headers):
            loc_key = "location"

        if (loc_key != None and headers[loc_key] != url):
            if ("IndexRedirect" in headers[loc_key]):
                logging.error("IndexRedirect, exiting")
                exit(1)

            return self._resolve_http_redirect(
                headers[loc_key],
                header,
                depth+1
                )
        else:

            return res, headers

    @staticmethod
    def get_http_header():
        """static http-header getter method"""

        random_index = random.randint(0, len(httpheader.http_header) - 1)

        return httpheader.http_header[random_index]

    @staticmethod
    def filter_result(link):
        """static result-link filter method which checks for special strings in
           url
        """

        parsed_link = urlparse(link)

        if (parsed_link.netloc and ("google" not in parsed_link.netloc)):
            return link

        if (link.startswith("/url?")):
            link = parse_qs(parsed_link.query)["q"][0]

            parsed_link = urlparse(link, "http")

            if (parsed_link.netloc and
                    ("google" not in parsed_link.netloc)):
                return link

    def search(self, num=10, start=0, pause=4.0):
        """method which executes the search"""

        self.output_directory = os.path.join(__builtin__.openhome.base_dir, self.output_directory)

        try:
            os.mkdir(self.output_directory)
        except OSError as err:
            logging.error("Error while creating output directory:'%s'", err)

        first_flag = True
        hashes = set()
        query = quote_plus(self.query)


        linklist_file = open(
            os.path.join(
                self.output_directory,
                "linklist_%s_%s" % (
                    query,
                    str(strftime("%Y-%m-%d_%H:%M:%S"))
                )),
            "w"
        )

        if (num == 10):
            url = GOOGLE_URL_SEARCH % (
                GOOGLE_URL_TLD,
                GOOGLE_URL_LANG,
                query
                )
        else:
            url = GOOGLE_URL_SEARCH_NUM % (
                GOOGLE_URL_TLD,
                GOOGLE_URL_LANG,
                query,
                num
                )

        while not self.count or start < self.count:
            if (not first_flag):
                time.sleep(pause)
                first_flag = False

            response, headers = self._resolve_http_redirect(
                url,
                self.get_http_header()
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
            s_anchors = soup.find(id="search")

            if (s_anchors != None):
                try:
                    a_anchors = s_anchors.find_all("a")
                except:
                    a_anchors = s_anchors.findAll("a")
            else:
                continue

            for entry in a_anchors:
                if (start >= self.count):
                    break

                try:
                    link = self.filter_result(entry["href"])
                except KeyError:
                    continue

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

            if not soup.find(id="nav"):
                break

            if num == 10:
                url = GOOGLE_URL_NEXT_PAGE % (
                    GOOGLE_URL_TLD,
                    GOOGLE_URL_LANG,
                    query,
                    start
                    )
            else:
                url = GOOGLE_URL_NEXT_PAGE_NUM % (
                    GOOGLE_URL_TLD,
                    GOOGLE_URL_LANG,
                    query,
                    num,
                    start
                    )

            first_flag = False

        linklist_file.close()

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
                host = GOOGLE_HOST,
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
                    response, headers = self._resolve_http_redirect(
                        link,
                        self.get_http_header()
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
                        gzip_file = gzip.GzipFile(
                            fileobj=BytesIO(response.read()),
                            mode="rb"
                            )
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
