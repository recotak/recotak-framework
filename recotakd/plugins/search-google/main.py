#!/usr/bin/env python
"""This module initializes the google search plugin"""
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
import logging
import threading

from google import GoogleQuery
import ccdClasses as ccd

__author__ = "curesec"
__version__ = "0.0.1"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def main(dbh, args):
    """method which executes the google search plugin"""

    logger.debug("starting plugin %s", __name__)

    google = GoogleQuery(dbh)
    google.parse_arguments(args)
    google.calc_query_id(google.query)
    google.search()

    event = threading.Event()
    threads = []
    time.sleep(0.05)

    for _ in range(google.thread_count):
        google_thread = GoogleQuery(dbh, event)
        google_thread.setDaemon(True)
        google_thread.output_directory = google.output_directory
        google_thread.set_query(google.query)
        google_thread.set_count(google.count)
        google_thread.set_query_id(google.query_id)
        google_thread.start()
        threads.append(google_thread)

    for google_thread in threads:
        google_thread.join()


def register():
    """method which registers the plugin"""

    plugin = ccd.Plugin(
        "google",
        ["searchengines"],
        dbtemplate=[ccd.Tmpl.SE_LINK_CRAWLER])
    plugin.execute = main
    return plugin


if __name__ == '__main__':
    import sys
    main(None, sys.argv[1:])
