#!/usr/bin/env python
"""This module initializes the bing search plugin"""
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

from bing import BingQuery
import ccdClasses as ccd

LOG_IP = "127.0.0.1"
LOG_PORT = 3002

def main(f_getSocket, rootpath, dbh, args):
    """bing search plugin main function"""

    socket_handler = logging.handlers.SocketHandler(LOG_IP, LOG_PORT)
    socket_handler.setLevel(logging.DEBUG)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(socket_handler)
    logger.debug("starting plugin %s", __name__)

    bing = BingQuery(rootpath, dbh)
    bing.parse_arguments(args)
    bing.calc_query_id(bing.query)

    event = threading.Event()
    threads = []
    bing.search()
    time.sleep(0.05)

    for _ in range(bing.thread_count):
        bing_thread = BingQuery(rootpath, dbh, event)
        bing_thread.setDaemon(True)
        bing_thread.output_directory = bing.output_directory
        bing_thread.set_query(bing.query)
        bing_thread.set_count(bing.count)
        bing_thread.set_query_id(bing.query_id)
        bing_thread.start()
        threads.append(bing_thread)

    for bing_thread in threads:
        bing_thread.join()

def register():
    """method which registers the plugin"""

    plugin = ccd.Plugin(
        "bing",
        ["searchengines"],
        dbtemplate=[ccd.Tmpl.SE_LINK_CRAWLER])
    plugin.execute = main
    return plugin


