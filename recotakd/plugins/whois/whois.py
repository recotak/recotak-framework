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
import logging
from Queue import Empty
import ConfigParser
import argparse
import sys
import threading

__version__ = 0.32
__author__ = "curesec"
__email__ = "curesec"

logging.basicConfig(filename="/dev/null")
logger = logging.getLogger("whois")
logger.setLevel(logging.DEBUG)

console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(process)d "
                                       "%(threadName)s -%(funcName)s "
                                       "[%(levelname)s] %(message)s"))
console.setLevel(logging.ERROR)
logger.addHandler(console)

from whoisworker import WhoisWorker
from ctools.ctools import printStatus
from ccdClasses import WhoisResult


def print_whois_resp(data, indent=''):
    if isinstance(data, str) or isinstance(data, unicode):
        print indent + data
    else:
        for field in data:
            if isinstance(field, str) or isinstance(field, unicode):
                print indent + field
            elif isinstance(field, dict):
                for key, subfield in field.items():
                    print indent + key
                    print_whois_resp(subfield, indent + '\t')


def print_result(result_queue, dbh=None):
    countdown = 3
    # run until a stop event is received
    while True:

        # wait maximal 1 second for an element
        # otherwise raise 'empty' exception
        try:
            res = result_queue.get(True, 1)
        except (Empty, EOFError):
            # If no element is available, continue.
            # Though, it check whether thread is
            # needed.
            if not countdown:
                break
            countdown -= 1
            continue

        #f.write(ip_clean + "\n")
        print '-' * 80
        print_whois_resp(res)
        print ''
        logger.info('Adding whois result1')
        if dbh:
            logger.info('Adding whois result %s', res)
            try:
                query = res[2]
                logger.info('query %s', query)
                result = {}
                result["adminhandle"] = []
                result["techhandle"] = []
                result["country"] = []
                result["inetnum"] = []
                result["netname"] = []
                for k, v in res[3].items():
                    #result = res[3]
                    result[k] = v
                logger.debug("res=%s", result)
                db_res = WhoisResult(
                    ip=query["host"],
                    adminhandle=" ".join(result["adminhandle"]),
                    techhandle=" ".join(result["techhandle"]),
                    country=" ".join(result["country"]),
                    inetnum=" ".join(result["inetnum"]),
                    netname=" ".join(result["netname"])
                )
                logger.debug("db_res=%s", db_res)
                dbh.add(db_res)
            except KeyError as err:
                logger.warning("Invalid whois result found. No such key: %s", err)
            except Exception as err:
                logger.warning("Failed to store in db:%s", err)

        result_queue.task_done()


class Whois(object):

    def __init__(self,
                 config_fn="whois.conf",
                 threads=3,
                 rmt_logger=None,
                 dbh=None,
                 ):
        if rmt_logger:
            global logger
            logger = rmt_logger

        self.THREADS = threads
        self.result_printer_thread = None
        self.whois_worker_thread = []
        self.dbh = dbh

        # config
        config = ConfigParser.RawConfigParser()
        with openany(config_fn, 'r') as fp:
            config.readfp(fp)

        # read config
        self.PORT = config.getint('Server', 'Port')
        self.servers = config.get('Server', 'WhoisServer').split(",")
        self.PERSONALINFORMATION = config.getboolean('Server',
                                                     'personalInformation')
        self.SOCKS = config.getboolean("Server", "useSocks")
        self.SOCKSSERVER = config.get("Server", "socksServer")

    def exitProgram(self):
        self.result_printer_thread.join()

        # stopping whois worker
        logger.debug("Stopping whoisWorker")
        for thread in self.whois_worker_thread:
            thread.stop()

        logger.debug("Chaos and destruction - "
                         "I think my work is done. bye")

    def processHosts(self, hosts):
        logger.debug("processing host %s", hosts)

        # pass important stuff to Whois worker
        WhoisWorker.servers = self.servers
        WhoisWorker.port = self.PORT
        WhoisWorker.PERSONALINFORMATION = self.PERSONALINFORMATION
        WhoisWorker.useSocks = self.SOCKS
        ss = self.SOCKSSERVER.split(":")
        socksServer = (ss[0], int(ss[1]))
        WhoisWorker.socksServer = socksServer

        for host in hosts:
            # add to queue
            WhoisWorker.target_queue.put(host)

        printStatus(WhoisWorker.target_queue)

        parser_regex =  "parser.regex"
        #parser_regex =  "%s/parser.regex"%self.rootpath

        # create and launch worker
        # to process hosts
        for _ in range(self.THREADS):
            logger.debug("Instancing new whoisWorker.")
            thread = WhoisWorker(
                                 rmt_logger=logger,
                                 parser_regex_fn=parser_regex)
            thread.setDaemon(True)
            thread.start()
            self.whois_worker_thread.append(thread)

        # create and txt worker
        # to build txt output
        result_printer_thread = threading.Thread(target=print_result,
                                             args=(WhoisWorker.result_queue,
                                                   self.dbh))
        self.result_printer_thread = result_printer_thread
        result_printer_thread.start()
        result_printer_thread.join()

        self.exitProgram()


def parse(args):
    parser = argparse.ArgumentParser(
        prog = "python2 whois.py",
        description = "whois resolver v%d" % __version__,
        epilog="""Examples:
        whois.plg 91.250.101.170
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-c", help="path to config file",
                              default="whois.conf")
    parser.add_argument("-nt", help="amount of threads to scan with",
                              default=3,
                              type=int)
    parser.add_argument("-v", help="verbosity for more details",
                              action="store_true")
    known, unknown = parser.parse_known_args(args)

    if known.v:
        console.setLevel(logging.DEBUG)

    if not len(unknown)==1:
        parser.print_help()
        print("Invalid arguments. Expecting host to scan, but "
              "did not find them. So the answer my friend, is "
              "blowing in the wind..")
        sys.exit(1)

    hosts = unknown[0].split(",")

    return (known.c, known.nt), hosts

if __name__ == "__main__":
    _args, _hosts = parse(sys.argv[1:])
    whois = Whois(*_args)
    whois.processHosts(_hosts)

