
from ctools.dns.validate import is_domain
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
from ctools.dns.validate import is_ip
from whoisparser import Parser
from ctools import csockslib
from datetime import *
import collections
import threading
import logging
import socket
import Queue
import copy
import sys
import re

logger = logging.getLogger("whois.worker")
logger.setLevel(logging.DEBUG)

class FoundBetterWhoisServerException(Exception):
    def __init__(self, value="Found a whois server to follow."):
        Exception.__init__(self)
        self.value = value
    def __str__(self):
        return repr(self.value)

class LeaveTryBlockException(Exception):
    def __init__(self, value="Continue with next value."):
        Exception.__init__(self)
        self.value = value
    def __str__(self):
        return repr(self.value)

class MultipleRequestException(Exception):
    def __init__(self, value="A request oughtn't to be sent multiple time."):
        Exception.__init__(self)
        self.value = value
    def __str__(self):
        return repr(self.value)

class UnsexyResponseException(Exception):
    def __init__(self, value="Response feels uncharming. May be empty?"):
        Exception.__init__(self)
        self.value = value
    def __str__(self):
        return repr(self.value)

class WhoisWorker(threading.Thread):
    # queue with ips to whois for
    # import for the worker threads
    target_queue = Queue.Queue()
    result_queue = Queue.Queue()

    # named tuple that is used for
    # storing information within
    # the Resolved list
    Request = collections.namedtuple('Request', 'name rangestart rangeend')

    # if no personal information are
    # request, the interesting suff is missing.
    # ripe only allows a limited amount
    # of requests for personal information
    PERSONALINFORMATION = False

    # Socks configuration are set by
    # whois.py. Consider some default
    # values.
    useSocks = False
    socksServer = {}

    # if an ip already requested (or an ip range)
    # then save this host anyway. otherwise omit.
    saveRequestedIps = False

    # if an request was successful,
    # save query, nameOfQuery and
    # the netrange to avoid redundant
    # requests to an ip (or ip range)
    Resolved = []
    ResolvedLock = threading.Lock()

    ResolvedNIC = []
    ResolvedNICLock = threading.Lock()

    ResolvedNetnames = []
    ResolvedNetnamesLock = threading.Lock()

    logger = logging.getLogger(__name__)
    f_getSocket = None

    def __init__(self, rmt_logger=None,
                 parser_regex_fn="parser.regex"):
        if rmt_logger:
            logger = rmt_logger

        self.parser_regex_fn = parser_regex_fn
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()

    def stop(self):
        logger.debug("received stop signal")
        self.stop_event.set()

    def run(self):
        logger.debug("Entering run method.")

        # servers that were requested for
        # one whois lookup
        self._usedServers = []

        # connect to server
        self.__connectToServerSocket()

        # set ip
        ip = None

        # parser that processes the response
        logger.debug("Instancing parser..")
        self._parser = Parser(self.parser_regex_fn)

        # stop if not needed any more
        logger.debug("Entering loop for requesting hosts.")
        while not self.stop_event.isSet():

            # if we have no IP yet, get one
            if ip == None:
                try:
                    # get next ip
                    ip = WhoisWorker.target_queue.get(True, 1)
                except Queue.Empty:
                    # If query is empty or timed out,
                    # lets check whether thread is
                    # still needed.
                    continue

            # Ok, all fine until here - so let's start
            # processing!
            nameOfQuery = ip
            queryObject = {}
            resultObject = {}

            try:
                logger.debug("Requesting %s", ip)

                # check whether requested object
                # is of type ip or of type nic
                if is_ip(ip):
                    logger.debug("%s seems to be a valid IP", ip)

                    requestType = Parser.IPTYPE

                    nameOfQuery, \
                    queryObject, resultObject = self.__processIP(ip)


                # nic handles
                elif self.__validNIC(ip):
                    logger.debug("%s seems to be a valid NIC", ip)

                    requestType = Parser.NICTYPE

                    nameOfQuery, \
                    queryObject, resultObject = self.__processNIC(ip)


                # netname or a domain name
                elif is_domain(ip):
                        # if we have domain name, resolve first
                        # and request the ip. getAddr() returns
                        # a list of socket information (incl. ipv6)
                        try:
                            ip = socket.gethostbyname(ip)

                            # put ips onto stack
                            logger.debug("putting %s onto "
                                         "target_queue ",
                                         ip)
                            WhoisWorker.target_queue.put(ip)

                        except Exception as err:
                            logger.error("%s konnte nicht "
                                                     "aufgeloest werden: %s",
                                                     ip, err)

                        finally:
                            raise LeaveTryBlockException()


                else:
                    requestType = Parser.NETNAMETYPE

                    nameOfQuery, \
                    queryObject, resultObject = self.__processNetname(ip,
                                                                 requestType)

                    logger.debug("netname result=%s", resultObject)

                # finally store response in xml queue
                WhoisWorker.result_queue.put((requestType,
                                    nameOfQuery,
                                    queryObject,
                                    resultObject))


            except UnsexyResponseException:
                # if connection is unsexy (e.g. empty or
                # contains 'not found' etc), then reconnect
                # to another whois server
                self.__connectToServerSocket()
                continue
            except FoundBetterWhoisServerException:
                continue
            except MultipleRequestException:
                # response came with a better whois
                # server, therefore server is
                # reconnected to that server. So
                # give the new server a try
                logger.warning("MultipleRequestException for %s",
                                           ip)
            except LeaveTryBlockException:
                pass
            except Exception as err:
                # if something bad happens, clean
                # up an exit thread
                WhoisWorker.target_queue.task_done()
                raise err

            # notificate that task is done
            WhoisWorker.target_queue.task_done()
            ip = None
            self._usedServers = []

        logger.debug("Leaving run method.")

    def __processNetname(self, netname, requestType):
        logger.debug("netname:%s", netname)

        # Check whether netname is already requested
        nameOfQuery = self.__alreadyNetnameRequested(netname)
        queryObject = {}
        resultObject = {}

        if (nameOfQuery == None):
            # send request to whois server
            queryObject, resultObject = \
                    self.__sendRequestToWhoisServer(netname, requestType)

            nameOfQuery = netname
        else:
            logger.warning("netname %s already requested", netname)
            raise MultipleRequestException()

        retest = self.__alreadyNetnameRequested(netname)

        if (retest == None):

            retest = self.__alreadyNetnameRequested(netname)
            if (retest != None):
                logger.warning("netname %s already requested",
                                           netname)
                raise MultipleRequestException()

            logger.debug("adding %s to ResolvedNetnames",
                                     nameOfQuery)
            WhoisWorker.ResolvedNetnamesLock.acquire()
            WhoisWorker.ResolvedNetnames.append(nameOfQuery)
            sorted(WhoisWorker.ResolvedNetnames)
            WhoisWorker.ResolvedNetnamesLock.release()
        else:
            logger.warning("netname %s already requested",
                                       netname)
            raise MultipleRequestException()

        return nameOfQuery, queryObject, resultObject

    def __processNIC(self, nic):
        # Check whether nic is already requested
        nameOfQuery = self.__alreadyNICRequested(nic)
        queryObject = {}
        resultObject = {}

        if (nameOfQuery == None):
            logger.debug("requesting %s", nic)
            # send request to whois server
            queryObject, resultObject = \
                    self.__sendRequestToWhoisServer(nic, Parser.NICTYPE)

            nameOfQuery = nic
        else:
            logger.warning("nic %s already requested", nic)
            raise MultipleRequestException()

        retest = self.__alreadyNICRequested(nic)
        if (retest == None):

            retest = self.__alreadyNICRequested(nic)
            if (retest != None):
                logger.warning("nic %s already requested", nic)
                raise MultipleRequestException()

            logger.debug("adding %s to ResolvedNIC", nameOfQuery)
            WhoisWorker.ResolvedNICLock.acquire()
            WhoisWorker.ResolvedNIC.append(nameOfQuery)
            sorted(WhoisWorker.ResolvedNIC)
            WhoisWorker.ResolvedNICLock.release()
        else:
            logger.warning("nic %s already requested", nic)
            raise MultipleRequestException()

        return nameOfQuery, queryObject, resultObject

    def __processIP(self, ip):
        nameOfQuery = self.__alreadyIPRequested(ip)
        queryObject = {}
        resultObject = {}

        ip = ip.replace("\n","")

        # ip or range containing that ip not
        # yet requested
        if (nameOfQuery == None):
            # send request to whois server
            queryObject, resultObject = \
                    self.__sendRequestToWhoisServer(ip, Parser.IPTYPE)
            logger.debug("resultObject %s", resultObject)

            request = self.__extractNetrange(resultObject, ip)

            nameOfQuery = request.name

            # Put provided NIC handles on request list.
            # They will be requested by the next thread
            handles = self.__extractHandles(resultObject)
            for handle in handles:
                logger.debug("pushing %s to target_queue", handle)
                WhoisWorker.target_queue.put(handle)
        else:
            logger.warning("ip %s already requested", ip)
            raise MultipleRequestException()

        # already request an ip of the same netrange
        retest = self.__alreadyIPRequested(ip)
        if (retest == None):

            # retest again
            retest = self.__alreadyIPRequested(ip)
            if (retest != None):
                logger.warning("ip %s already requested", ip)
                raise MultipleRequestException()

            logger.debug("adding %s to ResolvedIP", nameOfQuery)
            WhoisWorker.ResolvedLock.acquire()
            WhoisWorker.Resolved.append(request)
            sorted(WhoisWorker.Resolved, key=lambda r: r.rangestart)
            WhoisWorker.ResolvedLock.release()
        else:
            logger.warning("ip %s already requested", ip)
            if WhoisWorker.saveRequestedIps:
                queryObject = dict(
                    host=ip
                )
            else:
                raise MultipleRequestException()

        return nameOfQuery, queryObject, resultObject

    def __extractHandles(self, resultObject):
        try:
            adminhandles = copy.copy(resultObject["adminhandle"])
        except:
            adminhandles = []

        try:
            techhandles = copy.copy(resultObject["techhandle"])
        except:
            techhandles = []
        adminhandles.extend(techhandles)

        try:
            netnames = copy.copy(resultObject["netname"])
        except:
            netnames = []

        adminhandles.extend(netnames)

        return adminhandles

    # extract netrange and save this
    # and the nameOfQuery in our Resolved
    # array
    def __extractNetrange(self, resultObject, ip):

        try:
            name = resultObject['netname'][0]
            netrange = resultObject['inetnum'][0].split(" - ")
            rangeStart = netrange[0]
            rangeEnd = netrange[1]
        except:
            name = ip
            rangeStart = ip
            rangeEnd = rangeStart
            netrangeString = ip

        # create request object to store
        request = WhoisWorker.Request(name=name,
                          rangestart=rangeStart,
                          rangeend=rangeEnd)

        return request

    def __alreadyNetnameRequested(self, netname):

        WhoisWorker.ResolvedNetnamesLock.acquire()

        nameOfQuery = self.__binarysearchNetname(
                            liste=WhoisWorker.ResolvedNetnames,
                            start=0,
                            end=len(WhoisWorker.ResolvedNetnames)-1,
                            keyword=netname)

        WhoisWorker.ResolvedNetnamesLock.release()
        logger.debug("searched for %s found %s",
                                 netname, nameOfQuery)

        return nameOfQuery

    def __alreadyNICRequested(self, nic):

        WhoisWorker.ResolvedNICLock.acquire()

        nameOfQuery = self.__binarysearchNIC(
                            liste=WhoisWorker.ResolvedNIC,
                            start=0,
                            end=len(WhoisWorker.ResolvedNIC)-1,
                            keyword=nic)

        WhoisWorker.ResolvedNICLock.release()
        logger.debug("searched for %s found %s",
                                 nic, nameOfQuery)

        return nameOfQuery


    def __alreadyIPRequested(self, ip):

        WhoisWorker.ResolvedLock.acquire()

        nameOfQuery = self.__binarysearchIP(
                            liste=WhoisWorker.Resolved,
                            start=0,
                            end=len(WhoisWorker.Resolved)-1,
                            keyword=ip)

        WhoisWorker.ResolvedLock.release()
        logger.debug("searched for %s found %s",
                                 ip, nameOfQuery)
        return nameOfQuery

    def __sendRequestToWhoisServer(self, ip, requestType):
        # send request
        query, time = self.__send(ip)

        # get response
        response = self.__fetch()

        # check response
        if self.__validateResponse(response, ip):
            queryObject = dict(
                host=ip,
                query=query,
                time=time,
                whoisserver=self._currentWhoisServer
            )

            resultObject = self._parser.parseWhoisResponse(
                    server=self._currentWhoisServer,
                    response=response,
                    responseType=requestType
            )

            # If whois server is provided in
            # whois database entry, then query
            # that server too.
            try:
                server = resultObject["whoisserver"]
                if server != None and len(server)>0 and \
                    server[0] != "" and server[0] != self._currentWhoisServer:
                    logger.debug("following whois server to %s",
                                             server[0])
                    self.__connectToServerSocket(server[0])
                    raise FoundBetterWhoisServerException()
            except:
                # result has no 'whoisserver' property
                pass

        # response validation failed
        else:
            raise UnsexyResponseException()

        return (queryObject, resultObject)

    def __validateResponse(self, response, ip):
        # if nothing found, raise an
        # exception
        if ("No match" in response) or \
                ("No entries" in response) or \
                ("does not contain domains" in response) or \
                ("not registered here" in response) or\
                ("Status: invalid" in response) or \
                ("Connection refused" in response) or \
                ("access denied" in response) or\
                ("This object represents all IPv4 addresses" in response) or\
                ("This IP address range" in response) or\
                ("IANA-BL" in response) or\
                ("Not allocated by" in response) or\
                ("NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK" in response) or\
                ("Query rate limit exceeded" in response):
            logger.warning("invalid response for %s", ip)
            return False

        # if response is bad
        if len(response)==0:
            logger.warning("Empty response from %s! for %s",
                                       self._currentWhoisServer, ip)
            return False

        logger.warning("received valid response from %s for %s",
                                   self._currentWhoisServer, ip)

        return True

    SEND = 0
    sendLock = threading.Lock()
    def __send(self, ip):
        if 'denic' in self._currentWhoisServer:
            query = "-T dn,ace -C US-ASCII %s \r\n" % (ip)
        elif 'ripe' in self._currentWhoisServer:
            ripeParam = "" if WhoisWorker.PERSONALINFORMATION else "-r"
            query = "%s %s\r\n" % (ripeParam, ip)
        elif "arin" in self._currentWhoisServer:
            query = "n + %s\r\n" % (ip)
        else:
            query = "%s\r\n" % (ip)

        WhoisWorker.sendLock.acquire()
        WhoisWorker.SEND += 1
        logger.debug("send=%s %s", WhoisWorker.SEND, repr(query))
        WhoisWorker.sendLock.release()
        time = str(datetime.now())
        self._socket.send(query)

        return query.strip(), time

    def __fetch(self):
        response = ''
        while True:
            d = self._socket.recv(4096)
            response += d
            if not d:
                break
        logger.debug("reponse=%s", repr(response))
        return response

    def __socksResolveHost(host):
        PORT = 80
        logger.debug("Resolving %s:%d using SOCKS..", host,PORT)

        raddr = (host, PORT)

        try:
            logger.debug("Sending resolve request..")
            host = csockslib.socks4a_resolveHost(WhoisWorker.socksServer,
                                                 raddr)
            logger.debug("host=%s" % repr(host))
        except Exception as err:
            logger.error(err)
            raise err

        return host

    def __connectToServerSocket(self, server=None):
        if server != None:
            self._currentWhoisServer = server
        else:
            self._currentWhoisServer = self.__selectWhoisServer()

        logger.debug("connecting to ... %s, (%s)",
                     self._currentWhoisServer,
                     self._usedServers)

        # import addresses
        raddr = (self._currentWhoisServer, WhoisWorker.port)

        # use SOCKS
        if WhoisWorker.useSocks:
            try:

                logger.debug("Connecting to SOCKS Server at %s:%s",
                                         WhoisWorker.socksServer[0],
                                         WhoisWorker.socksServer[1])

                self._socket = csockslib.socks4a_connect(
                                         WhoisWorker.socksServer,
                                         raddr)

                # redirect resolving requests to socks server
                socket.gethostbyname = self.__socksResolveHost

            except Exception as err:
                logger.error("Error while connecting to SOCKS4a "
                                         "server: %s", err)
                raise

        # direct connection
        else:
            try:
                # open socket and connect
                self._socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_STREAM)
                logger.debug("new created socket:%s", self._socket)
                self._socket.connect(raddr)
            except Exception as e:
                logger.error("Error while connecting to %s: '%s'",
                              raddr, e)
                raise e

    def __socksResolveHost(self,host):
        PORT = 80
        logger.debug("Resolving %s:%d using SOCKS..", host, PORT)

        raddr = (host, PORT)

        try:
            logger.debug("Sending resolve request..")
            host = csockslib.socks4a_resolveHost(
                                        WhoisWorker.socksServer,
                                        raddr)
            logger.debug("host=%s" % repr(host))
        except Exception as err:
            logger.error(err)
            raise err

        return host

    def __selectWhoisServer(self):
        count = len(self._usedServers)
        logger.debug("count of used servers:%d", count)

        # select a whois server from list
        # and return the server
        # if server already used, try another one
        while True:
            if len(self._usedServers) >= len(WhoisWorker.servers):
                # if thread tried all servers
                raise Exception("Tried too many servers. "
                                "Now, I am exhausted :(")

            r = WhoisWorker.servers[count]
            if r not in self._usedServers:
                logger.debug("adding to _usedServers list")
                self._usedServers.append(r)
                break

            # if thread tried all servers
            raise Exception("Querying server %s twice is not allowed!" % r)

        return r

    def __binarysearchNetname(self, liste, start, end, keyword):
        return self.__binarysearchNIC(liste, start, end, keyword)

    def __binarysearchNIC(self, liste, start, end, keyword):
        if end < start:
            return None

        middle = (start + end)/2
        nic = liste[middle]


        if keyword < nic:
            return self.__binarysearchNIC(liste, start, middle-1, keyword)
        elif keyword > nic:
            return self.__binarysearchNIC(liste, middle+1, end, keyword)
        else:
            return nic


    def __binarysearchIP(self, liste, start, end, keyword):
        if end < start:
            return None

        middle = (start + end)/2
        request = liste[middle]
        logging.debug("checking %s, rangestart=%s, rangeend=%s",
                      keyword,
                      request.rangestart,
                      request.rangeend)
        if socket.inet_aton(keyword) < socket.inet_aton(request.rangestart):
            return self.__binarysearchIP(liste, start, middle-1,keyword)
        elif socket.inet_aton(keyword) > socket.inet_aton(request.rangeend):
            return self.__binarysearchIP(liste, middle+1, end,keyword)
        else:
            return request.name

    def __validNIC(self, string):
        nic = re.compile("(.+)-RIPE")
        return nic.match(string) != None

    def __validNetname(self, string):
        nic = re.compile("(.+)-RIPE")
        return nic.match(string)== None


