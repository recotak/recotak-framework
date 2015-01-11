#!/usr/bin/python

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
# TODO: auslagern
from cBing.bing import BingQuery
# TODO: ersetzen durch eingenes modul
import httplib
import gzip
import StringIO
import threading
import socket
import logging
import urlparse

# logging
#LOG = "/tmp/comm.log"
#FORMAT = '%(asctime)s - %(name)s - %(levelname)s' + \
#    '- %(threadName)s - %(message)s'
#logging.basicConfig(filename=LOG,
#                    filemode="w",
#                    format=FORMAT,
#                    level=logging.DEBUG)
#
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.NullHandler())

output_lock = threading.Lock()


class Comm(object):
    SSL = False
    NOSSL = False
    HTTP_TYPES = ['HTTP', 'HTTPS']
    HTTP_METHODS = ['GET', 'POST', 'HEAD']
    MAX_RETRIES = 3

    @staticmethod
    def resolve(ident):
        hostname = ident
        ip = ident
        try:
            ip = socket.gethostbyname(ident)
        except Exception:
            ip = ident
            pass
        try:
            if ident != ip:
                hostname = ident
            else:
                hostname = socket.gethostbyaddr(ident)[0]
        except Exception:
            hostname = ident
            pass
        return ip, hostname

    @staticmethod
    def isEncoded(header):
        try:
            enc = header['Content-Encoding']
            return enc
        except KeyError:
            try:
                enc = header['content-encoding']
                return enc
            except KeyError:
                return None

    @staticmethod
    def getLocation(header):
        try:
            loc = header['Location']
            return loc
        except KeyError:
            try:
                loc = header['location']
                return loc
            except KeyError:
                return None

    @staticmethod
    def fetch(mark,
              uri,
              method='GET',
              data='',
              req_headers={},
              httpver='HTTP/1.1',
              retry=0,
              follow=False
              ):

        if not mark.test:
            return 0, '', 'target excluded', '', []

        # if we reached the maximum number of retries, indicate an error
        if retry > Comm.MAX_RETRIES:
            return 0, '', 'max retries reached', '', []

        # check if mark supports the request method
        if method not in mark.http_methods:
            return 0, '', 'mehtod %s not supported for %s' % (method, mark.ident), '', []

        # get random headers
        headers = BingQuery.get_http_header()
        # overwrite specified fields
        for k, v in req_headers.items():
            headers[k] = v
        # add correct encoding: TODO ... think about this
        headers['encoding'] = 'text/html; charset=utf-8'
        headers['Host'] = mark.hostname

        con = None

        status = 0
        content = ''
        error = 'unknown error'
        res_headers = []
        try:
            # wait if the maximum number of parrallel connections is reached
            if mark.connections:
                mark.connections.acquire()

            #print 'Comm.SSL ' + repr(Comm.SSL)
            #print 'Comm.NOSSL ' + repr(Comm.NOSSL)
            #print 'mark.ssl ' + repr(mark.ssl)
            #print 'mark.port ' + repr(mark.port)
            #print 'uri ' + repr(uri)
            if Comm.SSL or mark.ssl and not Comm.NOSSL:
                try:
                    con = httplib.HTTPSConnection(mark.hostname, port=mark.port, timeout=mark.timeout)
                    #con = httplib.HTTPSConnection('https://' + mark.ip, port=mark.port, timeout=mark.timeout)
                except:
                    con = httplib.HTTPConnection(mark.hostname, port=mark.port, timeout=mark.timeout)
                    #con = httplib.HTTPConnection('http://' + mark.ip, port=mark.port, timeout=mark.timeout)
            else:
                con = httplib.HTTPConnection(mark.hostname, port=mark.port, timeout=mark.timeout)
                #con = httplib.HTTPConnection('http://' + mark.ip, port=mark.port, timeout=mark.timeout)
            # send request to mark

            if not uri:
                uri = '/'

            con.request(method, uri, body=data or None, headers=headers)

            res = con.getresponse()
            status = res.status
            content = res.read()
            res_headers = dict(res.getheaders())

            if status == 301 and follow:
                con.close()
                newloc = Comm.getLocation(res_headers)

                with output_lock:
                    print 'following reloc to %s' % newloc

                status, content, error, uri, res_headers = \
                    Comm.fetch(mark,
                               newloc,
                               method,
                               data,
                               req_headers,
                               httpver,
                               retry + 1,
                               False)

            enc = Comm.isEncoded(res_headers)
            if enc == 'gzip':
                gz = gzip.GzipFile(
                    fileobj=StringIO.StringIO(content),
                    mode="rb"
                )
                content = gz.read()
                gz.close()

            # snarf what we can find from the response
            try:
                if not mark.banner:
                    mark.banner = res_headers['server']
                else:
                    if mark.banner != res_headers['server']:
                        with output_lock:
                            print 'Warning: Server banner changed'
                            print 'old: ' + mark.banner
                            print 'new: ' + res_headers['server']
            except KeyError:
                pass

            error = ''
        except socket.error, e:
            error = e
            logger.error('Socket error in fetch for mark %s: %s  %s:%d%s (%s) -> %s',
                         mark.ident,
                         con,
                         mark.ip,
                         mark.port,
                         uri,
                         mark.hostname,
                         e
                         )
            try:
                if e.errno == 99:
                    # retry
                    con.close()
                    status, content, error, uri, res_headers = \
                        Comm.fetch(mark, uri, method, data, req_headers, httpver, retry + 1)

            except:
                pass
        except Exception, e:
            error = e
            logger.error('Error on %s/%s -> ' % (mark.ident, uri) + repr(e))
        finally:
            if mark.connections:
                mark.connections.release()
            if con:
                con.close()

        r = (status, content, error, uri, res_headers)
        return r

    @staticmethod
    def port_check(mark):
        if Comm.SSL:
            logger.info('Allowing https connections only')
            checktypes = ['HTTPS']
        elif Comm.NOSSL:
            logger.info('Allowing http connections only')
            checktypes = ['HTTP']
        else:
            checktypes = ['HTTP', 'HTTPS']

        ssl = -1
        for method in Comm.HTTP_METHODS:
            for ctype in checktypes:
                mark.test = 1
                #print 'CTYPE: %s' % ctype
                # if the connection type is HTTP (no ssl), set the
                # ssl flag of the mark to 0 for the check.
                # otherwise set it to 1
                mark.ssl = (ctype == 'HTTP' and [0] or [1])[0]

                #print 'mark.ssl: %s' % repr(mark.ssl)
                # save the original port
                status, body, error, request, resp_headers = \
                    Comm.fetch(mark, mark.path, method, follow=True)
                if error:
                    #print 'FAILED: ' + repr(error)
                    logger.warning(error)
                else:
                    # TODO
                    #if status < 200 or status >= 402:
                    # NO RELOCS
                    # srsly some sites (like spiegel) redirect to the non https
                    # site, how am i supposed to know if https is supported
                    # if I only get relocs
                    #if status != 200:
                    #    mark.http_methods.remove(method)
                    #else:
                    #    ssl = mark.ssl
                    #print 'status %d' % status
                    if status in mark.ok_codes:
                        ssl = mark.ssl
                    else:
                        logger.warning('Got response %d from %s:%d (ssl %s), but removing because not in acceptable codes (%s)',
                                       status, mark.ident, mark.port, mark.ssl, mark.ok_codes)
                        mark.http_methods.remove(method)
                #print ''
        return ssl


SCHEME, NETLOC, PATH, QUERY, FRAGMENT = range(5)


def fix_url(base_url):
    url = urlparse.urlparse(base_url)
    surl = list(url)
    if not surl[SCHEME]:
        surl[SCHEME] = 'http'
    # if 'www' is omitted, the netloc gets mixed up with the path
    if not surl[NETLOC] and surl[PATH]:
        surl[NETLOC] = surl[PATH]
        surl[PATH] = ''
    url = urlparse.urlunparse(surl)
    url = urlparse.urlparse(url)
    return url


class Mark(object):

    MAX_CON = 0
    FIX_PORT = 0
    TIMEOUT = 30

    def __init__(self,
                 ident,
                 hostname='',
                 ip='',
                 path='/',
                 timeout=TIMEOUT,
                 fix_port=FIX_PORT,
                 max_connections=MAX_CON,
                 ok_codes=[200, ]
                 ):

        """
        Create a mark object instance

        Input:
            ident            Mark identifier, either hostname or ip
            hostname         hostname (defaul: '' -> resolved or copied from identifier)
            ip               ip (defaul: '' -> resolved or copied from identifier)
            path             url path (default: '/')
            timeout          socket timeout (default: 30 seconds)
            fix_port         fixed target port (default disables)
            mac_connections  maximum amount of parallel connections for this target (default: disabled)
        """

        logger.info('Initializing %s' % ident)
        self.path = path
        self.ident = ident
        self.timeout = timeout
        self.ok_codes = ok_codes
        self.test = 1

        self.hostname = None
        self.ip = None
        if hostname:
            self.hostname = hostname
        if ip:
            self.ip = ip

        #print 'IDENT: %s' % self.ident
        #print 'IP: %s' % self.ip
        #print 'HOSTNAME: %s' % self.hostname
        #print 'PATH: %s' % self.path

        # if no hostname or no ip are given, try to determine them by resolving
        # the mark identifier
        if not self.hostname or not self.ip:
            try:
                ip, hostname = Comm.resolve(ident)
                logger.info('resolved: %s %s', ip, hostname)
                # this should match
                if self.ip and ip != self.ip:
                    logger.error('Given ip %s does not match resolved ip %s, excluding %s from scan',
                                 self.ip, ip, ident)
                    self.test = 0
                # this should match too
                elif self.hostname and hostname != self.hostname:
                    logger.error('Given hostname does not match resolved hostname, excluding %s from scan', ident)
                    self.test = 0
                else:
                    self.ip = ip
                    self.hostname = hostname
                    self.test = 1
            except:
                logger.error('Host %s appers to be unreachable, excluding from scan', ident)
                self.test = 0

        # the banner is later set on the first fetch from the target server
        # on subsequent fetches it is monitored for chages
        self.banner = ''

        # supported http methods (one set for ssl and one for plain http)
        self._http_methods = [['GET', 'POST', 'HEAD'], ['GET', 'POST', 'HEAD']]

        # [http, https] ports
        # if we have a fixed port, we use it for both encrypted and non
        # encrypted connections
        if fix_port:
            self._port = [fix_port, fix_port]
        else:
            # otherwise we use the default http/https ports
            self._port = [80, 443]

        # if a limit for parallel connections is set, we instatiate a semaphore
        # to account for opened connections
        if max_connections:
            self.connections = threading.Semaphore(value=max_connections)
        else:
            self.connections = None

        # check if this target supports ssl? 0: no, 1: yes
        ssl = Comm.port_check(self)
        # error
        if ssl < 0:
            self.test = 0
        else:
            self.ssl = ssl

        if self.test == 0:
            with output_lock:
                print '-' * 80
                print '[!] Unable to reach %s, removing target' % self.ident
                print '-' * 80

    @property
    def port(self):
        return self._port[self.ssl]

    @port.setter
    def port(self, value):
        self._port[self.ssl] = value

    @property
    def http_methods(self):
        return self._http_methods[self.ssl]

    def __repr__(self):
        r = self.ident
        r += '\n'
        r += '=' * len(self.ident)
        r += '\n'
        r += 'ip: %s' % self.ip
        r += '\n'
        r += 'hostname: %s' % self.hostname
        r += '\n'
        r += 'port: %d' % self.port
        r += '\n'
        r += 'banner: %s' % self.banner
        r += '\n'
        r += 'ssl: %d' % self.ssl
        r += '\n'
        r += 'methods: %s' % repr(self.http_methods)
        r += '\n'
        return r


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', help='target ip or hostname', required=True)
    parser.add_argument('-p', help='fixed port', type=int, default=0)
    parser.add_argument('-to', help='connection timeout', type=int, default=3)
    parser.add_argument('-ssl', help='ssl only', action='store_true')
    parser.add_argument('-nossl', help='plain only', action='store_true')
    parser.add_argument('-mc', help='max parallel connections', default=0, type=int)
    opt = parser.parse_args()

    Comm.SSL = opt.ssl
    Comm.NOSSL = opt.nossl

    m = Mark(opt.t,
             timeout=opt.to,
             fix_port=opt.p,
             max_connections=opt.mc)
    print m
