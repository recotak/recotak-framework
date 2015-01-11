#!/usr/bin/env python
"""this module implements the pop3 protocol rfc1939 + starttls
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
extension from rfc 2595"""

import socket
import ssl
import logging

__author__ = "curesec"
__version__ = "0.0.2"
__credits__ = "curesec"

SOCKET_RECV_BUFSIZE = 32768
CRLF = "\r\n"

logging.basicConfig(filename=" pop3.log", level=logging.DEBUG)


class CCDPOP3(object):
    """this class implements the pop3 commands and initialises a socket
    connection"""

    def __init__(self, host, port, connection_type=None):
        self.__sequence_number = 0
        self.__socket = None
        self.connection_type = connection_type
        self.host = host
        self.port = port
        self.capabilities = []
        self.mailboxes = []

        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.host, int(self.port)))

        if (self.connection_type.upper() == "SSL"):
            self.__socket = ssl.wrap_socket(self.__socket)

    def banner(self):
        """receive the inital banner from server"""
        try:
            response = self.__socket.recv(SOCKET_RECV_BUFSIZE)
        except (socket.error) as err:
            logging.error("banner, recv(SOCKET_RECV_BUFSIZE), exiting: %s", err)

        logging.info("banner, response: %s", response)

    def user(self, user):
        """ USER Command rfc 1939 section 7."""

        command = "USER"
        data = "%s %s%s" % (command, user, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    @staticmethod
    def validate_response(response):
        """this method validates the response"""

        needle_ok = "+OK"
        needle_err = "-ERR"

        if (needle_ok in response[0]):
            return True
        elif (needle_err in response[0]):
            logging.debug("request failed")
            return False
        else:
            logging.debug("request failed")
            return False


    def pass_(self, password):
        """ PASS Command rfc 1939 section 7."""

        command = "PASS"
        data = "%s %s%s" % (command, password, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def stat(self):
        """ STAT Command rfc 1939 section 5."""

        command = "STAT"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def list(self):
        """ LIST Command rfc 1939 section 5."""

        command = "LIST"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def quit(self):
        """ QUIT Command rfc 1939 section 6."""

        command = "QUIT"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def stls(self):
        """ STLS Command rfc 2595 section 4."""

        command = "STLS"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)


        if (self.validate_response(response)):
            self.__socket = ssl.wrap_socket(self.__socket)


    def retr(self, number):
        """ RETR Command rfc 1939 section 5."""

        command = "RETR"
        data = "%s %s%s" % (command, number, CRLF)
        response = self._command(data, loop=True)

        return self.validate_response(response)

    def _command(self, data, loop=False):
        """sends the request over the socket"""

        request = "%s" % (data)

        logging.info("_command, request: %s", request)

        try:
            self.__socket.sendall(request.encode("utf-8"))
        except (socket.error) as err:
            logging.error("_command, sendall(request), exiting: %s", err)
            exit(1)

        if (loop):
            response = ""

            while(1):
                data = self.__socket.recv(SOCKET_RECV_BUFSIZE)
                response = response + data.decode("utf-8")
                needle = "%s.%s" % (CRLF, CRLF)

                if (needle in data.decode("utf-8")):
                    break

        else:
            try:
                response = self.__socket.recv(SOCKET_RECV_BUFSIZE)
                response = response.decode("utf-8")
            except (socket.error) as err:
                logging.error("_command, recv(SOCKET_RECV_BUFSIZE), exiting: %s",
                              err)
                exit(1)

        logging.info("response: %s", response)
        response_lines = response.splitlines()

        if ("OK" not in (response_lines[len(response_lines)-1])):
            logging.error("_command, no OK received")

        logging.debug("_command, response: %s", response)

        return response_lines
