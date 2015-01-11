#!/usr/bin/env python
"""this module implements the imap4 protocol rfc3501"""
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

import socket
import ssl
import logging

__author__ = "curesec"
__version__ = "0.0.2"
__credits__ = "curesec"

SOCKET_RECV_BUFSIZE = 32768
CRLF = "\r\n"

logging.basicConfig(filename="imap.log", level=logging.DEBUG)


class CCDIMAP4(object):
    """this class implements the imap4 command and initialises a socket
    connection"""

    def __init__(self, host, port, connection_type=None, callback=None):
        self.__sequence_number = 0
        self.__socket = None
        self.connection_type = connection_type
        self.host = host
        self.port = port
        self.capabilities = []
        self.mailboxes = []

        callback = None
        if (callback):
            self.__socket = callback(tuple(self.host, self.port))

            if (self.connection_type.upper() == "SSL"):
                self.__socket = ssl.wrap_socket(self.__socket)
        else:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__socket.connect((self.host, self.port))

            if (self.connection_type.upper() == "SSL"):
                self.__socket = ssl.wrap_socket(self.__socket)


    def set_sequence_number(self, number):
        """set the imap sequence number"""
        self.__sequence_number = number

    def get_sequence_number(self):
        """get the imap sequence number"""
        return self.__sequence_number

    def increment_sequence_number(self):
        """increment the imap sequence number"""
        self.__sequence_number += 1

    def validate_response(self, response):
        """this method validates the response"""

        needle_ok = "%d OK" % (self.__sequence_number)
        needle_no = "%d NO" % (self.__sequence_number)
        needle_bad = "%d BAD" % (self.__sequence_number)

        if (needle_ok in response[0]):
            return True
        elif ((needle_no in response[0]) or (needle_bad in response[0])):
            logging.debug("request %s failed", self.__sequence_number)
            return False
        else:
            logging.debug("request %s failed", self.__sequence_number)
            return False

    def banner(self):
        """receive the inital banner from server"""
        try:
            response = self.__socket.recv(SOCKET_RECV_BUFSIZE)
        except (socket.error) as err:
            logging.error("banner, recv(SOCKET_RECV_BUFSIZE), exiting: %s", err)

        logging.info("banner, response: %s", response)

    def capability(self):
        """CAPABILITY Command rfc3501 6.1.1."""

        command = "CAPABILITY"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)

        if (self.validate_response(response)):
            self.capabilities = response[0].split()[3:]


    def examine(self, mailbox):
        """SELECT Command rfc3501 6.3.1"""

        command = "EXAMINE"
        data = "%s %s%s" % (command, mailbox, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def fetch(self, sequence_set, mdin_or_macro):
        """FETCH Command rfc3501 6.4.5"""

        command = "FETCH"
        data = "%s %s %s%s" % (command, sequence_set, mdin_or_macro, CRLF)
        response = self._command(data, loop=True)

        return self.validate_response(response)

    def list(self, reference, mailbox):
        """LIST Command rfc3501 6.3.8."""

        command = "LIST"
        data = "%s %s %s%s" % (command, reference, mailbox, CRLF)
        response = self._command(data)

        if (self.validate_response(response)):
            for mailbox in response[:len(response)-1]:
                self.mailboxes.append(mailbox.split()[-1])

    def login(self, user, password):
        """LOGIN Command rfc3501 6.2.3"""

        command = "LOGIN"
        data = "%s %s %s%s" % (command, user, password, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def logout(self):
        """LOGOUT Command rfc3501 6.1.3"""

        command = "LOGOUT"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def search(self, search_key):
        """SEARCH Command rfc3501 6.4.4."""

        command = "SEARCH"
        data = "%s %s%s" % (command, search_key, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def select(self, mailbox):
        """SELECT Command rfc3501 6.3.1."""

        command = "SELECT"
        data = "%s %s%s" % (command, mailbox, CRLF)
        response = self._command(data)

        return self.validate_response(response)

    def starttls(self):
        """STARTTLS Command rfc3501 6.2.1"""

        command = "STARTTLS"
        data = "%s%s" % (command, CRLF)
        response = self._command(data)

        if (self.validate_response(response)):
            self.__socket = ssl.wrap_socket(self.__socket)

    def _command(self, data, loop=False):
        """sends the request over the socket"""

        self.increment_sequence_number()
        request = "%d %s" % (self.__sequence_number, data)

        print(request)

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

                needle = "%d OK" % (self.__sequence_number)

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

        response_lines = response.splitlines()
        print(response)

        if ("OK" not in (response_lines[len(response_lines)-1])):
            logging.error("_command, no OK received")

        logging.debug("_command, response: %s", response)

        return response_lines
