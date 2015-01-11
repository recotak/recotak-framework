import sys
import re
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
import ConfigParser
import types
import logging

FILE = "parser.regex"
loggerparser = logging.getLogger(__name__)


class Parser():
    IPTYPE = "ip"
    NICTYPE = "admin-nic"
    NETNAMETYPE = "netname-nic"

    def __init__(self, fn):
        # this is used for nested
        # object creation while
        # parsing regex results
        self.__objectStack = []

        self.__count = 0

        # load regex
        self.regex = self.__loadRegex(fn)


    def parseWhoisResponse(self, server, response, responseType):
        loggerparser.debug("parsing response=%s" % response)
        serverCommentChar = "%"
        result = dict()

        regex = self.regex

        if responseType == Parser.NICTYPE:
            server = "ADMINNIC:%s" % (server)
        elif responseType == Parser.NETNAMETYPE:
            server = "NETNAMENIC:%s" % (server)
        server = server.upper()

        # check whether regex for this
        # server are defined in config
        if regex.has_section(server):
            result = self.__applyReg(regex, server, response)
        else:
            loggerparser.warning("[Parser] Server has no defined regex. "+\
                            "Using regex of ripe.net.")
            result = self.__applyReg(regex, "WHOIS.RIPE.NET", response)

        return result

    def __applyReg(self, regex, server, response):
        result = dict()

        # we need to remember objects
        # already created - this is
        # due to nested objects
        objectstack = []

        # load all key-value pairs
        # for the matching section
        items = regex.items(server)

        # apply every regex
        for name, reg in items:
            findings = re.findall(reg,response)

            # strip spaces etc
            findings = self.__stripFindings(findings)

            # build nested objects
            objects = name.split("-")
            result = self.__addToObject(\
                        parentObject=result,\
                        subObjects=objects,\
                        values=findings\
                        )

        return result

    def __addToObject(self, parentObject, subObjects=[], values=[]):

        length = len(subObjects)

        # create subobjects - add last entry n
        # to predecessor n-1
        if length>1:
            n = {subObjects[0]:{}}
            nPlusOne = subObjects[1:]

            # n to n+1
            n[subObjects[0]] = self.__addToObject(n[subObjects[0]], nPlusOne, values)

            # sub to parent
            parentObject = self.__addToObject(parentObject,[n],values)

            return parentObject

        # check whether parent already has
        # an object with that name -
        # if so extend, otherwise create one
        elif length ==1:
            new = subObjects[0]
            if type(new) == types.DictType:
                name = new.keys()[0]
                new = new[name]
            elif type(new) == types.StringType:
                name = new
                new = values

            new = self.__extendNode(name, parentObject,new)

            return parentObject

    def __extendNode(self, name, parentObject, new):

        if (type(new) != types.DictType):
            parentObject[name] = new
            return new

        if name in parentObject.keys():
            tmp = name
            name = new.keys()[0]
            return self.__extendNode(name, parentObject[tmp], new[name])
        else:
            parentObject[name] = new
            return new

    def __stripFindings(self, findings=[]):
        strippedFindings = []
        for f in findings:
            s = f.strip(' \t\n\r')
#           s = s.encode("utf-8")
            strippedFindings.append(s)

        return strippedFindings

    def __loadRegex(self, fn):
        regex = ConfigParser.RawConfigParser()
        with openany(fn, 'r') as fp:
            regex.readfp(fp)
        return regex
