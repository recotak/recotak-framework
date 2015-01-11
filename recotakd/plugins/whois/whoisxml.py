# -*- coding: utf8 -*-

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
from xml.dom.minidom import Document
import types
import cgi
import logging

loggerxml = logging.getLogger("whois.xml")

class Xml:
    QUERYRESULT = "QueryResult"
    QUERY = "Query"
    RESPONSE = "Response"

    def __init__(self):
        self._doc = Document()
        self._rootNode = self._doc.createElement("Whois")
        self._doc.appendChild(self._rootNode)

    def save(self,name):
        with __builtin__.openany(name, "w") as file:
            loggerxml.debug("saving file %s" % name)
            file.write(self._doc.toxml())

    # Adds a QueryResult node of a
    # specific name to root node.
    # A QueryResult node consists of
    # a Query Node and a Result Node.
    def addQueryResult(self, name, typeOf):
        loggerxml.debug("addQueryResult of name=%s" % (name))

        # look for node with a specific name
        old = self.__lookForQueryResult(name)
        if (old == None):
            request = self._doc.createElement(Xml.QUERYRESULT)
            request.setAttribute("name", name)
            request.setAttribute("type",typeOf)
            self._rootNode.appendChild(request)
        else:
            return old

        return request

    # Searches a queryResult node due
    # to a given name.
    def __lookForQueryResult(self,name):
        old = self._doc.getElementsByTagName(Xml.QUERYRESULT)
        for node in old:
            if name == node.getAttribute("name"):
                return node

        return None

    def __lookForNodeByContent(self, parentNode, tag, content):
        nodes = parentNode.getElementsByTagName(tag)
        for node in nodes:
            if node.childNodes[0].nodeValue == content:
                return node

        return None


    # adds a QueryNode to root
    # it consists of major Query
    # properties and options
    def addQuery(self, parentNode, query=dict()):
        loggerxml.debug("addQuery %s" % str(query))

        # check whether node only needs to
        # be extended
        if parentNode.hasChildNodes():
            queryNode = parentNode.getElementsByTagName(Xml.QUERY)[0]
        else:
            queryNode = self._doc.createElement(Xml.QUERY)
            parentNode.appendChild(queryNode)

        # add child nodes
        queryNode = self.__addDictAsNodes(queryNode, query)

        return parentNode

    # Adds an ResultNode to the document.
    # The function gets a node to
    # add the host and a dictionary.
    def addResponse(self, parentNode, result=dict()):
        loggerxml.debug("addResponse %s" % str(result))

        # look for existing 'response' nodes
        rnodes = parentNode.getElementsByTagName(Xml.RESPONSE)
        if len(rnodes) == 0:
            resultNode = self._doc.createElement(Xml.RESPONSE)
            parentNode.appendChild(resultNode)
        else:
            resultNode = rnodes[0]

        # add child nodes
        resultNode = self.__addDictAsNodes(resultNode, result)

        return parentNode

    # Adds a given dictionary to a node
    # given as parameter. This is relevant
    # for instance for Results and Host nodes.
    # It returns the modified node.
    def __addDictAsNodes(self, parentNode, dictionary=dict()):
        for key in dictionary:
            value = dictionary[key]

            # dictionary
            if type(value) == types.DictType:
                node = self.__lookForNodeByContent(parentNode, key, value)
                # if node already exists skip
                if (node != None):
                    continue

                node = self._doc.createElement(key)
                parentNode.appendChild(node)
                self.__addDictAsNodes(node, value)

            # list
            if type(value) == types.ListType:
                for element in value:
                    node = self.__lookForNodeByContent(parentNode, key, element)
                    # if node already exists skip
                    if (node != None):
                        continue

                    node = self.__createNode(key, element)
                    parentNode.appendChild(node)


            # string
            elif type(value) == types.StringType:
                node = self.__lookForNodeByContent(parentNode, key, value)
                # if node already exists skip
                if (node != None):
                        continue
                node = self.__createNode(key, value)
                parentNode.appendChild(node)

        return parentNode

    def __createNode(self, name, value):
        tmp = value
        try:
            value = value.decode("latin-1").encode("utf-8")
        except Exception as err:
            raise err
            loggerxml.warning("crashing error=%s" % value)
            value = tmp

        node = self._doc.createElement(cgi.escape(name))
        text = self._doc.createTextNode(cgi.escape(value))
        node.appendChild(text)
        return node

