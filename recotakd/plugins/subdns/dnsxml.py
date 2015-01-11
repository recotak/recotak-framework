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

loggerxml = logging.getLogger(__name__)

class Xml:
	SCANINFO = "scaninfo"
	QUERYRESULT = "ip"
	QUERY = "host"
	RESPONSE = "hosts"
	
	def __init__(self):
		self._doc = Document()
		self._rootNode = self._doc.createElement("dnsscanrun")
		self._doc.appendChild(self._rootNode)

	def save(self,name):
		with open(name, "w") as file:
			loggerxml.debug("saving file %s" % name)
			file.write(self._doc.toxml())

	# Adds a scaninfo tag that contains information
	# like scan type, used protocols and scanned
	# services
	def addScaninfo(self, information):
		scaninfo = self._doc.createElement(Xml.SCANINFO)

		for i in information:
			scaninfo.setAttribute(i, information.get(i))
			
		self._rootNode.appendChild(scaninfo)

	# Adds a QueryResult node of a 
	# specific name to root node.
	# A QueryResult node consists of
	# a Query Node and a Result Node.
	def addIpNode(self, (ip4, ip6)):
		loggerxml.debug("addIpNode: %s" % str(ip4))

		# look for node with a specific name
		old = self.__lookForQueryResult((ip4,ip6))
		if (old != None):
			loggerxml.debug("found query result node")
			return old

		ip_node = self._doc.createElement(Xml.QUERYRESULT)
		ip_node = self.__addDictAsAttributes(ip_node, {"ip4":ip4, "ip6":ip6})			

		self._rootNode.appendChild(ip_node)
	
		return ip_node

	# Searches a queryResult node due
	# to a given name.	
	def __lookForQueryResult(self,name):
		old = self._doc.getElementsByTagName(Xml.QUERYRESULT)
		for node in old:
			try:
				if name[0] == node.getAttribute("ip4") and\
					name[1] == node.getAttribute("ip6"):
					return node	
			except:
				pass

		return None

	def __lookForNodeByContent(self, parentNode, tag, content):
		nodes = parentNode.getElementsByTagName(tag)	
		for node in nodes:
			if node.childNodes[0].nodeValue == content:
				return node
		
		return None
	
	def __lookForAttributeByContent(self, parentNode, attribute, content):
		value = parentNode.getAttribute(attribute)	
		if value == content:
			return parentNode
		
		return None
	

	# adds a QueryNode to root
	# it consists of major Query
	# properties and options
	def addQuery(self, parentNode, query=dict()):
		loggerxml.debug("addQuery %s" % str(query))

		# check whether node only needs to
		# be extended
		try:
			queryNode = parentNode.getElementsByTagName(Xml.QUERY)[0]
		except IndexError:
			queryNode = self._doc.createElement(Xml.QUERY)
			parentNode.appendChild(queryNode)

		# add child nodes
		if query != {}:
			queryNode = self.__addDictAsAttributes(queryNode, query)		

		return queryNode

	# Adds an ResultNode to the document.
	# The function gets a node to
	# add the host and a dictionary.
	def addHostNode(self, parentNode, hosts=[]):
		loggerxml.debug("addResponse")

		# look for existing 'response' nodes
		hostNode = self._doc.createElement(Xml.RESPONSE)
		parentNode.appendChild(hostNode)

		# add child nodes 
		hostNode = self.__addDictAsNodes(hostNode, {"host":hosts})		

		return parentNode

	# Adds a given dictionary as node properties.
	# Returns the modified node.
	def __addDictAsAttributes(self, parentNode, dictionary=dict()):
		loggerxml.debug("addDictAsAttributes: %s" % str(dictionary))		

		for key in dictionary:
			value = dictionary.get(key)

			# dictionary		
			if type(value) == types.DictType:
				node = self.__lookForAttributeByContent(parentNode, key, value)
				# if node already exists skip 
				if (node != None):
					continue

				node = self._doc.createElement(key)
				parentNode.appendChild(node)
				self.__addDictAsAttributes(node, value)

			# list
			if type(value) == types.ListType:
				for element in value:	
					node = self.__lookForAttributeByContent(parentNode, key, element)
					# if node already exists skip 
					if (node != None):
						continue

					parentNode.setAttribute(key, value)
			
			# string
			elif type(value) == types.StringType:
				node = self.__lookForAttributeByContent(parentNode, key, value)
				# if node already exists skip 
				if (node != None):
						continue

				parentNode.setAttribute(key, value)

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

