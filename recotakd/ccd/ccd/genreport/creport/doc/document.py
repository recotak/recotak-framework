# coding: utf8

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
from odf.opendocument import OpenDocumentText
from datetime import date as pyDate

# local modules
from styles import DocumentStyle

TODAY = pyDate.today().strftime("%d.%m.%y")

class Doc:

    def __init__(self, filename, language="de", curesec_brand=True):

        # create document tree
        self.document = OpenDocumentText()

        # set members
        self.filename = filename
        self.language = language

        # some basic report details
        self.project = "XY-932521-OMEGA"
        self.date = TODAY
        self.dateStart = TODAY
        self.dateEnd = TODAY
        self.author = "Curesec GmbH"
        self.authorAddress = "Berliner Allee 170"
        self.clientName = "Name des Kunden"
        self.clientAddress = "Adresse des Kunden"
        self.version = "0.1"

        # define style and add user information
        self.__style = DocumentStyle()
        self.__style.defineCuresecStyles(self.document, self.language)

        if curesec_brand:
            self.__style.addUserfieldsToBody(self.document,
                                             projekt=self.project,
                                             date=self.date,
                                             dateStart=self.dateStart,
                                             dateEnd=self.dateEnd,
                                             author=self.author,
                                             authorAddress=self.authorAddress,
                                             clientName=self.clientName,
                                             clientAddress=self.clientAddress,
                                             version=self.version
                                             )
            self.setHeader()
            self.setFooter()
            self.setDeckblatt()
            self.setVertragspartner()
            self.setTableOfContent()

    def setTableOfContent(self):
        self.__style.addTableOfContent(self.document)

    def setDeckblatt(self):
        self.__style.addDeckblatt(self.document)

    def setVertragspartner(self):
        self.__style.addVertragspartner(self.document)

    def setFooter(self):
        self.__style.setFooterData(self.document)

    def setHeader(self):
        self.__style.setHeaderData(self.document,
                                   self.project,
                                   self.date,
                                   self.version)

    def save(self):
        # save document
        self.document.save(self.filename)

    def add(self, element):
        if element is not None:
            self.document.text.addElement(element)

    def addAsObject(self, element):
        if element is not None:
            return self.document.addObject(element)

#   def applyProperty(self, _property):
#       self._document.automaticself.__style.addElement(_property)



