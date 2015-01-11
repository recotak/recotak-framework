#!/bin/env python2
import unittest
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
from ctools.dns.domain import get_domain
from ctools.dns.exceptions import BadUrl, DomainNotFound

__author__ = "curesec"

FILE = "urls.txt"

class DnsDomain(unittest.TestCase):

    def setUp(self):
        self.urls_fd = open(FILE, "r")

    def tearDown(self):
        self.urls_fd.close()

    def test_domains(self):
        """ iterating over urls to test ctools.dns.get_domain() """
        for line in self.urls_fd:
            url, domain = line.rstrip().split(",")
            print("url=%s" % url)

            if domain == "BadUrl":
                self.assertRaises(BadUrl, get_domain, url)
            elif domain == "DomainNotFound":
                self.assertRaises(DomainNotFound, get_domain, url)
            else:
                self.assertEqual(get_domain(url), domain)

if __name__ == "__main__":
    import os
    unittest.main()

