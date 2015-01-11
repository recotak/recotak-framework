#!/usr/bin/env python3

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
__author__ = "curesec"
__credits__ = ["curesec"]
__version__ = "0.0.1"

import collections

request_user_agents = [
    "Lynx/2.8.7rel.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.0.1e",            
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9) Gecko/2008052906 Firefox/3.0", 
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1) Gecko/20090624 Firefox/3.5",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.28) Gecko/20120306 Firefox/3.6.28",
    "Mozilla/5.0 (Windows NT 5.1; rv:2.0) Gecko/20100101 Firefox/4.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:16.0) Gecko/20100101 Firefox/16.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:16.0) Gecko/20100101 Firefox/16.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:17.0) Gecko/17.0 Firefox/17.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:17.0) Gecko/20100101 Firefox/17.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:20.0) Gecko/20100101 Firefox/20.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:20.0) Gecko/20100101 Firefox/20.0",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/531.0 (KHTML, like Gecko) Chrome/3.0.182.2 Safari/531.0",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.3 (KHTML, like Gecko) Chrome/4.0.223.11 Safari/532.3",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.9 (KHTML, like Gecko) Chrome/5.0.307.1 Safari/532.9",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.2 (KHTML, like Gecko) Chrome/6.0.453.1 Safari/534.2",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.517.44 Safari/534.7",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Chrome/9.0.597.84 Safari/534.13",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.133 Safari/534.16",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/11.0.696.77 Safari/534.24",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/15.0.849.0 Safari/535.1",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.8 (KHTML, like Gecko) Chrome/17.0.938.0 Safari/535.8",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.3 Safari/535.19",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.22 (KHTML, like Gecko) Chrome/19.0.1049.3 Safari/535.22",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1096.1 Safari/536.6",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1163.0 Safari/537.1",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.64 Safari/537.31",
    "Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8d",
    "Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.6.3",
    "Lynx/2.8.7rel.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.0.0a",
    "Lynx/2.8.8dev.3 libwww-FM/2.14 SSL-MM/1.4.1",
    "Lynx/2.8.7pre.5 libwww-FM/2.14 SSL-MM/1.4.1",
    "Lynx/2.8.7dev.9 libwww-FM/2.14",
    "Lynx/2.8.7dev.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8d",
    "Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.4.4",
    "Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.0.16",
    "Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/0.8.12",
    "Lynx/2.8.4rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7a",
    "w3m/0.5.2 (Linux i686; it; Debian-3.0.6-3)",
    "w3m/0.5.2 (Linux i686; en; Debian-3.0.6-3)",
    "w3m/0.5.2 (Debian-3.0.6-3)",
    "w3m/0.5.2",
    "w3m/0.5.1+cvs-1.968",
    "Mozilla/5.0 (PLAYSTATION 3; 3.55)",
    "Mozilla/5.0 (PLAYSTATION 3; 2.00)",
    "Mozilla/5.0 (PLAYSTATION 3; 1.90)",
    "wii libnup/1.0",
    "Mozilla/5.0 (X11; U; Linux x86_64; it-it) AppleWebKit/534.26+ (KHTML, like Gecko) Ubuntu/11.04 Epiphany/2.30.6",
    "Mozilla/5.0 (X11; U; Linux x86_64; fr-FR) AppleWebKit/534.7 (KHTML, like Gecko) Epiphany/2.30.6 Safari/534.7",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Epiphany/2.30.6 Safari/534.7",
    "Mozilla/5.0 (X11; U; Linux x86_64; ca-ad) AppleWebKit/531.2+ (KHTML, like Gecko) Safari/531.2+ Epiphany/2.30.6",
    "Mozilla/5.0 (X11; U; Linux x86; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Epiphany/2.30.6 Safari/534.7",
    "Mozilla/5.0 (X11; U; Linux i686; sv-se) AppleWebKit/531.2+ (KHTML, like Gecko) Safari/531.2+ Epiphany/2.30.6"
    ]

http_header = list()

ua_chrome_3_0_182 = collections.OrderedDict()
ua_chrome_3_0_182["Host"] = "www.google.com"
ua_chrome_3_0_182["User-Agent"] = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/531.0 (KHTML, like Gecko) Chrome/3.0.182.2 Safari/531.0"
ua_chrome_3_0_182["Connection"] = "keep-alive"
ua_chrome_3_0_182["Accept"] = "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
ua_chrome_3_0_182["Accept-Encoding"] = "gzip,deflate,bzip2,sdch"
ua_chrome_3_0_182["Avail-Dictionary"] = "3iU0DwMp"
ua_chrome_3_0_182["Accept-Language"] = "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"
ua_chrome_3_0_182["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.3"
http_header.append(ua_chrome_3_0_182)

ua_chrome_31_0_1650_57 = collections.OrderedDict()
ua_chrome_31_0_1650_57["Host"] = "www.google.com"
ua_chrome_31_0_1650_57["Connection"] = "keep-alive"
ua_chrome_31_0_1650_57["Cache-Control"] = "max-age=0"
ua_chrome_31_0_1650_57["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
ua_chrome_31_0_1650_57["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36"
ua_chrome_31_0_1650_57["Accept-Encoding"] = "gzip,deflate,sdch"
ua_chrome_31_0_1650_57["Avail-Dictionary"] = "3iU0DwMp"
ua_chrome_31_0_1650_57["Accept-Language"] = "en-US,en;q=0.8"
http_header.append(ua_chrome_31_0_1650_57)

ua_firefox_3_0 = collections.OrderedDict()
ua_firefox_3_0["Host"] = "www.google.com"
ua_firefox_3_0["User-Agent"] = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9) Gecko/2008052906 Firefox/3.0"
ua_firefox_3_0["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ua_firefox_3_0["Accept-Language"] = "en-US,en;q=0.5"
ua_firefox_3_0["Accept-Encoding"] = "gzip,deflate"
ua_firefox_3_0["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
ua_firefox_3_0["Keep-Alive"] = "300"
ua_firefox_3_0["Connection"] = "keep-alive"
http_header.append(ua_firefox_3_0)

ua_firefox_3_5 = collections.OrderedDict()
ua_firefox_3_5["Host"] = "www.google.com"
ua_firefox_3_5["User-Agent"] = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1) Gecko/20090624 Firefox/3.5"
ua_firefox_3_5["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ua_firefox_3_5["Accept-Language"] = "en-US,en;q=0.5"
ua_firefox_3_5["Accept-Encoding"] = "gzip,deflate"
ua_firefox_3_5["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
ua_firefox_3_5["Keep-Alive"] = "300"
ua_firefox_3_5["DNT"] = "1"
ua_firefox_3_5["Connection"] = "keep-alive"
http_header.append(ua_firefox_3_5)

ua_firefox_3_6_28 = collections.OrderedDict()
ua_firefox_3_6_28["Host"] = "www.google.com"
ua_firefox_3_6_28["User-Agent"] = "Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.28) Gecko/20120306 Firefox/3.6.28"
ua_firefox_3_6_28["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ua_firefox_3_6_28["Accept-Language"] = "de-de,de;q=0.8,en-us;q=0.5,en;q=0.3"
ua_firefox_3_6_28["Accept-Encoding"] = "gzip,deflate"
ua_firefox_3_6_28["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
ua_firefox_3_6_28["Keep-Alive"] = "115"
ua_firefox_3_6_28["DNT"] = "1"
ua_firefox_3_6_28["Connection"] = "127.0.0.1"
http_header.append(ua_firefox_3_6_28)

ua_firefox_4_0 = collections.OrderedDict()
ua_firefox_4_0["Host"] = "www.google.com"
ua_firefox_4_0["User-Agent"] = "Mozilla/5.0 (Windows NT 5.1; rv:2.0) Gecko/20100101 Firefox/4.0"
ua_firefox_4_0["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ua_firefox_4_0["Accept-Language"] = "en-us;en;q=0.5"
ua_firefox_4_0["Accept-Encoding"] = "gzip,deflate"
ua_firefox_4_0["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
ua_firefox_4_0["Keep-Alive"] = "115"
ua_firefox_4_0["Connection"] = "keep-alive"
http_header.append(ua_firefox_4_0)

ua_firefox_25_0_1 = collections.OrderedDict()
ua_firefox_25_0_1["Host"] = "www.google.com"
ua_firefox_25_0_1["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/25.0"
ua_firefox_25_0_1["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ua_firefox_25_0_1["Accept-Language"] = "en-US,en;q=0.5"
ua_firefox_25_0_1["Accept-Encoding"] = "gzip,deflate"
ua_firefox_25_0_1["Connection"] = "keep-alive"
http_header.append(ua_firefox_25_0_1)

ua_chrome_26_0_1410_64 = collections.OrderedDict()
ua_chrome_26_0_1410_64["Host"] = "www.google.com"
ua_chrome_26_0_1410_64["Connection"] = "keep-alive"
ua_chrome_26_0_1410_64["User-Agent"] = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.64 Safari/537.31"
ua_chrome_26_0_1410_64["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ua_chrome_26_0_1410_64["Accept-Encoding"] = "gzip,deflate,sdch"
ua_chrome_26_0_1410_64["Accept-Language"] = "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"
ua_chrome_26_0_1410_64["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.3"
http_header.append(ua_chrome_26_0_1410_64) 

ua_lynx_2_8_7rel_2 = collections.OrderedDict()
ua_lynx_2_8_7rel_2["Host"] = "www.google.com"
ua_lynx_2_8_7rel_2["Accept"] = "text/html, text/plain, text/css, text/sgml, */*;q=0.01"
ua_lynx_2_8_7rel_2["Accept-Encoding"] = "gzip, bzip2"
ua_lynx_2_8_7rel_2["Accept-Language"] = "en"
ua_lynx_2_8_7rel_2["User-Agent"] = "Lynx/2.8.7rel.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.0.1e"
http_header.append(ua_lynx_2_8_7rel_2)


