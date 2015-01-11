from ctools.dns.exceptions import BadUrl, DomainNotFound
from urlparse import urlparse
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
import os.path
import sys

FILE = "%s/wordlists/effective_tld_names.dat" % sys.prefix
tld_names = set()


def __init():
    """ read top level domain from FILE in tld_names """
    global tld_names

    with open(FILE, "r") as f:
        for line in f:

            if line[0] == "\n":
                continue

            tld_names.add(line.strip())

def get_domain(fqdn):
    """
    extracts the domain and top level domain from a given fqdn

    input:
        fqdn    fully qualified domain name to extract domain from

    output:
        domain  domain and top level domain

    """
    if not tld_names:
        __init()

    domain_parsed = urlparse(fqdn)
    if domain_parsed.netloc:
        domain = domain_parsed.netloc.split(":", 1)[0]
    elif domain_parsed.path:
        domain = domain_parsed.path.split("@", 1)[0]
        domain = domain.split("/", 1)[0]
    else:
        BadUrl(url=fqdn)

    if not domain:
        BadUrl(url=fqdn)

    # iteratore over fqdn to check which substring represents the actual domain
    parts = domain.split(".")
    for i in range(len(parts)):
        d = ".".join(parts[i:])

        if d in tld_names:
            return ".".join(parts[i-1:]) if i > 0 else ".".join(parts)

    else:
        raise DomainNotFound(fqdn)






