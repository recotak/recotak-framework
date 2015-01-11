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
from dir_bruteforce import DirBruteforce
from dir_bruteforce import parse
from dir_bruteforce import __plgname__
import ccdClasses as ccd
import sys

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def main(dbh, args):
    logger.debug("starting plugin %s", __plgname__)
    base_url, files, dirs, nthreads, recurse, depth, wait, negative = \
        parse(args)

    dbf = DirBruteforce(base_url,
                        dirs,
                        files,
                        ['/'],
                        recurse,
                        negative,
                        depth,
                        nthreads,
                        wait,
                        dbhandler=dbh,
                        socks=True)

    dbf.scan()


def register():
    plugin = ccd.Plugin(__plgname__,
                        ["bruteforce/directories"],
                        dbtemplate=[ccd.Tmpl.DIR_BRUTEFORCE])

    plugin.execute = main
    return plugin


if __name__ == "__main__":
    base_url, files, dirs, nthreads, recurse, depth, wait, negative = \
        parse(sys.argv[1:])

    dbf = DirBruteforce(base_url,
                        dirs,
                        files,
                        ['/'],
                        recurse,
                        negative,
                        depth,
                        1,
                        wait)
    dbf.scan()
