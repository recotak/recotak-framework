#!/usr/bin/env python2

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
import ccdClasses as ccd
import logging
import geoip

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


desc = {
    'remote_data': {
        'GeoLite2-City-CSV.zip': {
            'src': 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City-CSV.zip',
            'extract_dir': '.',
        },
        'GeoLite2-Country-CSV.zip': {
            'src': 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip',
            'extract_dir': '.',
        }
    }
}

def main(dbh, args):
    logger.debug("starting plugin %s", __name__)
    geoip.parse(args)


def register():
    plugin = ccd.Plugin('geoip',
                        ["scanner"],
                        dbtemplate=[ccd.Tmpl.GEOIP])
    plugin.execute = main
    return plugin


if __name__ == '__main__':
    import __builtin__
    import sys
    if not hasattr(__builtin__, 'openany'):
        __builtin__.openany = open
        __builtin__.openhome = open
        __builtin__.openshared = open
    main(None, sys.argv[1:])