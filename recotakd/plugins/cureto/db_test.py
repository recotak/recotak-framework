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
from __future__ import with_statement
from ctools import cComm
import re
import logging

# logging
LOG = "/tmp/cComm.log"
FORMAT = '%(asctime)s - %(name)s - %(levelname)s' + \
    '- %(threadName)s - %(message)s'
logging.basicConfig(filename=LOG,
                    filemode="w",
                    format=FORMAT,
                    level=logging.DEBUG)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


errcodes = []


def validate(status, content, **kwargs):
    m = {}
    m['m1'] = False
    m['m1_or'] = False
    m['m1_and'] = True
    m['f1'] = False
    m['f2'] = False

    for key in ['m1', 'm1_or', 'm1_and', 'f1', 'f2']:
        try:
            valid = kwargs[key]
            if not valid:
                continue
            try:
                m[key] = (int(valid) == status)
            except:
                m[key] = (re.search(valid, content, re.IGNORECASE) is not None)
        except:
            pass

    return (m['m1'] or m['m1_or']) \
        and m['m1_and'] \
        and not (m['f1'] or m['f2'])


def test(mark, test_line):  # mark, test):
    """
    Try to fetch resource from mark

    Input:
        mark        cComm.Mark object
        test_line   line from database/db_tests (nikto format)
    """

    logger.info('Testing %s on %s', test_line.decode('latin-1'), mark.ident)
    #mark, test_line = args

    mdict = {}
    test_id, \
        osvdb, \
        stype, \
        uri, \
        method, \
        mdict['m1'], \
        mdict['m1_or'], \
        mdict['m1_and'], \
        mdict['f1'], \
        mdict['f2'], \
        summary, \
        data, \
        headers = \
        test_line.split('","')

    status, content, error, request, res_headers = \
        cComm.Comm.fetch(mark, uri, method, data)
    success = True

    if error:
        logger.warning(error)
        success = False

    if status == '200':
        # TODO: show ok
        pass
    elif status in ('300', '301', '302', '303', '307'):
        try:
            print 'Reloc: ' + res_headers['location']
        except KeyError:
            print 'Reloc: ' + res_headers['Location']
        success = False

    for errcode in test.errcodes:
        if errcode in status:
            logger.warning('errcode %d is status %d' % (errcode, status))
            success = False
            break

    success = validate(status,
                       content,
                       **mdict
                       )

    result = (summary, test_id, request, content, osvdb, method, uri)
    yield (success, mark, result)
    raise StopIteration


if __name__ == '__main__':
    m1 = '100'
    m1_or = 'bla'
    m1_and = ''
    f1 = ''
    f2 = ''
    mdict = {}
    for key in ['m1', 'm1_or', 'm1_and', 'f1', 'f2']:
        mdict[key] = locals()[key]
    r = validate(200, 'bla', **mdict)
    r = validate(200, 'bla', m1='100', m1_or='bla', m1_and=200, f1=100, f2='bla')
