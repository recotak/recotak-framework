"""
This module creates export the project database to csv
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

"""
from database import ccddb
from database.project import db as projectdb
import logging

__version__ = 0.1

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)


def gen_csv(db, pid, filename):
    """
    generates a csv report

    input:
        db          database connection object
        pid         project id
        filename    name of the file to generate

    output:
        final filename

    """


    logger.debug('generating csv report %s', filename)
    tables = projectdb.get_table_dict(db, pid)

    if not tables:
        return

    fd = open(filename, 'w')

    for name, data in tables.items():
        fd.write('-' * 80)
        fd.write('\n')
        fd.write(name)
        fd.write('\n')
        fd.write('-' * 80)
        fd.write('\n')
        for items in data:
            fd.write(','.join(items))
            fd.write('\n')
    fd.close()

    logger.info('Created csv %s', filename)
    return filename


