"""
This module creates latex report. To do so, it accesses database, reads its
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
content from various project tables and sets up the tex.

"""
from database.project import db as projectdb
import logging
import re

__version__ = 0.1

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

def gen_tex(db, pid, filename, template, tables_dict, lang):
    """
    generates a latex report

    input:
        db          database connection object
        pid         project id
        filename    name of the file to generate
        template    path to latex template that is used for generation
        tables_dict contains the data to report
        lang        language to generate report in

    output:
        final filename

    """

    logger.debug('generating tex report %s in %s', filename, lang)

    with open(template, 'r') as template_fd:
        template = template_fd.read()

    table_marker = re.search("%tables%", template)
    start, stop = table_marker.span()
    template_first = template[:start]
    template_last = template[stop:]
    tables_str = ''

    try:
        tables_str += _make_tex_table('01_heartbleed_vulnerable',
                                      tables_dict['01_heartbleed_vulnerable'])
    except:
        pass

    for name, table in tables_dict.items():
        if 'bleed_vuln' in name:
            continue
        if not table["data"] or not table["data"][0]:
            continue
        tables_str += _make_tex_table(name, table)

#    if not filename:
#        filename = '/tmp/report.tex'

    with open(filename, 'w') as fd:
        fd.write(template_first + '\n' + tables_str + '\n' + template_last)

    logger.info('Created tex %s', filename)
    return filename

def _make_tex_table(name, content):
    """ returns a latex table string """
    tables_str = '\\section*{%s}\n' % _escape_latex(name)

    # add meta information
    if content["description"]:
        tables_str += "%s\\\\" % content["description"]
        tables_str += "\\\\"

    if content["solution"]:
        tables_str += "%s\\\\" % content["solution"]

    # get number of columns (first field are always column names)
    data = content["data"]
    n_fields = len(data[0])

    tables_str += '\\begin{longtable}{@{\\extracolsep{\\fill}}' + '|l' * \
                      n_fields + '|@{}}'

    tables_str += '\n\\hline\n'
    tables_str += ' & '.join(map(_escape_latex, data[0]))
    tables_str += '\\\\\n\\hline\n'

    for items in data[1:]:
        if 'bleed_vulnerable' in name:
            tables_str += '\\cellcolor[rgb]{0.9, 0.1, 0}\n'
        tables_str += ' & '.join(map(_escape_latex, items))
        tables_str += '\\\\\n'

    tables_str += '\\hline\n'
    tables_str += '\\end{longtable}\n'

    return tables_str

def _escape_latex(data):
    data = str(data)
    CHARS = {
        '&':  r'\&',
        '%':  r'\%',
        '$':  r'\$',
        '#':  r'\#',
        '_':  r'\_',
        '{':  r'\{',
        '}':  r'\}',
        '~':  r'\~',
        '^':  r'\^',
        '\\': r'\\',
    }

    return ''.join([CHARS.get(char, char) for char in data])



