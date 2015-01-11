"""
module generates a odf report.
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
from odf.opendocument import OpenDocumentChart, OpenDocumentText
from odf.table import Table, TableColumn, TableRow, TableCell
from genreport.creport.doc import chart, document, styles
from database.project import db as projectdb
from odf.text import P,H, A, List, ListItem
from strings import get_string
import logging

__version__ = 0.1

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

def gen_odf(db, pid, tables_dict, filename="/tmp/report.odt", lang="de"):
    """
    generates an odf report

    input:
        db          database connection object
        pid         project id
        tables_dict contains the data to report
        filename    name of the file to generate
        lang        language to generate report in

    output:
        final filename

    """
    logger.debug('generating odf report')

    doc = document.Doc(filename, language=lang)
    add_tables(doc, tables_dict)

    doc.save()
    logger.info('Created odf %s', filename)
    return filename

def add_header(doc, text, level):
    """ add odf header object """
    header = H(outlinelevel=level, text=text, stylename="header.%s" % level)
    doc.add(header)

def add_paragraph(doc, text):
    """ add odf paragraph object """
    paragraph = P(text=text, stylename="default")
    doc.add(paragraph)

def add_tables(doc, tables):
    """
    for every database database table create an odf table and add it to the
    document

    input:
        doc     odf document
        tables  dictionary containg the database tables

    """
    for name, table in tables.items():
        # header
        add_header(doc, name, 2)

        # description
        add_paragraph(doc, table["description"])

        # solution
        add_paragraph(doc, table["solution"])

        # data
        odf_table = create_odf_table(name, table["data"])
        doc.add(odf_table)

def create_odf_table(name, data):
    """
    returns an odf table object that has been added a first row containing
    the columns' title

    """
    table = Table(name=name)

    # we need to add columns. The columns itself do not contain the data
    # though. So, we add them only for the first row.
    for c in range(len(data[0])):
        # add table columns
        col = TableColumn(numbercolumnsrepeated=1, stylename="wCol0")
        table.addElement(col)

    for i, item in enumerate(data):

        # the first row contains the table heading, which is colored
        # differently from the rest of the table. Additionally,
        style = "bgrOrange" if i == 0 else None

        logger.debug("row content:%s", item)
        tr = create_odf_table_row(item, style)
        table.addElement(tr)

    return table

def create_odf_table_row(data, first=""):
    """
    returns a odt table row that contains the passed data in odf table cells

    input:
        first   style scheme of the first row's cells

    output:
        row     the created table row containing cells with corresponding data

    """
    row = TableRow()

    for i, item in enumerate(data):

        # we need to distinguish between first column, middle columns and last
        # columns. The first and the last have outer borders, while the middle
        # have not. If we draw the first row, skip this and use the passed
        # style.
        if not first:

            # first
            if i == 0:
                style = "col_left"

            # last
            elif i == (len(data)-1):
                style = "col_right"

            # middle
            else:
                style = "col_middle"

        else:
            style = first

        logger.debug("cell content (i=%d):%s, style=%s", i, item, style)

        cell = TableCell(valuetype= 'string', stylename=style)
        cell.addElement(P(text=item, stylename="default"))
        row.addElement(cell)

    return row



