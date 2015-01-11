"""
This module generates a pdf based on a latex document.
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

import os
import logging
import tempfile
import shutil
import tarfile
import subprocess
from genreport.latex import gen_tex

__version__ = 0.1

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

def gen_pdf(db, pid, filename, template, tables_dict, lang):
    """
    generates a pdf report by compiling a latex template

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

    logger.debug('generating pdf report %s in %s', filename, lang)

    # we need some temporary things that we use for generating the latex
    # document
    tmp_dir = tempfile.mkdtemp()
    tmp_file = "%s/report.tex" % tmp_dir

    # extract latex template
    template_main = _extract_latex_template(template, tmp_dir)
    if not template_main:
        raise Exception("Got no valid latex template!")

    # generating latex
    try:
        texfile = gen_tex(db,
                          pid,
                          tmp_file,
                          template_main,
                          tables_dict,
                          lang)

        if not texfile and not texfile == tmp_file:
            raise Exception('Error, could not create texfile')

        # generate pdf and name is correctly
        cwd = os.getcwd()
        os.chdir(tmp_dir)
        pdffile = _execute_pdflatex(texfile)
        shutil.copy(pdffile, filename)
        os.chdir(cwd)

    finally:

        try:
            shutil.rmtree(tmp_dir)  # delete directory

        except OSError as exc:
            if exc.errno != 2:  # code 2 - no such file or directory
                raise  # re-raise exception

    logger.info('Created pdf %s', filename)
    return filename

def _extract_latex_template(template, dst):
    """ extract latex template as tarball to dst """
    template_main = None
    tar = None

    try:
        logger.debug('Trying to open template as tar: %s', template)
        tar = tarfile.open(template)
        tar.extractall(path=dst)

        # find tex file:
        files = [os.path.join(dst, f) for f in os.listdir(dst)]
        tex_files = filter(lambda f: os.path.isfile(f) and \
                                     os.path.splitext(f)[1] == '.tex',
                                  files)

        logger.debug('Found tex files %s', repr(tex_files))
        template_main = tex_files[0]

    except Exception, e:
        shutil.copy(template_main, dst)
        raise Exception('Failed to open template as tar: %s', e)

    finally:
        if tar:
            tar.close()

    return template_main

def _execute_pdflatex(texfile):
    """
    execute pdflatex on passed texfile. pdflatex is called twice. return the
    name of the new pdf file

    input:
        texfile     latex file to generate pdf from

    output
        pdffile     name of the generated pdf file

    """
    MODE = "batchmode"
    logger.debug("texfile=%s", texfile)
    proc = subprocess.Popen(['pdflatex', "-interaction", MODE, texfile],
                            stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    stdout, stderr = proc.communicate()

    if not proc.returncode == 0:
        logger.debug(stdout)
        logger.error(stderr)
        raise Exception("Failed to execute pdflatex")

    # longatble needs to bu built twice in order to look nice
    proc = subprocess.Popen(['pdflatex', "-interaction", MODE, texfile],
                            stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    stdout, stderr = proc.communicate()

    if not proc.returncode == 0:
        logger.debug(stdout)
        logger.error(stderr)
        raise Exception("Failed to execute pdflatex")

    # check whether pdf file exists. if not, raise an IOError
    pdffile = texfile.replace(".tex", ".pdf")
    if not os.path.isfile(pdffile):
        raise Exception("pdflatex failed to generate pdffile!")

    return pdffile


