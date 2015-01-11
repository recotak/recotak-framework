#!/usr/bin/env python2
from distutils.core import setup

VERSION = "0.0.0"
DESCRIPTION = 'recotak libraries.'

setup(name='recotak',
      version=VERSION,
      description=DESCRIPTION,
      author='felicitas hetzelt',
      #packages=["recotak", "recotak.input"],
      packages=["recotak"],
      #data_files=[("wordlists", ["wordlists/effective_tld_names.dat"]),
      #            ("img", ["img/header_logo.tif"]),
      #            ("img", ["img/header_logo.png"]),
      #            ("probes", ["probes/nmap-service-probes"])]
      )
