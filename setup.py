#!c:\python\python.exe

# $Id: setup.py 238 2010-04-05 20:40:46Z rgovostes $

import os.path

from distutils.core import setup

mac = [ ]
if os.path.exists("pydbg/libmacdll.dylib"):
   mac = [ "libmacdll.dylib" ]

setup( name         = "PaiMei",
       version      = "1.2",
       description  = "PaiMei - Reverse Engineering Framework",
       author       = "Pedram Amini",
       author_email = "pedram.amini@gmail.com",
       url          = "http://www.openrce.org",
       license      = "GPL",
       packages     = ["pida", "pgraph", "pydbg", "utils"],
       package_data = {
                        "pydbg" : [ "pydasm.pyd" ] + mac,
                        "utils" : mac
                      }
)