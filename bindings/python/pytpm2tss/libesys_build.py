#!/usr/bin/python3
"""
SPDX-License-Identifier: BSD-2

Copyright 2018, Fraunhofer SIT
All rights reserved.
"""

import os
import cffi

# env CFLAGS and LDFLAGS unfortunately override our definitions below
os.environ["CFLAGS"] = ""
os.environ["LDFLAGS"] = ""

ffibuilder = cffi.FFI()
ffibuilder.set_source("pytpm2tss._libesys",
                      """#include <tss2/tss2_esys.h>""",
                      libraries = ['tss2-esys'],
                      include_dirs = ['../../include'],
                      library_dirs = ['../../src/tss2-esys/.libs',
                                      '../../src/tss2-tcti/.libs',
                                     ],
                     )

ffibuilder.cdef(open('pytpm2tss/libesys.h').read())

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
