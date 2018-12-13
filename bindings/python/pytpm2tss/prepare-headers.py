#!/usr/bin/python3
"""
SPDX-License-Identifier: BSD-2

Copyright 2018, Fraunhofer SIT
All rights reserved.
"""

import re
import sys

def prepare(indir, outfile):
    indir = indir + '/tss2/'
    out = dict()

    #Read in headers
    s = open(indir + 'tss2_common.h').read()

    s += open(indir + 'tss2_tpm2_types.h').read()

    s += """
typedef struct TSS2_TCTI_CONTEXT TSS2_TCTI_CONTEXT;
typedef struct TSS2_TCTI_POLL_HANDLE TSS2_TCTI_POLL_HANDLE;
"""

    s += open(indir + 'tss2_esys.h').read()

    #Remove false define (workaround)
    s = re.sub('#define TPM2_MAX_TAGGED_POLICIES.*\n.*TPMS_TAGGED_POLICY\)\)',
               '', s, flags=re.MULTILINE)

    #Remove includes and guards
    s = re.sub('#ifndef.*', '', s)
    s = re.sub('#define .*_H\n', '', s)
    s = re.sub('#endif.*', '', s)
    s = re.sub('#error.*', '', s)
    s = re.sub('#ifdef __cplusplus\nextern "C" {', '', s, flags=re.MULTILINE)
    s = re.sub('#ifdef __cplusplus\n}', '', s, flags=re.MULTILINE)
    s = re.sub('#include.*', '', s)

    #Remove certain makros
    s = re.sub('#define TSS2_API_VERSION.*', '', s)
    s = re.sub('#define TSS2_ABI_VERSION.*', '', s)
    s = re.sub('#define TSS2_RC_LAYER\(level\).*', '', s)
    s = re.sub('(#define.*)TSS2_RC_LAYER\(0xff\)', '\g<1>0xff0000', s)

    #Remove comments
    s = re.sub('/\*.*?\*/', '', s, flags=re.MULTILINE)

    #Restructure #defines with ...
    s = re.sub('(#define [A-Za-z0-9_]+) +\(\(.*?\) \(.*?\)\)', '\g<1>...', s)
    s = re.sub('(#define [A-Za-z0-9_]+) +\(\(.*?\).*?\) ', '\g<1>...', s)
    s = re.sub('(#define [A-Za-z0-9_]+) .*\n.*?.*\)\)', '\g<1>...', s, flags=re.MULTILINE)
    s = re.sub('(#define [A-Za-z0-9_]+) .*', '\g<1>...', s)

    #Restructure structs and untions with ...
    s = re.sub('\[.*?\]', '[...]', s)
#    s = re.sub('typedef struct {[^}]*} +([A-Za-z0-9_]+);',
#               'typedef struct { ...; } \g<1>;', s, flags=re.MULTILINE)

#    s = re.sub('typedef union {[^}]*} ([A-Za-z0-9_]+);',
#               'typedef union { ...; } \g<1>;', s, flags=re.MULTILINE)

    #Write result
    f = open(outfile, 'w')
    f.write("""/* SPDX-License-Identifier: BSD-2
*
* Copyright 2019, Fraunhofer SIT
* All rights reserved.
*
* This file was automatically generated. Do not modify !
*/

""")

    f.write(s)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {0} <tss2-header-dir> <output-file>".format(sys.argv[0]))
        exit(1)
    prepare(sys.argv[1], sys.argv[2])
