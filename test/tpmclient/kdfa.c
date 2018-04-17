//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdio.h>
#include <stdlib.h>

#include "tss2_tpm2_types.h"
#include "../integration/sapi-util.h"

#include "tpmclient.int.h"
#include "sysapi_util.h"
#include "util/tss2_endian.h"
#define LOGMODULE test
#include "util/log.h"

TSS2_RC KDFa(
    TPMI_ALG_HASH hashAlg,
    TPM2B *key,
    char *label,
    TPM2B *contextU,
    TPM2B *contextV,
    UINT16 bits,
    TPM2B_MAX_BUFFER *resultKey)
{
    TPM2B_DIGEST digest;
    TPM2B_DIGEST tpm2bLabel, tpm2bBits, tpm2bi;
    TPM2B_DIGEST *bufferList[8];
    UINT32 val;
    TSS2_RC rval;
    int i, j;
    UINT16 bytes = bits / 8;

    resultKey->size = 0;
    tpm2bi.size = 4;
    tpm2bBits.size = 4;
    val = BE_TO_HOST_32(bits);
    memcpy(tpm2bBits.buffer, &val, 4);
    tpm2bLabel.size = strlen(label) + 1;
    memcpy(tpm2bLabel.buffer, label, tpm2bLabel.size);

    LOG_DEBUG("KDFA, hashAlg = %4.4x", hashAlg);
    LOGBLOB_DEBUG(&key->buffer[0], key->size, "KDFA, key =");
    LOGBLOB_DEBUG(&tpm2bLabel.buffer[0], tpm2bLabel.size, "KDFA, tpm2bLabel =");
    LOGBLOB_DEBUG(&contextU->buffer[0], contextU->size, "KDFA, contextU =");
    LOGBLOB_DEBUG(&contextV->buffer[0], contextV->size, "KDFA, contextV =");

    for (i = 1, j = 0; resultKey->size < bytes; j = 0) {
        val = BE_TO_HOST_32(i++);
        memcpy(tpm2bi.buffer, &val, 4);
        bufferList[j++] = (TPM2B_DIGEST *)&tpm2bi;
        bufferList[j++] = (TPM2B_DIGEST *)&tpm2bLabel;
        bufferList[j++] = (TPM2B_DIGEST *)contextU;
        bufferList[j++] = (TPM2B_DIGEST *)contextV;
        bufferList[j++] = (TPM2B_DIGEST *)&tpm2bBits;
        bufferList[j++] = NULL;

        for (j = 0; bufferList[j] != NULL; j++) {
            LOGBLOB_DEBUG(&bufferList[j]->buffer[0], bufferList[j]->size, "bufferlist[%d]:", j);
            ;
        }

        rval = hmac(hashAlg, key->buffer, key->size, bufferList, &digest);
        if (rval != TPM2_RC_SUCCESS) {
            LOGBLOB_ERROR(digest.buffer, digest.size, "HMAC Failed rval = %d", rval);
            return rval;
        }

        ConcatSizedByteBuffer(resultKey, (TPM2B *)&digest);
    }

    /* Truncate the result to the desired size. */
    resultKey->size = bytes;
    LOGBLOB_DEBUG(&resultKey->buffer[0], resultKey->size, "KDFA, resultKey = ");
    return TPM2_RC_SUCCESS;
}
