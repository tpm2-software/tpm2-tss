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

#include "sapi/tpm20.h"
#include "sysapi_util.h"

typedef struct {
    TPM2_ALG_ID  algId;
    UINT16      size;
} HASH_SIZE_INFO;

HASH_SIZE_INFO   hashSizes[] = {
    {TPM2_ALG_SHA1,          TPM2_SHA1_DIGEST_SIZE},
    {TPM2_ALG_SHA256,        TPM2_SHA256_DIGEST_SIZE},
    {TPM2_ALG_SHA384,        TPM2_SHA384_DIGEST_SIZE},
    {TPM2_ALG_SHA512,        TPM2_SHA512_DIGEST_SIZE},
    {TPM2_ALG_SM3_256,       TPM2_SM3_256_DIGEST_SIZE},
    {TPM2_ALG_NULL,          0}
};

UINT16 GetDigestSize(TPM2_ALG_ID authHash)
{
    uint8_t  i;

    for (i = 0; i < sizeof(hashSizes) / sizeof(HASH_SIZE_INFO); i++)
        if (hashSizes[i].algId == authHash)
            return hashSizes[i].size;

    return 0;
}
