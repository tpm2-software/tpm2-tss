//**********************************************************************;
// Copyright (c) 2015, Intel Corporation All rights reserved.
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
#include "tss2_endian.h"

void Unmarshal_Simple_TPM2B_NoSizeCheck(UINT8 *outBuffPtr, UINT32 maxResponseSize, size_t *nextData, TPM2B *outTPM2B, TSS2_RC *rval)
{
    int i;
    UINT16 length;

    if(*rval)
        return;

    if (!outBuffPtr || !nextData) {
        *rval = TSS2_SYS_RC_BAD_REFERENCE;
        return;
    }

    length = BE_TO_HOST_16(*(UINT16 *)(outBuffPtr + *nextData));

    *rval = Tss2_MU_UINT16_Unmarshal(outBuffPtr, maxResponseSize, nextData, outTPM2B ? &outTPM2B->size : NULL);

    if (*rval)
        return;

    for (i = 0; i < length; i++) {
        *rval = Tss2_MU_UINT8_Unmarshal(outBuffPtr, maxResponseSize, nextData, outTPM2B ? &outTPM2B->buffer[i] : NULL);

        if (*rval)
            return;
    }
}
