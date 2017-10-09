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

void Marshal_Simple_TPM2B(UINT8 *inBuffPtr, UINT32 maxCommandSize, size_t *nextData, TPM2B *value, TSS2_RC *rval)
{
    INT64 usedCommandBuffSize;
    int i = 0;

    if (*rval)
        return;
    if (!inBuffPtr || !nextData) {
        *rval = TSS2_SYS_RC_BAD_REFERENCE;
        return;
    }

    usedCommandBuffSize = (INT64)*nextData + sizeof(UINT16);

    /* Check for possible writing past end of command buffer */
    if (usedCommandBuffSize > (INT64)maxCommandSize) {
        *rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        return;
    }

    if (value) {
        *rval = Tss2_MU_UINT16_Marshal(value->size, inBuffPtr, maxCommandSize, nextData);
        if (*rval)
            return;

        for (i = 0; i < value->size; i++) {
            *rval = Tss2_MU_UINT8_Marshal(value->buffer[i], inBuffPtr, maxCommandSize, nextData);

            if (*rval)
                break;
        }
    } else {
        *rval = Tss2_MU_UINT16_Marshal(0, inBuffPtr, maxCommandSize, nextData);
    }
}
