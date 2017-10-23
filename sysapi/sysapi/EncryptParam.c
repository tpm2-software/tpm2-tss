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
#include "tss2_endian.h"

TSS2_RC Tss2_Sys_GetEncryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *encryptParamSize,
    const uint8_t **encryptParamBuffer)
{
    TPM2B *encryptParam;

    if (!encryptParamSize || !encryptParamBuffer || !sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (SYS_CONTEXT->encryptAllowed == 0 ||
        BE_TO_HOST_16(SYS_RESP_HEADER->tag) == TPM_ST_NO_SESSIONS)
        return TSS2_SYS_RC_NO_ENCRYPT_PARAM;

    /* Get first parameter and return its size and a pointer to it. */
    SYS_CONTEXT->rpBuffer = (UINT8 *)SYS_CONTEXT->rspParamsSize;
    /* Skip over params size field. */
    SYS_CONTEXT->rpBuffer += 4;
    encryptParam = (TPM2B *)SYS_CONTEXT->rpBuffer;
    *encryptParamSize = BE_TO_HOST_16(encryptParam->size);
    *encryptParamBuffer = encryptParam->buffer;

    return TSS2_RC_SUCCESS;
}

TSS2_RC Tss2_Sys_SetEncryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t encryptParamSize,
    const uint8_t *encryptParamBuffer)
{
    TSS2_RC rval;
    size_t currEncryptParamSize;
    const uint8_t *currEncryptParamBuffer;

    if (!encryptParamBuffer || !sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_GetEncryptParam(sysContext,
                                    &currEncryptParamSize,
                                    &currEncryptParamBuffer);
    if (rval)
        return rval;

    if (encryptParamSize != currEncryptParamSize)
        return TSS2_SYS_RC_BAD_SIZE;

    if (currEncryptParamBuffer + encryptParamSize >
        SYS_CONTEXT->cmdBuffer + SYS_CONTEXT->maxCmdSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    memmove((void *)currEncryptParamBuffer,
            encryptParamBuffer, encryptParamSize);

    return TSS2_RC_SUCCESS;
}
