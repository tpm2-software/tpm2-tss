/*
 * Copyright (c) 2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "session-util.h"
#include "sapi-util.h"
#include "context-util.h"
#include "util/tss2_endian.h"
#define LOGMODULE test
#include "util/log.h"

TSS2_RC
TpmCalcPHash(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2_HANDLE handle1,
    TPM2_HANDLE handle2,
    TPM2_HANDLE handle3,
    TPMI_ALG_HASH authHash,
    bool command,
    TPM2B_DIGEST *pHash)
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *tcti_context;
    UINT32 i;
    TPM2B_NAME name1, name2, name3;
    TPM2B_MAX_BUFFER hashInput;
    UINT8 *hashInputPtr;
    size_t parametersSize;
    const uint8_t *startParams;
    TPM2_CC cmdCode;

    name1.size = 0;
    name2.size = 0;
    name3.size = 0;
    hashInput.size = 0;

    rval = Tss2_Sys_GetTctiContext(sysContext, &tcti_context);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    if (command) {
        rval = TpmHandleToName(tcti_context, handle1, &name1);
        if (rval != TPM2_RC_SUCCESS)
                return rval;

        rval = TpmHandleToName(tcti_context, handle2, &name2);
        if (rval != TPM2_RC_SUCCESS)
            return rval;

        rval = TpmHandleToName(tcti_context, handle3, &name3);
        if (rval != TPM2_RC_SUCCESS)
            return rval;

        rval = Tss2_Sys_GetCpBuffer(sysContext, &parametersSize, &startParams);
        if (rval != TPM2_RC_SUCCESS)
            return rval;
    } else {
        rval = Tss2_Sys_GetRpBuffer(sysContext, &parametersSize, &startParams);
        if (rval != TPM2_RC_SUCCESS)
            return rval;

        hashInputPtr = &(hashInput.buffer[hashInput.size]);
        /* This is response code. Assuming 0 (success) */
        *(UINT32 *)hashInputPtr = 0;
        hashInput.size += 4;
    }

    rval = Tss2_Sys_GetCommandCode(sysContext, (UINT8 *)&cmdCode);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    hashInputPtr = &(hashInput.buffer[hashInput.size]);
    *(UINT32 *)hashInputPtr = cmdCode;
    hashInput.size += 4;

    rval = ConcatSizedByteBuffer(&hashInput, (TPM2B *)&name1);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    rval = ConcatSizedByteBuffer(&hashInput, (TPM2B *)&name2);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    rval = ConcatSizedByteBuffer(&hashInput, (TPM2B *)&name3);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    if (hashInput.size + parametersSize > sizeof(hashInput.buffer))
        return TSS2_SYS_RC_INSUFFICIENT_BUFFER;

    for(i = 0; i < parametersSize; i++)
        hashInput.buffer[hashInput.size + i ] = startParams[i];

    hashInput.size += (UINT16)parametersSize;
    LOGBLOB_DEBUG(&hashInput.buffer[0], hashInput.size, "PHASH input bytes=");

    if (hashInput.size > sizeof(hashInput.buffer))
        return TSS2_SYS_RC_INSUFFICIENT_BUFFER;

    rval = hash(authHash, hashInput.buffer, hashInput.size, pHash);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    LOGBLOB_DEBUG(&pHash->buffer[0], pHash->size, "PHASH =");
    return rval;
}

UINT32 TpmHandleToName(
    TSS2_TCTI_CONTEXT *tcti_context,
    TPM2_HANDLE handle,
    TPM2B_NAME *name)
{
    TSS2_RC rval;
    TPM2B_NAME qualified_name = TPM2B_NAME_INIT;
    TPM2B_PUBLIC public;
    TPM2B_NV_PUBLIC nvPublic;
    TSS2_SYS_CONTEXT *sysContext;
    UINT8 *namePtr;

    if (!tcti_context || !name)
        return TSS2_SYS_RC_BAD_VALUE;

    namePtr = name->name;

    if (handle == TPM2_RH_NULL) {
        name->size = 0;
        return TSS2_RC_SUCCESS;
    }

    switch(handle >> TPM2_HR_SHIFT)
    {
        case TPM2_HT_NV_INDEX:
            sysContext = sapi_init_from_tcti_ctx(tcti_context);
            if (sysContext == NULL)
                return TSS2_SYS_RC_GENERAL_FAILURE;

            nvPublic.size = 0;
            rval = Tss2_Sys_NV_ReadPublic(sysContext, handle, 0,
                                          &nvPublic, name, 0);
            sapi_teardown(sysContext);
            break;

        case TPM2_HT_TRANSIENT:
        case TPM2_HT_PERSISTENT:
            sysContext = sapi_init_from_tcti_ctx(tcti_context);
            if (sysContext == NULL)
                return TSS2_SYS_RC_GENERAL_FAILURE;

            public.size = 0;
			rval = Tss2_Sys_ReadPublic(sysContext, handle, 0,
                                       &public, name, &qualified_name, 0);
            sapi_teardown(sysContext);
            break;

        default:
            rval = TPM2_RC_SUCCESS;
            name->size = sizeof(TPM2_HANDLE);
            *(TPM2_HANDLE *)namePtr = BE_TO_HOST_32(handle);
    }
    return rval;
}
