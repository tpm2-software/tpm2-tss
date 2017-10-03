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

TSS2_RC Tss2_Sys_GetDecryptParam(
	TSS2_SYS_CONTEXT 		*sysContext,
	size_t                  *decryptParamSize,
	const uint8_t 			**decryptParamBuffer
)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B *decryptParam;

    if( decryptParamSize == 0 || decryptParamBuffer == 0 || sysContext == 0 )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else if( SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE )
    {
        rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else if( SYS_CONTEXT->decryptAllowed == 0 )
    {
        rval = TSS2_SYS_RC_NO_DECRYPT_PARAM;
    }
    else
    {
        // Get first parameter and return its
        // size and a pointer to it.
        decryptParam = (TPM2B *)( SYS_CONTEXT->cpBuffer );
        *decryptParamSize = BE_TO_HOST_16(decryptParam->size);
        *decryptParamBuffer = &( decryptParam->buffer[0] );
    }
    return rval;
}


TSS2_RC Tss2_Sys_SetDecryptParam(
	TSS2_SYS_CONTEXT 		*sysContext,
	size_t                  decryptParamSize,
	const uint8_t			*decryptParamBuffer
)
{
	size_t          currDecryptParamSize;
	const uint8_t   *currDecryptParamBuffer;
    TSS2_RC         rval = TSS2_RC_SUCCESS;
    UINT32          sizeToBeUsed;
    UINT32          currCommandSize;
    const UINT8 *src, *limit;
    UINT8 *dst;
    UINT32 len;

    if( decryptParamBuffer == 0 || sysContext == 0 )
    {
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    rval = Tss2_Sys_GetDecryptParam( sysContext, &currDecryptParamSize, &currDecryptParamBuffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        return rval;
    }

    sizeToBeUsed = BE_TO_HOST_32(((TPM20_Header_In *)(SYS_CONTEXT->tpmInBuffPtr))->commandSize) + decryptParamSize;
    if( sizeToBeUsed > SYS_CONTEXT->maxCommandSize )
    {
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
    }

    if( currDecryptParamSize == 0 && SYS_CONTEXT->decryptNull )
    {
        if( decryptParamSize < 1 )
        {
            return TSS2_SYS_RC_BAD_VALUE;
        }

        /* Move stuff around. First move current cpBuffer down. */
        src = SYS_CONTEXT->cpBuffer + 2;
        dst = SYS_CONTEXT->cpBuffer + SYS_CONTEXT->cpBufferUsedSize + 2;
        len = SYS_CONTEXT->cpBufferUsedSize - 2;
        limit = SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->maxCommandSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        memmove(dst, src, len);

        SYS_CONTEXT->cpBufferUsedSize += decryptParamSize;
        *(UINT16 *)SYS_CONTEXT->cpBuffer = HOST_TO_BE_16(decryptParamSize);

        src = decryptParamBuffer;
        dst = (UINT8 *) currDecryptParamBuffer;
        len = decryptParamSize;
        limit = SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->maxCommandSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        /* Now copy in the encrypted decrypt param. */
        memmove(dst, src, len);

        // And fixup the command size.
        currCommandSize = BE_TO_HOST_32(((TPM20_Header_In *)(SYS_CONTEXT->tpmInBuffPtr))->commandSize);
        currCommandSize += decryptParamSize;
        ((TPM20_Header_In *)(SYS_CONTEXT->tpmInBuffPtr))->commandSize = HOST_TO_BE_32(currCommandSize);
    }
    else
    {
        if( decryptParamSize != currDecryptParamSize )
        {
            return TSS2_SYS_RC_BAD_SIZE;
        }

        *(UINT16 *)SYS_CONTEXT->cpBuffer = HOST_TO_BE_16(decryptParamSize);

        src = decryptParamBuffer;
        dst = (UINT8 *) currDecryptParamBuffer;
        len = decryptParamSize;
        limit = SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->maxCommandSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        memmove(dst, src, len);
    }

    return rval;
}
