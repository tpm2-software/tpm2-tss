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
	TSS2_SYS_CONTEXT 	*sysContext,
	size_t				*encryptParamSize,
	const uint8_t 		**encryptParamBuffer
)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B *encryptParam;
    void *otherData;

    if( encryptParamSize == 0 || encryptParamBuffer == 0 || sysContext == 0 )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else if( SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE )
    {
        rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else if( SYS_CONTEXT->encryptAllowed == 0 ||
            (BE_TO_HOST_16(((TPM20_Header_Out *)(SYS_CONTEXT->tpmOutBuffPtr))->tag) == TPM_ST_NO_SESSIONS))
    {
        rval = TSS2_SYS_RC_NO_ENCRYPT_PARAM;
    }
    else
    {
        // Get first parameter and return its
        // size and a pointer to it.
        otherData = SYS_CONTEXT->rspParamsSize;
        SYS_CONTEXT->rpBuffer = otherData;
        SYS_CONTEXT->rpBuffer += 4; // Skip over params size field.
        encryptParam = (TPM2B *)( SYS_CONTEXT->rpBuffer );
        *encryptParamSize = BE_TO_HOST_16(encryptParam->size);
        *encryptParamBuffer = &( encryptParam->buffer[0] );
    }
    return rval;
}


TSS2_RC Tss2_Sys_SetEncryptParam(
	TSS2_SYS_CONTEXT 		*sysContext,
	size_t                  encryptParamSize,
	const uint8_t			*encryptParamBuffer
)
{
    TSS2_RC         rval = TSS2_RC_SUCCESS;
	size_t          currEncryptParamSize;
    uint8_t         *currEncryptParamBuffer;

    if( encryptParamBuffer == 0 || sysContext == 0 )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else
    {
        rval = Tss2_Sys_GetEncryptParam(sysContext,
                                    &currEncryptParamSize,
                                    (const uint8_t **)&currEncryptParamBuffer);

        if( rval == TSS2_RC_SUCCESS )
        {
            if( encryptParamSize != currEncryptParamSize )
            {
                return TSS2_SYS_RC_BAD_SIZE;
            }
            else
            {
                if (currEncryptParamBuffer + encryptParamSize >
                        SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->maxCommandSize)
                    return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

                memmove(currEncryptParamBuffer, encryptParamBuffer, encryptParamSize);
            }
        }
    }

    return rval;
}
