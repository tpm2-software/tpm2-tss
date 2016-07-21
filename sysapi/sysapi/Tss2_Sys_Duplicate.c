/***********************************************************************;
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
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
 ***********************************************************************/

#include <sapi/tpm20.h>
#include "sysapi_util.h"

TPM_RC Tss2_Sys_Duplicate_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	newParentHandle,
    TPM2B_DATA	*encryptionKeyIn,
    TPMT_SYM_DEF_OBJECT	*symmetricAlg
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    if( symmetricAlg == NULL  )
	{
		return TSS2_SYS_RC_BAD_REFERENCE;
	}

    CommonPreparePrologue( sysContext, TPM_CC_Duplicate );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), objectHandle, &(SYS_CONTEXT->rval) );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), newParentHandle, &(SYS_CONTEXT->rval) );

    if( encryptionKeyIn == 0 )
	{
		SYS_CONTEXT->decryptNull = 1;
	}

    MARSHAL_SIMPLE_TPM2B( sysContext, &( encryptionKeyIn->b ) );

    Marshal_TPMT_SYM_DEF_OBJECT( sysContext, symmetricAlg );

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 1;
    SYS_CONTEXT->authAllowed = 1;

    CommonPrepareEpilogue( sysContext );

    return SYS_CONTEXT->rval;
}

TPM_RC Tss2_Sys_Duplicate_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DATA	*encryptionKeyOut,
    TPM2B_PRIVATE	*duplicate,
    TPM2B_ENCRYPTED_SECRET	*outSymSeed
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    CommonComplete( sysContext );

    UNMARSHAL_SIMPLE_TPM2B( sysContext, &( encryptionKeyOut->b ) );

    UNMARSHAL_SIMPLE_TPM2B( sysContext, &( duplicate->b ) );

    UNMARSHAL_SIMPLE_TPM2B( sysContext, &( outSymSeed->b ) );

    return SYS_CONTEXT->rval;
}

TPM_RC Tss2_Sys_Duplicate(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	newParentHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_DATA	*encryptionKeyIn,
    TPMT_SYM_DEF_OBJECT	*symmetricAlg,
    TPM2B_DATA	*encryptionKeyOut,
    TPM2B_PRIVATE	*duplicate,
    TPM2B_ENCRYPTED_SECRET	*outSymSeed,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC     rval = TPM_RC_SUCCESS;

    if( symmetricAlg == NULL  )
	{
		return TSS2_SYS_RC_BAD_REFERENCE;
	}

    rval = Tss2_Sys_Duplicate_Prepare( sysContext, objectHandle, newParentHandle, encryptionKeyIn, symmetricAlg );

    if( rval == TSS2_RC_SUCCESS )
    {
        rval = CommonOneCall( sysContext, cmdAuthsArray, rspAuthsArray );

        if( rval == TSS2_RC_SUCCESS )
        {
            rval = Tss2_Sys_Duplicate_Complete( sysContext, encryptionKeyOut, duplicate, outSymSeed );
        }
    }

    return rval;
}

