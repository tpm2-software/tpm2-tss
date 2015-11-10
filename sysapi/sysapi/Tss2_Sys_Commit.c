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

#include <tpm20.h>   
#include <tss2_sysapi_util.h>   

TPM_RC Tss2_Sys_Commit_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TPM2B_ECC_POINT	*P1,
    TPM2B_SENSITIVE_DATA	*s2,
    TPM2B_ECC_PARAMETER	*y2
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    SYS_CONTEXT->rval = TSS2_RC_SUCCESS;
    
    CommonPreparePrologue( sysContext, TPM_CC_Commit );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), signHandle, &(SYS_CONTEXT->rval) );

    if( P1 == 0 )
	{
		SYS_CONTEXT->decryptNull = 1;
	}
            
    Marshal_TPM2B_ECC_POINT( sysContext, P1 );

    MARSHAL_SIMPLE_TPM2B( sysContext, &( s2->b ) );

    MARSHAL_SIMPLE_TPM2B( sysContext, &( y2->b ) );

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 1;
    SYS_CONTEXT->authAllowed = 1;

    CommonPrepareEpilogue( sysContext );

    return SYS_CONTEXT->rval;
}

TPM_RC Tss2_Sys_Commit_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT	*K,
    TPM2B_ECC_POINT	*L,
    TPM2B_ECC_POINT	*E,
    UINT16	*counter
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    CommonComplete( sysContext );

    Unmarshal_TPM2B_ECC_POINT( sysContext, K );

    Unmarshal_TPM2B_ECC_POINT( sysContext, L );

    Unmarshal_TPM2B_ECC_POINT( sysContext, E );

    Unmarshal_UINT16( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), counter, &(SYS_CONTEXT->rval) );

    return SYS_CONTEXT->rval;
}

TPM_RC Tss2_Sys_Commit(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_ECC_POINT	*P1,
    TPM2B_SENSITIVE_DATA	*s2,
    TPM2B_ECC_PARAMETER	*y2,
    TPM2B_ECC_POINT	*K,
    TPM2B_ECC_POINT	*L,
    TPM2B_ECC_POINT	*E,
    UINT16	*counter,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC     rval = TPM_RC_SUCCESS;

    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    rval = Tss2_Sys_Commit_Prepare( sysContext, signHandle, P1, s2, y2 );
    
    if( rval == TSS2_RC_SUCCESS )
    {
        rval = CommonOneCall( sysContext, cmdAuthsArray, rspAuthsArray );

        if( rval == TSS2_RC_SUCCESS )
        {
            rval = Tss2_Sys_Commit_Complete( sysContext, K, L, E, counter );
        }
    }
    
    return rval;
}

