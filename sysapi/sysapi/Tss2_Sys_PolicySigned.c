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

#include "sapi/tpm20.h"
#include "sysapi_util.h"

TPM_RC Tss2_Sys_PolicySigned_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	authObject,
    TPMI_SH_POLICY	policySession,
    TPM2B_NONCE	*nonceTPM,
    TPM2B_DIGEST	*cpHashA,
    TPM2B_NONCE	*policyRef,
    INT32	expiration,
    TPMT_SIGNATURE	*auth
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    if( auth == NULL  )
	{
		return TSS2_SYS_RC_BAD_REFERENCE;
	}

    CommonPreparePrologue( sysContext, TPM_CC_PolicySigned );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), authObject, &(SYS_CONTEXT->rval) );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), policySession, &(SYS_CONTEXT->rval) );

    if( nonceTPM == 0 )
	{
		SYS_CONTEXT->decryptNull = 1;
	}

    MARSHAL_SIMPLE_TPM2B( sysContext, &( nonceTPM->b ) );

    MARSHAL_SIMPLE_TPM2B( sysContext, &( cpHashA->b ) );

    MARSHAL_SIMPLE_TPM2B( sysContext, &( policyRef->b ) );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), expiration, &(SYS_CONTEXT->rval) );

    Marshal_TPMT_SIGNATURE( sysContext, auth );

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 1;
    SYS_CONTEXT->authAllowed = 1;

    CommonPrepareEpilogue( sysContext );

    return SYS_CONTEXT->rval;
}

TPM_RC Tss2_Sys_PolicySigned_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_TIMEOUT	*timeout,
    TPMT_TK_AUTH	*policyTicket
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    CommonComplete( sysContext );

    UNMARSHAL_SIMPLE_TPM2B( sysContext, &( timeout->b ) );

    Unmarshal_TPMT_TK_AUTH( sysContext, policyTicket );

    return SYS_CONTEXT->rval;
}

TPM_RC Tss2_Sys_PolicySigned(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	authObject,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_NONCE	*nonceTPM,
    TPM2B_DIGEST	*cpHashA,
    TPM2B_NONCE	*policyRef,
    INT32	expiration,
    TPMT_SIGNATURE	*auth,
    TPM2B_TIMEOUT	*timeout,
    TPMT_TK_AUTH	*policyTicket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC     rval = TPM_RC_SUCCESS;

    if( auth == NULL  )
	{
		return TSS2_SYS_RC_BAD_REFERENCE;
	}

    rval = Tss2_Sys_PolicySigned_Prepare( sysContext, authObject, policySession, nonceTPM, cpHashA, policyRef, expiration, auth );

    if( rval == TSS2_RC_SUCCESS )
    {
        rval = CommonOneCall( sysContext, cmdAuthsArray, rspAuthsArray );

        if( rval == TSS2_RC_SUCCESS )
        {
            rval = Tss2_Sys_PolicySigned_Complete( sysContext, timeout, policyTicket );
        }
    }

    return rval;
}

