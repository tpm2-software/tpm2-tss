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

TPM_RC Tss2_Sys_SetCommandCodeAuditStatus_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TPMI_ALG_HASH	auditAlg,
    TPML_CC	*setList,
    TPML_CC	*clearList
    )
{
    if( sysContext == NULL )
    {
        return( TSS2_SYS_RC_BAD_REFERENCE );
    }

    if( setList == NULL  || clearList == NULL  )
	{
		return TSS2_SYS_RC_BAD_REFERENCE;
	}

    CommonPreparePrologue( sysContext, TPM_CC_SetCommandCodeAuditStatus );

    Marshal_UINT32( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), auth, &(SYS_CONTEXT->rval) );



    Marshal_UINT16( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &(SYS_CONTEXT->nextData), auditAlg, &(SYS_CONTEXT->rval) );

    Marshal_TPML_CC( sysContext, setList );

    Marshal_TPML_CC( sysContext, clearList );

    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    CommonPrepareEpilogue( sysContext );

    return SYS_CONTEXT->rval;
}


TPM_RC Tss2_Sys_SetCommandCodeAuditStatus(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_ALG_HASH	auditAlg,
    TPML_CC	*setList,
    TPML_CC	*clearList,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC     rval = TPM_RC_SUCCESS;

    if( setList == NULL  || clearList == NULL  )
	{
		return TSS2_SYS_RC_BAD_REFERENCE;
	}

    rval = Tss2_Sys_SetCommandCodeAuditStatus_Prepare( sysContext, auth, auditAlg, setList, clearList );

    if( rval == TSS2_RC_SUCCESS )
    {
        rval = CommonOneCallForNoResponseCmds( sysContext, cmdAuthsArray, rspAuthsArray );
    }

    return rval;
}

