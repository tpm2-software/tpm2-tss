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

void Marshal_TPMU_PUBLIC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_PUBLIC_PARMS *publicVarParms,
	UINT32 selector
	)
{
	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	switch( selector )
	{
#ifdef TPM_ALG_KEYEDHASH
	case TPM_ALG_KEYEDHASH:
			Marshal_TPMS_KEYEDHASH_PARMS( sysContext, &publicVarParms->keyedHashDetail );
			break;
#endif
#ifdef TPM_ALG_SYMCIPHER
	case TPM_ALG_SYMCIPHER:
			Marshal_TPMS_SYMCIPHER_PARMS( sysContext, &publicVarParms->symDetail );
			break;
#endif
#ifdef TPM_ALG_RSA
	case TPM_ALG_RSA:
			Marshal_TPMS_RSA_PARMS( sysContext, &publicVarParms->rsaDetail );
			break;
#endif
#ifdef TPM_ALG_ECC
	case TPM_ALG_ECC:
			Marshal_TPMS_ECC_PARMS( sysContext, &publicVarParms->eccDetail );
			break;
#endif
	}
	return;
}
