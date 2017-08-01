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

void Marshal_TPMU_SIGNATURE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SIGNATURE *signature,
	UINT32 selector
	)
{
	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	switch( selector )
	{
	case TPM_ALG_RSASSA:
			Marshal_TPMS_SIGNATURE_RSASSA( sysContext, &signature->rsassa );
			break;
	case TPM_ALG_RSAPSS:
			Marshal_TPMS_SIGNATURE_RSAPSS( sysContext, &signature->rsapss );
			break;
	case TPM_ALG_ECDSA:
			Marshal_TPMS_SIGNATURE_ECDSA( sysContext, &signature->ecdsa );
			break;
	case TPM_ALG_ECDAA:
			Marshal_TPMS_SIGNATURE_ECDAA( sysContext, &signature->ecdaa );
			break;
	case TPM_ALG_SM2:
			Marshal_TPMS_SIGNATURE_SM2( sysContext, &signature->sm2 );
			break;
	case TPM_ALG_ECSCHNORR:
			Marshal_TPMS_SIGNATURE_ECSCHNORR( sysContext, &signature->ecschnorr );
			break;
	case TPM_ALG_HMAC:
			Marshal_TPMT_HA( sysContext, &signature->hmac );
			break;
	case TPM_ALG_NULL:
					break;
	}
	return;
}
