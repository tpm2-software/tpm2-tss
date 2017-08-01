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

void Unmarshal_TPMU_KDF_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_KDF_SCHEME *kdfScheme,
	UINT32 selector
	)
{
	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	if( kdfScheme == 0 )
		return;

	switch( selector )
	{
	case TPM_ALG_MGF1:
			Unmarshal_TPMS_SCHEME_MGF1( sysContext, &kdfScheme->mgf1 );
			break;
	case TPM_ALG_KDF1_SP800_56A:
			Unmarshal_TPMS_SCHEME_KDF1_SP800_56A( sysContext, &kdfScheme->kdf1_sp800_56a );
			break;
	case TPM_ALG_KDF2:
			Unmarshal_TPMS_SCHEME_KDF2( sysContext, &kdfScheme->kdf2 );
			break;
	case TPM_ALG_KDF1_SP800_108:
			Unmarshal_TPMS_SCHEME_KDF1_SP800_108( sysContext, &kdfScheme->kdf1_sp800_108 );
			break;
	case TPM_ALG_NULL:
					break;
	}
	return;
}
