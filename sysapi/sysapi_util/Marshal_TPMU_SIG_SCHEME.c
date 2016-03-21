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

#include <tss2/tpm20.h>
#include "sysapi_util.h"

void Marshal_TPMU_SIG_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SIG_SCHEME *sigScheme,
	UINT32 selector
	)
{
	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	switch( selector )
	{
#ifdef TPM_ALG_RSASSA
	case TPM_ALG_RSASSA:
			Marshal_TPMS_SIG_SCHEME_RSASSA( sysContext, &sigScheme->rsassa );
			break;
#endif
#ifdef TPM_ALG_RSAPSS
	case TPM_ALG_RSAPSS:
			Marshal_TPMS_SIG_SCHEME_RSAPSS( sysContext, &sigScheme->rsapss );
			break;
#endif
#ifdef TPM_ALG_ECDSA
	case TPM_ALG_ECDSA:
			Marshal_TPMS_SIG_SCHEME_ECDSA( sysContext, &sigScheme->ecdsa );
			break;
#endif
#ifdef TPM_ALG_ECDAA
	case TPM_ALG_ECDAA:
			Marshal_TPMS_SIG_SCHEME_ECDAA( sysContext, &sigScheme->ecdaa );
			break;
#endif
#ifdef TPM_ALG_SM2
	case TPM_ALG_SM2:
			Marshal_TPMS_SIG_SCHEME_SM2( sysContext, &sigScheme->sm2 );
			break;
#endif
#ifdef TPM_ALG_ECSCHNORR
	case TPM_ALG_ECSCHNORR:
			Marshal_TPMS_SIG_SCHEME_ECSCHNORR( sysContext, &sigScheme->ecschnorr );
			break;
#endif
#ifdef TPM_ALG_HMAC
	case TPM_ALG_HMAC:
			Marshal_TPMS_SCHEME_HMAC( sysContext, &sigScheme->hmac );
			break;
#endif
#ifdef TPM_ALG_NULL
	case TPM_ALG_NULL:
					break;
#endif
	}
	return;
}
