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

void Unmarshal_TPMU_HA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_HA *ha,
	UINT32 selector
	)
{
	UINT32	i;

	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	if( ha == 0 )
		return;

	switch( selector )
	{
#ifdef TPM_ALG_SHA
	case TPM_ALG_SHA:
		
	for( i = 0; i < SHA_DIGEST_SIZE; i++ )
	{
		Unmarshal_UINT8( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &ha->sha[i], &( SYS_CONTEXT->rval ) );
	}
			break;
#endif
#ifdef TPM_ALG_SHA1
	case TPM_ALG_SHA1:
		
	for( i = 0; i < SHA1_DIGEST_SIZE; i++ )
	{
		Unmarshal_UINT8( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &ha->sha1[i], &( SYS_CONTEXT->rval ) );
	}
			break;
#endif
#ifdef TPM_ALG_SHA256
	case TPM_ALG_SHA256:
		
	for( i = 0; i < SHA256_DIGEST_SIZE; i++ )
	{
		Unmarshal_UINT8( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &ha->sha256[i], &( SYS_CONTEXT->rval ) );
	}
			break;
#endif
#ifdef TPM_ALG_SHA384
	case TPM_ALG_SHA384:
		
	for( i = 0; i < SHA384_DIGEST_SIZE; i++ )
	{
		Unmarshal_UINT8( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &ha->sha384[i], &( SYS_CONTEXT->rval ) );
	}
			break;
#endif
#ifdef TPM_ALG_SHA512
	case TPM_ALG_SHA512:
		
	for( i = 0; i < SHA512_DIGEST_SIZE; i++ )
	{
		Unmarshal_UINT8( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &ha->sha512[i], &( SYS_CONTEXT->rval ) );
	}
			break;
#endif
#ifdef TPM_ALG_SM3_256
	case TPM_ALG_SM3_256:
		
	for( i = 0; i < SM3_256_DIGEST_SIZE; i++ )
	{
		Unmarshal_UINT8( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &ha->sm3_256[i], &( SYS_CONTEXT->rval ) );
	}
			break;
#endif
#ifdef TPM_ALG_NULL
	case TPM_ALG_NULL:
					break;
#endif
	}
	return;
}
