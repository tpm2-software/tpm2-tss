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

void Unmarshal_TPML_ALG(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_ALG *alg
	)
{
	UINT32	i;

	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	if( alg == 0 )
		return;

	Unmarshal_UINT32( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &alg->count, &( SYS_CONTEXT->rval ) );

	for( i = 0; i < alg->count; i++ )
	{
		Unmarshal_UINT16( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &alg->algorithms[i], &( SYS_CONTEXT->rval ) );
	}

	return;
}
