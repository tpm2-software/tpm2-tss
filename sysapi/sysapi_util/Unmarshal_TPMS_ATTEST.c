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

void Unmarshal_TPMS_ATTEST(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ATTEST *attest
	)
{
	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	if( attest == 0 )
		return;

	Unmarshal_UINT32( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &attest->magic, &( SYS_CONTEXT->rval ) );
	Unmarshal_UINT16( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &attest->type, &( SYS_CONTEXT->rval ) );
	UNMARSHAL_SIMPLE_TPM2B_NO_SIZE_CHECK( sysContext, (TPM2B *)&attest->qualifiedSigner );
	UNMARSHAL_SIMPLE_TPM2B_NO_SIZE_CHECK( sysContext, (TPM2B *)&attest->extraData );
	Unmarshal_TPMS_CLOCK_INFO( sysContext, &attest->clockInfo );
	Unmarshal_UINT64( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &(SYS_CONTEXT->nextData), &attest->firmwareVersion, &( SYS_CONTEXT->rval ) );
	Unmarshal_TPMU_ATTEST( sysContext, &attest->attested, attest->type );

	return;
}
