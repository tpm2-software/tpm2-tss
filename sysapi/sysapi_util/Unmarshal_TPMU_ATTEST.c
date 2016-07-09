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

void Unmarshal_TPMU_ATTEST(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_ATTEST *attest,
	UINT32 selector
	)
{
	if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
		return;

	if( attest == 0 )
		return;

	switch( selector )
	{
#ifdef TPM_ST_ATTEST_CERTIFY
	case TPM_ST_ATTEST_CERTIFY:
			Unmarshal_TPMS_CERTIFY_INFO( sysContext, &attest->certify );
			break;
#endif
#ifdef TPM_ST_ATTEST_CREATION
	case TPM_ST_ATTEST_CREATION:
			Unmarshal_TPMS_CREATION_INFO( sysContext, &attest->creation );
			break;
#endif
#ifdef TPM_ST_ATTEST_QUOTE
	case TPM_ST_ATTEST_QUOTE:
			Unmarshal_TPMS_QUOTE_INFO( sysContext, &attest->quote );
			break;
#endif
#ifdef TPM_ST_ATTEST_COMMAND_AUDIT
	case TPM_ST_ATTEST_COMMAND_AUDIT:
			Unmarshal_TPMS_COMMAND_AUDIT_INFO( sysContext, &attest->commandAudit );
			break;
#endif
#ifdef TPM_ST_ATTEST_SESSION_AUDIT
	case TPM_ST_ATTEST_SESSION_AUDIT:
			Unmarshal_TPMS_SESSION_AUDIT_INFO( sysContext, &attest->sessionAudit );
			break;
#endif
#ifdef TPM_ST_ATTEST_TIME
	case TPM_ST_ATTEST_TIME:
			Unmarshal_TPMS_TIME_ATTEST_INFO( sysContext, &attest->time );
			break;
#endif
#ifdef TPM_ST_ATTEST_NV
	case TPM_ST_ATTEST_NV:
			Unmarshal_TPMS_NV_CERTIFY_INFO( sysContext, &attest->nv );
			break;
#endif
	}
	return;
}
