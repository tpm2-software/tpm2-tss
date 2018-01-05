/***********************************************************************;
 * Copyright (c) 2017, Intel Corporation
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

TSS2_RC Tss2_Sys_AC_GetCapability_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_AC ac,
    TPM_AT capability,
    UINT32 count)
{
    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    CommonPreparePrologue(sysContext, TPM_CC_AC_GetCapability);

    Marshal_UINT32(SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize,
                   &SYS_CONTEXT->nextData, ac, &SYS_CONTEXT->rval);

    Marshal_UINT32(SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize,
                   &SYS_CONTEXT->nextData, capability, &SYS_CONTEXT->rval);

    Marshal_UINT32(SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize,
                   &SYS_CONTEXT->nextData, count, &SYS_CONTEXT->rval);

    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    CommonPrepareEpilogue(sysContext);

    return SYS_CONTEXT->rval;
}

TSS2_RC Tss2_Sys_AC_GetCapability_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO *moreData,
    TPML_AC_CAPABILITIES *capabilityData)
{
    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    CommonComplete(sysContext);

    Unmarshal_UINT8(SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize,
                    &SYS_CONTEXT->nextData, moreData, &SYS_CONTEXT->rval);

    Unmarshal_TPML_AC_CAPABILITIES(sysContext, capabilityData);

    return SYS_CONTEXT->rval;
}

TSS2_RC Tss2_Sys_AC_GetCapability(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_RH_AC ac,
    TPM_AT capability,
    UINT32 count,
    TPMI_YES_NO *moreData,
    TPML_AC_CAPABILITIES *capabilityData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if (!moreData || !capabilityData)
		return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_AC_GetCapability_Prepare(sysContext, ac, capability, count);
    if (rval)
        return rval;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_AC_GetCapability_Complete(sysContext, moreData,
                                              capabilityData);
}
