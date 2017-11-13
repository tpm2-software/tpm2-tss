/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
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

TSS2_RC Tss2_Sys_PCR_SetAuthValue_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR pcrHandle,
    const TPM2B_DIGEST	*auth)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM2_CC_PCR_SetAuthValue);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(pcrHandle, SYS_CONTEXT->cmdBuffer,
                                  SYS_CONTEXT->maxCmdSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DIGEST_Marshal(auth, SYS_CONTEXT->cmdBuffer,
                                        SYS_CONTEXT->maxCmdSize,
                                        &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TSS2_RC Tss2_Sys_PCR_SetAuthValue(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR pcrHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*auth,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    rval = Tss2_Sys_PCR_SetAuthValue_Prepare(sysContext, pcrHandle, auth);
    if (rval)
        return rval;

    return CommonOneCallForNoResponseCmds(sysContext, cmdAuthsArray, rspAuthsArray);
}
