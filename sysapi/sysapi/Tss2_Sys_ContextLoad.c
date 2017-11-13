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

TSS2_RC Tss2_Sys_ContextLoad_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT	*context)
{
    TSS2_RC rval;

    if (!sysContext || !context)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM2_CC_ContextLoad);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMS_CONTEXT_Marshal(context, SYS_CONTEXT->cmdBuffer,
                                        SYS_CONTEXT->maxCmdSize,
                                        &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 0;

    return CommonPrepareEpilogue(sysContext);
}

TSS2_RC Tss2_Sys_ContextLoad_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT *loadedHandle)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_MU_UINT32_Unmarshal(SYS_CONTEXT->cmdBuffer,
                                    SYS_CONTEXT->maxCmdSize,
                                    &SYS_CONTEXT->nextData,
                                    loadedHandle);
    if (rval)
        return rval;

    return CommonComplete(sysContext);
}

TSS2_RC Tss2_Sys_ContextLoad(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT	*context,
    TPMI_DH_CONTEXT *loadedHandle)
{
    TSS2_RC rval;

    if (!context)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_ContextLoad_Prepare(sysContext, context);
    if (rval)
        return rval;

    rval = CommonOneCall(sysContext, 0, 0);
    if (rval)
        return rval;

    return Tss2_Sys_ContextLoad_Complete(sysContext, loadedHandle);
}
