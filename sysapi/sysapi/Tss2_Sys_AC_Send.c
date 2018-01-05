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

TSS2_RC Tss2_Sys_AC_Send_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT sendObject,
    TPMI_RH_NV_AUTH authHandle,
    TPMI_RH_AC ac,
    TPM2B_MAX_BUFFER *acDataIn)
{
    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    CommonPreparePrologue(sysContext, TPM_CC_AC_Send);

    Marshal_UINT32(SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize,
                   &SYS_CONTEXT->nextData, sendObject, &SYS_CONTEXT->rval);

    Marshal_UINT32(SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize,
                   &SYS_CONTEXT->nextData, authHandle, &SYS_CONTEXT->rval);

    Marshal_UINT32(SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize,
                   &SYS_CONTEXT->nextData, ac, &SYS_CONTEXT->rval);

    if (!acDataIn)
        SYS_CONTEXT->decryptNull = 1;

    MARSHAL_SIMPLE_TPM2B(sysContext, (TPM2B *)acDataIn);

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    CommonPrepareEpilogue(sysContext);

    return SYS_CONTEXT->rval;
}

TSS2_RC Tss2_Sys_AC_Send_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_AC_OUTPUT *acDataOut)
{
    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    CommonComplete(sysContext);

    Unmarshal_TPMS_AC_OUTPUT(sysContext, acDataOut);

    return SYS_CONTEXT->rval;
}

TSS2_RC Tss2_Sys_AC_Send(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_DH_OBJECT sendObject,
    TPMI_RH_NV_AUTH authHandle,
    TPMI_RH_AC ac,
    TPM2B_MAX_BUFFER *acDataIn,
    TPMS_AC_OUTPUT *acDataOut,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if (!acDataOut)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_AC_Send_Prepare(sysContext, sendObject, authHandle, ac,
                                    acDataIn);
    if (rval)
        return rval;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_AC_Send_Complete(sysContext, acDataOut);
}
