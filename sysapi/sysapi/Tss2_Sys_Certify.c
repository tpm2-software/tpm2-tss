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

TSS2_RC Tss2_Sys_Certify_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT objectHandle,
    TPMI_DH_OBJECT signHandle,
    TPM2B_DATA *qualifyingData,
    TPMT_SIG_SCHEME *inScheme)
{
    TSS2_RC rval;

    if (!sysContext || !inScheme)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM_CC_Certify);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(objectHandle, SYS_CONTEXT->cmdBuffer,
                                  SYS_CONTEXT->maxCmdSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(signHandle, SYS_CONTEXT->cmdBuffer,
                                  SYS_CONTEXT->maxCmdSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    if (!qualifyingData) {
        SYS_CONTEXT->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, SYS_CONTEXT->cmdBuffer,
                                      SYS_CONTEXT->maxCmdSize,
                                      &SYS_CONTEXT->nextData);
    } else {

        rval = Tss2_MU_TPM2B_DATA_Marshal(qualifyingData, SYS_CONTEXT->cmdBuffer,
                                           SYS_CONTEXT->maxCmdSize,
                                           &SYS_CONTEXT->nextData);
    }
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_SIG_SCHEME_Marshal(inScheme, SYS_CONTEXT->cmdBuffer,
                                           SYS_CONTEXT->maxCmdSize,
                                           &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 1;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TSS2_RC Tss2_Sys_Certify_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST *certifyInfo,
    TPMT_SIGNATURE *signature)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(sysContext);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_ATTEST_Unmarshal(SYS_CONTEXT->cmdBuffer,
                                          SYS_CONTEXT->maxCmdSize,
                                          &SYS_CONTEXT->nextData,
                                          certifyInfo);
    if (rval)
        return rval;

    return Tss2_MU_TPMT_SIGNATURE_Unmarshal(SYS_CONTEXT->cmdBuffer,
                                            SYS_CONTEXT->maxCmdSize,
                                            &SYS_CONTEXT->nextData,
                                            signature);
}

TSS2_RC Tss2_Sys_Certify(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT objectHandle,
    TPMI_DH_OBJECT signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_DATA *qualifyingData,
    TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST *certifyInfo,
    TPMT_SIGNATURE *signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if (!inScheme)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_Certify_Prepare(sysContext, objectHandle, signHandle,
                                    qualifyingData, inScheme);
    if (rval)
        return rval;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_Certify_Complete(sysContext, certifyInfo, signature);
}
