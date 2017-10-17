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

TPM_RC Tss2_Sys_Rewrap_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT oldParent,
    TPMI_DH_OBJECT newParent,
    TPM2B_PRIVATE *inDuplicate,
    TPM2B_NAME *name,
    TPM2B_ENCRYPTED_SECRET *inSymSeed)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM_CC_Rewrap);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(oldParent, SYS_CONTEXT->tpmInBuffPtr,
                                  SYS_CONTEXT->maxCommandSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(newParent, SYS_CONTEXT->tpmInBuffPtr,
                                  SYS_CONTEXT->maxCommandSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    if (!inDuplicate) {
        SYS_CONTEXT->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, SYS_CONTEXT->tpmInBuffPtr,
                                      SYS_CONTEXT->maxCommandSize,
                                      &SYS_CONTEXT->nextData);
    } else {

        rval = Tss2_MU_TPM2B_PRIVATE_Marshal(inDuplicate, SYS_CONTEXT->tpmInBuffPtr,
                                             SYS_CONTEXT->maxCommandSize,
                                             &SYS_CONTEXT->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Marshal(name, SYS_CONTEXT->tpmInBuffPtr,
                                      SYS_CONTEXT->maxCommandSize,
                                      &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(inSymSeed,
                                                  SYS_CONTEXT->tpmInBuffPtr,
                                                  SYS_CONTEXT->maxCommandSize,
                                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 1;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TPM_RC Tss2_Sys_Rewrap_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PRIVATE *outDuplicate,
    TPM2B_ENCRYPTED_SECRET *outSymSeed)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(sysContext);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal(SYS_CONTEXT->tpmInBuffPtr,
                                           SYS_CONTEXT->maxCommandSize,
                                           &SYS_CONTEXT->nextData, outDuplicate);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(SYS_CONTEXT->tpmInBuffPtr,
                                                    SYS_CONTEXT->maxCommandSize,
                                                    &SYS_CONTEXT->nextData,
                                                    outSymSeed);
}

TPM_RC Tss2_Sys_Rewrap(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT oldParent,
    TPMI_DH_OBJECT newParent,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_PRIVATE *inDuplicate,
    TPM2B_NAME *name,
    TPM2B_ENCRYPTED_SECRET *inSymSeed,
    TPM2B_PRIVATE *outDuplicate,
    TPM2B_ENCRYPTED_SECRET *outSymSeed,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    rval = Tss2_Sys_Rewrap_Prepare(sysContext, oldParent, newParent, inDuplicate, name, inSymSeed);
    if (rval)
        return rval;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_Rewrap_Complete(sysContext, outDuplicate, outSymSeed);
}
