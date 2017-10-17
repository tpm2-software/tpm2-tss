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

TPM_RC Tss2_Sys_PolicyAuthorize_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY policySession,
    TPM2B_DIGEST *approvedPolicy,
    TPM2B_NONCE *policyRef,
    TPM2B_NAME *keySign,
    TPMT_TK_VERIFIED *checkTicket)
{
    TSS2_RC rval;

    if (!sysContext || !checkTicket)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM_CC_PolicyAuthorize);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(policySession, SYS_CONTEXT->tpmInBuffPtr,
                                  SYS_CONTEXT->maxCommandSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    if (!approvedPolicy) {
        SYS_CONTEXT->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, SYS_CONTEXT->tpmInBuffPtr,
                                      SYS_CONTEXT->maxCommandSize,
                                      &SYS_CONTEXT->nextData);
    } else {

        rval = Tss2_MU_TPM2B_DIGEST_Marshal(approvedPolicy, SYS_CONTEXT->tpmInBuffPtr,
                                            SYS_CONTEXT->maxCommandSize,
                                            &SYS_CONTEXT->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NONCE_Marshal(policyRef, SYS_CONTEXT->tpmInBuffPtr,
                                       SYS_CONTEXT->maxCommandSize,
                                       &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Marshal(keySign, SYS_CONTEXT->tpmInBuffPtr,
                                      SYS_CONTEXT->maxCommandSize,
                                      &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_TK_VERIFIED_Marshal(checkTicket, SYS_CONTEXT->tpmInBuffPtr,
                                            SYS_CONTEXT->maxCommandSize,
                                            &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TPM_RC Tss2_Sys_PolicyAuthorize(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_DIGEST *approvedPolicy,
    TPM2B_NONCE *policyRef,
    TPM2B_NAME *keySign,
    TPMT_TK_VERIFIED *checkTicket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if (!checkTicket)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PolicyAuthorize_Prepare(sysContext, policySession,
                                            approvedPolicy, policyRef,
                                            keySign, checkTicket);
    if (rval)
        return rval;

    return CommonOneCallForNoResponseCmds(sysContext, cmdAuthsArray, rspAuthsArray);
}
