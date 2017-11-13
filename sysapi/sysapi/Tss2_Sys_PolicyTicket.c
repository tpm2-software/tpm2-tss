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

TSS2_RC Tss2_Sys_PolicyTicket_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY policySession,
    TPM2B_TIMEOUT *timeout,
    TPM2B_DIGEST *cpHashA,
    TPM2B_NONCE *policyRef,
    TPM2B_NAME *authName,
    TPMT_TK_AUTH *ticket)
{
    TSS2_RC rval;

    if (!sysContext || !ticket)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM_CC_PolicyTicket);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(policySession, SYS_CONTEXT->cmdBuffer,
                                  SYS_CONTEXT->maxCmdSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    if (!timeout) {
        SYS_CONTEXT->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, SYS_CONTEXT->cmdBuffer,
                                      SYS_CONTEXT->maxCmdSize,
                                      &SYS_CONTEXT->nextData);
    } else {

        rval = Tss2_MU_TPM2B_TIMEOUT_Marshal(timeout, SYS_CONTEXT->cmdBuffer,
                                             SYS_CONTEXT->maxCmdSize,
                                             &SYS_CONTEXT->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DIGEST_Marshal(cpHashA, SYS_CONTEXT->cmdBuffer,
                                        SYS_CONTEXT->maxCmdSize,
                                        &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NONCE_Marshal(policyRef, SYS_CONTEXT->cmdBuffer,
                                       SYS_CONTEXT->maxCmdSize,
                                       &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Marshal(authName, SYS_CONTEXT->cmdBuffer,
                                      SYS_CONTEXT->maxCmdSize,
                                      &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_TK_AUTH_Marshal(ticket, SYS_CONTEXT->cmdBuffer,
                                        SYS_CONTEXT->maxCmdSize,
                                        &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 1;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TSS2_RC Tss2_Sys_PolicyTicket(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_TIMEOUT *timeout,
    TPM2B_DIGEST *cpHashA,
    TPM2B_NONCE *policyRef,
    TPM2B_NAME *authName,
    TPMT_TK_AUTH *ticket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if (!ticket)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PolicyTicket_Prepare(sysContext, policySession, timeout,
                                         cpHashA, policyRef, authName, ticket);
    if (rval)
        return rval;

    return CommonOneCallForNoResponseCmds(sysContext, cmdAuthsArray, rspAuthsArray);
}
