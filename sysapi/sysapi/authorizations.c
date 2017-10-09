/***********************************************************************
 * Copyright (c) 2015 - 2017, Intel Corporation
 *
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

#include "tss2_endian.h"
#include "sapi/tpm20.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_SetCmdAuths(
    TSS2_SYS_CONTEXT *sysContext,
    const TSS2_SYS_CMD_AUTHS *cmdAuthsArray)
{
    uint8_t i;
    UINT32 authSize = 0;
    UINT32 newCmdSize = 0;
    size_t authOffset;
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if (!sysContext || !cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (cmdAuthsArray->cmdAuthsCount > MAX_SESSION_NUM)
        return TSS2_SYS_RC_BAD_VALUE;

    if (SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (!SYS_CONTEXT->authAllowed)
        return rval;

    SYS_CONTEXT->rval = TSS2_RC_SUCCESS;
    SYS_CONTEXT->authsCount = 0;

    if (!cmdAuthsArray->cmdAuthsCount)
        return rval;

    ((TPM20_Header_In *)SYS_CONTEXT->tpmInBuffPtr)->tag = HOST_TO_BE_16(TPM_ST_SESSIONS);

    /* Calculate size needed for authorization area, check for any null
     * pointers, and check for decrypt/encrypt sessions. */
    for (i = 0; i < cmdAuthsArray->cmdAuthsCount; i++) {

        if (!cmdAuthsArray->cmdAuths[i])
            return TSS2_SYS_RC_BAD_VALUE;

        authSize += sizeof(TPMI_SH_AUTH_SESSION);
        authSize += sizeof(UINT16) + cmdAuthsArray->cmdAuths[i]->nonce.t.size;
        authSize += sizeof(UINT8);
        authSize += sizeof(UINT16) + cmdAuthsArray->cmdAuths[i]->hmac.t.size;

        if (cmdAuthsArray->cmdAuths[i]->sessionAttributes.decrypt)
            SYS_CONTEXT->decryptSession = 1;

        if (cmdAuthsArray->cmdAuths[i]->sessionAttributes.encrypt)
            SYS_CONTEXT->encryptSession = 1;
    }

    newCmdSize = authSize;
    newCmdSize += sizeof(UINT32); /* authorization size field */
    newCmdSize += BE_TO_HOST_32(((TPM20_Header_In *)SYS_CONTEXT->tpmInBuffPtr)->commandSize);

    if (newCmdSize > SYS_CONTEXT->maxCommandSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    if (SYS_CONTEXT->cpBufferUsedSize > SYS_CONTEXT->maxCommandSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    /* We're going to have to move stuff around.
     * First move current cpBuffer down by the auth area size. */
    memmove(SYS_CONTEXT->cpBuffer + authSize + sizeof(UINT32),
            SYS_CONTEXT->cpBuffer, SYS_CONTEXT->cpBufferUsedSize);

    /* Reset the auth size field */
    *(UINT32 *)SYS_CONTEXT->cpBuffer = 0;

    /* Now copy in the authorization area. */
    authOffset = SYS_CONTEXT->cpBuffer - SYS_CONTEXT->tpmInBuffPtr;
    rval = UINT32_Marshal(authSize, SYS_CONTEXT->tpmInBuffPtr,
                          newCmdSize, &authOffset);
    if (rval)
        return rval;

    for (i = 0; i < cmdAuthsArray->cmdAuthsCount; i++) {
        rval = TPMS_AUTH_COMMAND_Marshal(cmdAuthsArray->cmdAuths[i],
                                         SYS_CONTEXT->tpmInBuffPtr, newCmdSize,
                                         &authOffset);
        if (rval)
            break;
    }

    SYS_CONTEXT->cpBuffer += authSize + sizeof(UINT32);

    /* Now update the command size. */
    ((TPM20_Header_In *)SYS_CONTEXT->tpmInBuffPtr)->commandSize = HOST_TO_BE_32(newCmdSize);
    SYS_CONTEXT->authsCount = cmdAuthsArray->cmdAuthsCount;
    return rval;
}

TSS2_RC Tss2_Sys_GetRspAuths(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    size_t offset = 0, offset_tmp;
    int i = 0;

    if (!sysContext || !rspAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE ||
        SYS_CONTEXT->rsp_header.responseCode != TPM_RC_SUCCESS ||
        SYS_CONTEXT->authAllowed == 0)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (rspAuthsArray->rspAuthsCount == 0)
        return TSS2_SYS_RC_BAD_VALUE;

    if (rspAuthsArray->rspAuthsCount != SYS_CONTEXT->authsCount)
        return TSS2_SYS_RC_INVALID_SESSIONS;

    if (TPM_ST_SESSIONS != SYS_CONTEXT->rsp_header.tag)
        return rval;

    offset += sizeof(TPM20_Header_Out);
    offset += SYS_CONTEXT->numResponseHandles * sizeof(TPM_HANDLE);
    offset += BE_TO_HOST_32(*SYS_CONTEXT->rspParamsSize);
    offset += sizeof(UINT32);
    offset_tmp = offset;

    /* Validate the auth area before copying it */
    for (i = 0; i < rspAuthsArray->rspAuthsCount; i++) {

        if (offset_tmp > SYS_CONTEXT->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        offset_tmp += sizeof(UINT16) +
            BE_TO_HOST_16(*(UINT16 *)(SYS_CONTEXT->tpmOutBuffPtr + offset_tmp));

        if (offset_tmp > SYS_CONTEXT->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        offset_tmp += 1;

        if (offset_tmp > SYS_CONTEXT->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        offset_tmp += sizeof(UINT16) +
            BE_TO_HOST_16(*(UINT16 *)(SYS_CONTEXT->tpmOutBuffPtr + offset_tmp));

        if (offset_tmp > SYS_CONTEXT->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        if (i + 1 > rspAuthsArray->rspAuthsCount)
            return TSS2_SYS_RC_INVALID_SESSIONS;
    }

    /* Unmarshal the auth area */
    for (i = 0; i < rspAuthsArray->rspAuthsCount; i++) {
        rval = TPMS_AUTH_RESPONSE_Unmarshal(SYS_CONTEXT->tpmOutBuffPtr,
                                            SYS_CONTEXT->maxCommandSize,
                                            &offset, rspAuthsArray->rspAuths[i]);
        if (rval)
            break;
    }

    return rval;
}
