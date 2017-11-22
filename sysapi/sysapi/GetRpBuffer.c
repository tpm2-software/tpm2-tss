//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include "sapi/tpm20.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_GetRpBuffer(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *rpBufferUsedSize,
    const uint8_t **rpBuffer)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !rpBufferUsedSize || !rpBuffer)
        return TSS2_SYS_RC_BAD_REFERENCE;

    /* NOTE: should this depend on the status of previous
     * API call? i.e. ctx->rval != TSS2_RC_SUCCESS */
    if (ctx->previousStage != CMD_STAGE_RECEIVE_RESPONSE ||
        ctx->rval != TSS2_RC_SUCCESS)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    /* Calculate the position of the response parameter section within the TPM
     * repsponse as well as its size. Structure is:
     * Header (tag, responseSize, responseCode)
     * handle(if Command has handles)
     * parameterSize (if TPM_ST_SESSIONS), size of rpArea
     * rpArea
     * Sessions (if TPM_ST_SESSIONS) */
    size_t offset = sizeof(TPM20_Header_Out); /* Skip over the header */
    offset += ctx->numResponseHandles * sizeof(TPM2_HANDLE); /* Skip handle */

    if (ctx->rsp_header.tag == TPM2_ST_SESSIONS) {
        /* If sessions are used a parameterSize values exists for convenience */
        TPM2_PARAMETER_SIZE parameterSize;
        rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                ctx->rsp_header.responseSize, &offset, &parameterSize);
        if (rval != TSS2_RC_SUCCESS) {
            return rval;
        }
        *rpBuffer = ctx->cmdBuffer + offset;
        *rpBufferUsedSize = parameterSize;
    } else {
        /* If no session is used the remainder is the rpArea */
        *rpBuffer = ctx->cmdBuffer + offset;
        *rpBufferUsedSize = ctx->rsp_header.responseSize - offset;
    }

    return TSS2_RC_SUCCESS;
}
