/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#include <inttypes.h>

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"
#include "util/tss2_endian.h"
#define LOGMODULE sys
#include "util/log.h"

TSS2_RC Tss2_Sys_ExecuteAsync(TSS2_SYS_CONTEXT *sysContext)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    rval = Tss2_Tcti_Transmit(ctx->tctiContext,
                              HOST_TO_BE_32(req_header_from_cxt(ctx)->commandSize),
                              ctx->cmdBuffer);
    if (rval)
        return rval;

    ctx->previousStage = CMD_STAGE_SEND_COMMAND;

    return rval;
}

TSS2_RC Tss2_Sys_ExecuteFinish(TSS2_SYS_CONTEXT *sysContext, int32_t timeout)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;
    size_t responseSize = 0;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_SEND_COMMAND)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    /*
     * First call receive with NULL as the response buffer to
     * get the size of the response
     */
    rval = Tss2_Tcti_Receive(ctx->tctiContext, &responseSize,
                             NULL, timeout);
    if (rval)
        return rval;

    if (responseSize < sizeof(TPM20_Header_Out)) {
        ctx->previousStage = CMD_STAGE_PREPARE;
        return TSS2_SYS_RC_INSUFFICIENT_RESPONSE;
    }
    if (responseSize > ctx->maxCmdSize) {
        ctx->previousStage = CMD_STAGE_PREPARE;
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
    }

    /*
     * Then call receive again with the response buffer to read the response
     */
    rval = Tss2_Tcti_Receive(ctx->tctiContext, &responseSize,
                             ctx->cmdBuffer, timeout);
    if (rval == TSS2_TCTI_RC_INSUFFICIENT_BUFFER)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    if (rval)
        return rval;

    /*
     * Unmarshal the tag, response size, and response code as soon
     * as possible. Later processing code should get this data from
     * the TPM20_Header_Out in the context structure. No need to
     * unmarshal this stuff again.
     */
    ctx->nextData = 0;

    rval = Tss2_MU_TPM2_ST_Unmarshal(ctx->cmdBuffer,
                                     ctx->maxCmdSize,
                                     &ctx->nextData,
                                     &ctx->rsp_header.tag);
    if (rval) {
        LOG_ERROR("Unmarshaling response tag. RC=%" PRIx32, rval);
        return rval;
    }

    if (ctx->rsp_header.tag != TPM2_ST_SESSIONS &&
        ctx->rsp_header.tag != TPM2_ST_NO_SESSIONS) {
        if (ctx->rsp_header.tag == TPM2_ST_RSP_COMMAND) {
            LOG_ERROR("Unsupported device. The device is a TPM 1.2");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        } else {
            LOG_ERROR("Malformed reponse: Invalid tag in response header: %" PRIx32,
                      ctx->rsp_header.tag);
            return TSS2_SYS_RC_MALFORMED_RESPONSE;
        }
    }

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                     ctx->maxCmdSize,
                                     &ctx->nextData,
                                     &ctx->rsp_header.responseSize);
    if (rval)
        return rval;

    if (ctx->rsp_header.responseSize > ctx->maxCmdSize) {
        return TSS2_SYS_RC_MALFORMED_RESPONSE;
    }

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    &ctx->rsp_header.responseCode);
    if (rval)
        return rval;

    rval = ctx->rsp_header.responseCode;

    /* If we received a TPM error other than CANCELED or if we didn't
     * receive enough response bytes, reset SAPI state machine to
     * CMD_STAGE_PREPARE. There's nothing else we can do for current command.
     */
    if (ctx->rsp_header.responseSize < sizeof(TPM20_Header_Out)) {
        ctx->previousStage = CMD_STAGE_PREPARE;
        return TSS2_SYS_RC_INSUFFICIENT_RESPONSE;
    }
    if (rval == TPM2_RC_CANCELED) {
        ctx->previousStage = CMD_STAGE_PREPARE;
        return rval;
    }

    ctx->previousStage = CMD_STAGE_RECEIVE_RESPONSE;
    return rval;
}

TSS2_RC Tss2_Sys_Execute(TSS2_SYS_CONTEXT *sysContext)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_ExecuteAsync(sysContext);
    if (rval)
        return rval;

    return Tss2_Sys_ExecuteFinish(sysContext, TSS2_TCTI_TIMEOUT_BLOCK);
}
