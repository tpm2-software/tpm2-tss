/***********************************************************************
 * Copyright (c) 2015 - 2017 Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sapi/tpm20.h"
#include "sapi/tss2_mu.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common/debug.h"
#include "tcti.h"
#include "tcti/tcti_device.h"
#include "logging.h"

TSS2_RC LocalTpmSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    uint8_t *command_buffer
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ssize_t size;

#ifdef DEBUG
    UINT32 commandCode;
    UINT32 cnt;
#endif
    printf_type rmPrefix;

    rval = tcti_send_checks (tctiContext, command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }
    if (tcti_intel->status.rmDebugPrefix == 1) {
        rmPrefix = RM_PREFIX;
    } else {
        rmPrefix = NO_PREFIX;
    }
#ifdef DEBUG
    TSS2_RC rc;
    size_t offset = sizeof (TPM_ST);
    rc = Tss2_MU_TPM_ST_Unmarshal (command_buffer,
                                   command_size,
                                   &offset,
                                   &commandCode);
    rc = Tss2_MU_UINT32_Unmarshal (command_buffer,
                                   command_size,
                                   &offset,
                                   &cnt);
    if (tcti_intel->status.debugMsgEnabled == 1) {
        TCTI_LOG (tctiContext, rmPrefix, "");
        TCTI_LOG (tctiContext,
                  rmPrefix,
                  "Cmd sent: %s\n",
                  strTpmCommandCode (commandCode));
        DEBUG_PRINT_BUFFER (rmPrefix, command_buffer, cnt);
    }
#endif
    size = write (tcti_intel->devFile, command_buffer, command_size);
    if (size < 0) {
        TCTI_LOG (tctiContext,
                  rmPrefix,
                  "send failed with error: %d\n",
                  errno);
        return TSS2_TCTI_RC_IO_ERROR;
    } else if ((size_t)size != command_size) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    tcti_intel->previousStage = TCTI_STAGE_SEND_COMMAND;
    tcti_intel->status.tagReceived = 0;
    tcti_intel->status.responseSizeReceived = 0;
    tcti_intel->status.protocolResponseSizeReceived = 0;

    return TSS2_RC_SUCCESS;
}

TSS2_RC LocalTpmReceiveTpmResponse(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    unsigned char *response_buffer,
    int32_t timeout
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ssize_t  size;
    unsigned int i;
    printf_type rmPrefix;

    rval = tcti_receive_checks (tctiContext, response_size, response_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        goto retLocalTpmReceive;
    }

    if (tcti_intel->status.rmDebugPrefix == 1) {
        rmPrefix = RM_PREFIX;
    } else {
        rmPrefix = NO_PREFIX;
    }

    if (tcti_intel->status.tagReceived == 0) {
        size = read (tcti_intel->devFile, tcti_intel->responseBuffer, 4096);
        if (size < 0) {
            TCTI_LOG (tctiContext,
                      rmPrefix,
                      "read failed with error: %d\n",
                      errno);
            rval = TSS2_TCTI_RC_IO_ERROR;
            goto retLocalTpmReceive;
        } else {
            tcti_intel->status.tagReceived = 1;
            tcti_intel->responseSize = size;
        }

        tcti_intel->responseSize = size;
    }

    if (response_buffer == NULL) {
        *response_size = tcti_intel->responseSize;
        goto retLocalTpmReceive;
    }

    if (*response_size < tcti_intel->responseSize) {
        rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        *response_size = tcti_intel->responseSize;
        goto retLocalTpmReceive;
    }

    *response_size = tcti_intel->responseSize;

    for (i = 0; i < *response_size; i++) {
        response_buffer[i] = tcti_intel->responseBuffer[i];
    }

#ifdef DEBUG
    if (tcti_intel->status.debugMsgEnabled == 1 &&
        tcti_intel->responseSize > 0)
    {
        TCTI_LOG (tctiContext, rmPrefix, "\n");
        TCTI_LOG (tctiContext, rmPrefix, "Response Received: ");
        DEBUG_PRINT_BUFFER (rmPrefix,
                            response_buffer,
                            tcti_intel->responseSize);
    }
#endif

    tcti_intel->status.commandSent = 0;

retLocalTpmReceive:
    if (rval == TSS2_RC_SUCCESS && response_buffer != NULL ) {
        tcti_intel->previousStage = TCTI_STAGE_RECEIVE_RESPONSE;
    }

    return rval;
}

void LocalTpmFinalize(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);

    if (tctiContext != NULL) {
        close(tcti_intel->devFile);
    }
}

TSS2_RC LocalTpmCancel(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    /* Linux driver doesn't expose a mechanism to cancel commands. */
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC LocalTpmGetPollHandles(
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    /* Linux driver doesn't support polling. */
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC LocalTpmSetLocality(
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality
    )
{
    /*
     * Linux driver doesn't expose a mechanism for user space applications
     * to set locality.
     */
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC InitDeviceTcti (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    const TCTI_DEVICE_CONF *config
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof (TSS2_TCTI_CONTEXT_INTEL);
        return TSS2_RC_SUCCESS;
    }
    if (config == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Init TCTI context */
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = LocalTpmSendTpmCommand;
    TSS2_TCTI_RECEIVE (tctiContext) = LocalTpmReceiveTpmResponse;
    TSS2_TCTI_FINALIZE (tctiContext) = LocalTpmFinalize;
    TSS2_TCTI_CANCEL (tctiContext) = LocalTpmCancel;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = LocalTpmGetPollHandles;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = LocalTpmSetLocality;
    tcti_intel->status.locality = 3;
    tcti_intel->status.commandSent = 0;
    tcti_intel->status.rmDebugPrefix = 0;
    tcti_intel->currentTctiContext = 0;
    tcti_intel->previousStage = TCTI_STAGE_INITIALIZE;
    TCTI_LOG_CALLBACK (tctiContext) = config->logCallback;
    TCTI_LOG_DATA (tctiContext) = config->logData;

    tcti_intel->devFile = open (config->device_path, O_RDWR);
    if (tcti_intel->devFile < 0) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return rval;
}
