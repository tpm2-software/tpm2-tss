/*
 * Copyright (c) 2015 - 2018 Intel Corporation
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sapi/tpm20.h"
#include "sapi/tss2_mu.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include "tcti.h"
#include "tcti/tcti_device.h"
#define LOGMODULE tcti
#include "log/log.h"

TSS2_RC LocalTpmSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ssize_t size;

    rval = tcti_send_checks (tctiContext, command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }
    LOGBLOB_DEBUG (command_buffer,
                   command_size,
                   "sending %zu byte command buffer:",
                   command_size);
    size = write_all (tcti_intel->devFile,
                      command_buffer,
                      command_size);
    if (size < 0) {
        LOG_ERROR("send failed with error: %d", errno);
        return TSS2_TCTI_RC_IO_ERROR;
    } else if ((size_t)size != command_size) {
        LOG_ERROR ("wrong number of bytes written. Expected %zu, wrote %zd.",
                   command_size,
                   size);
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
    uint8_t *response_buffer,
    int32_t timeout
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ssize_t  size;
    unsigned int i;

    rval = tcti_receive_checks (tctiContext, response_size, response_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        goto retLocalTpmReceive;
    }

    if (tcti_intel->status.tagReceived == 0) {
        size = TEMP_RETRY (read (tcti_intel->devFile,
                                 tcti_intel->responseBuffer,
                                 4096));
        if (size < 0) {
            LOG_ERROR("send failed with error: %d", errno);
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

    LOGBLOB_DEBUG(response_buffer, tcti_intel->responseSize, "Response Received");

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
    TSS2_RC rc;

    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return;
    }
    close (tcti_intel->devFile);
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

static TSS2_RC
_InitDeviceTcti (
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
    tcti_intel->currentTctiContext = 0;
    tcti_intel->previousStage = TCTI_STAGE_INITIALIZE;

    tcti_intel->devFile = open (config->device_path, O_RDWR);
    if (tcti_intel->devFile < 0) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return rval;
}

TSS2_RC
InitDeviceTcti (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    const TCTI_DEVICE_CONF *config
    )
{
    return _InitDeviceTcti (tctiContext, contextSize, config);
}

TSS2_RC Tss2_Tcti_Device_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf
    )
{
    const char *dev_path = conf != NULL ? conf : TCTI_DEVICE_DEFAULT;
    TCTI_DEVICE_CONF dev_conf = {
        .device_path = dev_path,
    };

    return _InitDeviceTcti (tctiContext, size, &dev_conf);
}

const static TSS2_TCTI_INFO tss2_tcti_info = {
    .name = "tcti-device",
    .description = "TCTI module for communication with Linux kernel interface.",
    .config_help = "Path to TPM character device. Default value is: "
        "TCTI_DEVICE_DEFAULT",
    .init = Tss2_Tcti_Device_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
