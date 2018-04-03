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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "tss2_tcti.h"
#include "tss2_tcti_device.h"

#include "tcti-common.h"
#include "tcti-device.h"
#include "util/io.h"
#define LOGMODULE tcti
#include "util/log.h"

#define TCTI_DEVICE_DEFAULT "/dev/tpm0"
/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the device TCTI context. The only safe-guard we have to ensure
 * this operation is possible is the magic number for the device TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
TSS2_TCTI_DEVICE_CONTEXT*
tcti_device_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC (tcti_ctx) == TCTI_DEVICE_MAGIC) {
        return (TSS2_TCTI_DEVICE_CONTEXT*)tcti_ctx;
    }
    return NULL;
}
/*
 * This function down-casts the device TCTI context to the common context
 * defined in the tcti-common module.
 */
TSS2_TCTI_COMMON_CONTEXT*
tcti_device_down_cast (TSS2_TCTI_DEVICE_CONTEXT *tcti_dev)
{
    if (tcti_dev == NULL) {
        return NULL;
    }
    return &tcti_dev->common;
}

TSS2_RC
tcti_device_transmit (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer)
{
    TSS2_TCTI_DEVICE_CONTEXT *tcti_dev = tcti_device_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_device_down_cast (tcti_dev);
    TSS2_RC rc = TSS2_RC_SUCCESS;
    ssize_t size;

    if (tcti_dev == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_transmit_checks (tcti_common, command_buffer);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    LOGBLOB_DEBUG (command_buffer,
                   command_size,
                   "sending %zu byte command buffer:",
                   command_size);
    size = write_all (tcti_dev->fd,
                      command_buffer,
                      command_size);
    if (size < 0) {
        return TSS2_TCTI_RC_IO_ERROR;
    } else if ((size_t)size != command_size) {
        LOG_ERROR ("wrong number of bytes written. Expected %zu, wrote %zd.",
                   command_size,
                   size);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_device_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout)
{
    TSS2_TCTI_DEVICE_CONTEXT *tcti_dev = tcti_device_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_device_down_cast (tcti_dev);
    TSS2_RC rc = TSS2_RC_SUCCESS;
    ssize_t  size;

    if (tcti_dev == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_receive_checks (tcti_common, response_size);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (timeout != TSS2_TCTI_TIMEOUT_BLOCK) {
        LOG_WARNING ("The underlying IPC mechanism does not support "
                     "asynchronous I/O. The 'timeout' parameter must be "
                     "TSS2_TCTI_TIMEOUT_BLOCK");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Read header first to get size of response. */
    if (tcti_common->header.size == 0) {
        uint8_t header_buf [TPM_HEADER_SIZE];
        LOG_INFO ("Header not yet received, reading %zd byte header from fd %d",
                  sizeof (header_buf), tcti_dev->fd);
        size = read_all (tcti_dev->fd, header_buf, sizeof (header_buf));
        if (size < 0) {
            LOG_WARNING ("Failed to read response header.");
            rc = TSS2_TCTI_RC_IO_ERROR;
            goto out;
        }
        LOGBLOB_DEBUG (header_buf, TPM_HEADER_SIZE, "Response header received");
        rc = header_unmarshal (header_buf, &tcti_common->header);
        if (rc != TSS2_RC_SUCCESS) {
            return rc;
        }
        LOG_INFO ("Received response header with size: %" PRIu32,
                  tcti_common->header.size);
    }

    if (response_buffer == NULL) {
        *response_size = tcti_common->header.size;
        LOG_DEBUG ("response_buffer is null, returning size: %zd", *response_size);
        return TSS2_RC_SUCCESS;
    }
    if (*response_size < tcti_common->header.size) {
        LOG_WARNING ("Size of user supplied response buffer %zd is less than "
                     "the size of the response buffer: %" PRIu32,
                     *response_size, tcti_common->header.size);
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    *response_size = tcti_common->header.size;

    rc = header_marshal (&tcti_common->header, response_buffer);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    /* Read the rest of the response, minus the header that we already jave. */
    size = read_all (tcti_dev->fd,
                     &response_buffer [TPM_HEADER_SIZE],
                     tcti_common->header.size - TPM_HEADER_SIZE);
    if (size < 0) {
        LOG_WARNING ("Failed to read response body.");
        rc = TSS2_TCTI_RC_IO_ERROR;
        goto out;
    }

    LOGBLOB_DEBUG(response_buffer, tcti_common->header.size, "Response Received");

    /*
     * Executing code beyond this point transitions the state machine to
     * TRANSMIT. Another call to this function will not be possible until
     * another command is sent to the TPM.
     */
out:
    tcti_common->header.size = 0;
    tcti_common->state = TCTI_STATE_TRANSMIT;

    return rc;
}

void
tcti_device_finalize (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_DEVICE_CONTEXT *tcti_dev = tcti_device_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_device_down_cast (tcti_dev);

    if (tcti_dev == NULL) {
        return;
    }
    close (tcti_dev->fd);
    tcti_common->state = TCTI_STATE_FINAL;
}

TSS2_RC
tcti_device_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    /* Linux driver doesn't expose a mechanism to cancel commands. */
    (void)(tctiContext);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_device_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    /* Linux driver doesn't support polling. */
    (void)(tctiContext);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_device_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    /*
     * Linux driver doesn't expose a mechanism for user space applications
     * to set locality.
     */
    (void)(tctiContext);
    (void)(locality);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
Tss2_Tcti_Device_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    TSS2_TCTI_DEVICE_CONTEXT *tcti_dev;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common;
    const char *dev_path = conf != NULL ? conf : TCTI_DEVICE_DEFAULT;

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_DEVICE_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_DEVICE_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_device_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_device_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_device_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = tcti_device_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = tcti_device_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = tcti_device_set_locality;
    TSS2_TCTI_MAKE_STICKY (tctiContext) = tcti_make_sticky_not_implemented;
    tcti_dev = tcti_device_context_cast (tctiContext);
    tcti_common = tcti_device_down_cast (tcti_dev);
    tcti_common->state = TCTI_STATE_TRANSMIT;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));
    tcti_common->locality = 3;

    tcti_dev->fd = open (dev_path, O_RDWR);
    if (tcti_dev->fd < 0) {
        LOG_ERROR ("Failed to open device file %s: %s",
                   dev_path, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}

const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = {
        .magic = TCTI_DEVICE_MAGIC,
        .version = TCTI_VERSION,
    },
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
