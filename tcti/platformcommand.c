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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sapi/tpm20.h"
#include "tcti/tcti_socket.h"
#include "sysapi_util.h"
#include "sapi/tss2_tcti.h"
#include "sockets.h"
#include "tcti.h"
#define LOGMODULE tcti
#include "log/log.h"

TSS2_RC PlatformCommand(
    TSS2_TCTI_CONTEXT *tctiContext,
    UINT32 cmd)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    uint8_t buf [sizeof (cmd)] = { 0 };
    UINT32 rsp = 0;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    int ret;
    ssize_t read_ret;

    rc = Tss2_MU_UINT32_Marshal (cmd, buf, sizeof (cmd), NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to marshal platform command %" PRIu32 ", rc: 0x%"
                   PRIx32, cmd, rc);
        return rc;
    }

    LOGBLOB_DEBUG(buf, sizeof (cmd), "Sending %zu bytes to socket %" PRIu32
                  ":", sizeof (cmd), tcti_intel->otherSock);
    ret = write_all (tcti_intel->otherSock, buf, sizeof (cmd));
    if (ret < sizeof (cmd)) {
        LOG_ERROR("Failed to send platform command %d with error: %d",
                  cmd, ret);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    read_ret = read (tcti_intel->otherSock, buf, sizeof (buf));
    if (read_ret < sizeof (buf)) {
        LOG_ERROR("Failed to get response to platform command, errno %d: %s",
                  errno, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }

    LOGBLOB_DEBUG (buf, sizeof (buf), "Received %zu bytes from socket 0x%"
                   PRIx32 ":", read_ret, tcti_intel->otherSock);
    rc = Tss2_MU_UINT32_Unmarshal (buf, sizeof (rsp), NULL, &rsp);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal response to platform command. rc: 0x%"
                   PRIx32, rc);
        return rc;
    }
    if (rsp != 0) {
        LOG_INFO ("Platform command failed with error: %" PRIu32, rsp);
        return TSS2_TCTI_RC_IO_ERROR;
    }
    return rc;
}
