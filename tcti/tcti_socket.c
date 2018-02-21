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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <inttypes.h>

#include <uriparser/Uri.h>

#include "sapi/tpm20.h"
#include "sapi/tss2_mu.h"
#include "tcti/tcti_socket.h"
#include "sysapi_util.h"
#include "tcti.h"
#include "sockets.h"
#include "tss2_endian.h"
#define LOGMODULE tcti
#include "log/log.h"

static TSS2_RC tctiRecvBytes (
    TSS2_TCTI_CONTEXT *tctiContext,
    SOCKET sock,
    unsigned char *data,
    int len
    )
{
    TSS2_RC result = 0;
    result = recvBytes (sock, data, len);
    if ((INT32)result == SOCKET_ERROR) {
        LOG_ERROR("In recvBytes, recv failed (socket: 0x%x) with error: %d",
                  sock, WSAGetLastError ());
        return TSS2_TCTI_RC_IO_ERROR;
    }
    LOGBLOB_DEBUG(data, len, "Receive Bytes from socket #0x%x:", sock);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC xmit_buf (
    SOCKET sock,
    const void *buf,
    size_t size)
{
    int ret;

    LOGBLOB_DEBUG (buf, size, "Writing %zu bytes to socket %d:", size, sock);
    ret = write_all (sock, buf, size);
    if (ret < size) {
        LOG_ERROR("Failed to write to fd %d: %d", sock, WSAGetLastError ());
        return TSS2_TCTI_RC_IO_ERROR;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC send_sim_session_end (
    SOCKET sock)
{
    uint8_t buf [4] = { 0, };
    TSS2_RC rc;

    rc = Tss2_MU_UINT32_Marshal (TPM_SESSION_END, buf, sizeof (buf), NULL);
    if (rc == TSS2_RC_SUCCESS) {
        return rc;
    }
    return xmit_buf (sock, buf, sizeof (buf));
}

/*
 * Utility to function to parse the first 10 bytes of a buffer and populate
 * the 'header' structure with the results. The provided buffer is assumed to
 * be at least 10 bytes long.
 */
TSS2_RC parse_header (
    uint8_t *buf,
    tpm_header_t *header)
{
    TSS2_RC rc;
    size_t offset = 0;

    LOG_TRACE ("Parsing header from buffer: 0x%" PRIxPTR, (uintptr_t)buf);
    rc = Tss2_MU_TPM2_ST_Unmarshal (buf,
                                    TPM_HEADER_SIZE,
                                    &offset,
                                    &header->tag);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal tag.");
        return rc;
    }
    rc = Tss2_MU_UINT32_Unmarshal (buf,
                                   TPM_HEADER_SIZE,
                                   &offset,
                                   &header->size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal command size.");
        return rc;
    }
    rc = Tss2_MU_UINT32_Unmarshal (buf,
                                   TPM_HEADER_SIZE,
                                   &offset,
                                   &header->code);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal command code.");
    }
    return rc;
}

TSS2_RC SocketSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    uint8_t *command_buffer
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    UINT32 sim_cmd;
    UINT8 locality;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    tpm_header_t header;
    uint8_t buf [sizeof (UINT32)] = { 0 };

    rval = tcti_send_checks (tctiContext, command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    rval = parse_header (command_buffer, &header);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }
    if (command_size != header.size) {
        LOG_ERROR ("Buffer size parameter: %zu, and TPM2 command header size "
                   "field: %" PRIu32 " disagree. Rejecting command.",
                   command_size, header.size);
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    LOG_DEBUG("Command sent on socket #0x%x: %" PRIx16, tcti_intel->tpmSock,
              header.code);
    /* Send TPM2_SEND_COMMAND */
    rval = Tss2_MU_UINT32_Marshal (MS_SIM_TPM_SEND_COMMAND,
                                   (uint8_t*)&sim_cmd,
                                   sizeof (sim_cmd),
                                   NULL);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    rval = xmit_buf (tcti_intel->tpmSock, &sim_cmd, sizeof (sim_cmd));
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    /* Send the locality */
    locality = (UINT8)tcti_intel->status.locality;
    rval = xmit_buf (tcti_intel->tpmSock, &locality, sizeof (locality));
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    LOG_DEBUG("Locality = %d", tcti_intel->status.locality);

    /* Send number of bytes. */
    rval = Tss2_MU_UINT32_Marshal (header.size, buf, sizeof (buf), NULL);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }
    rval = xmit_buf (tcti_intel->tpmSock, buf, sizeof (buf));
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    /* Send the TPM command buffer */
    rval = xmit_buf (tcti_intel->tpmSock, command_buffer, header.size);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }
    LOGBLOB_DEBUG(command_buffer, command_size, "Sent command buffer=");

    tcti_intel->status.commandSent = 1;

    tcti_intel->previousStage = TCTI_STAGE_SEND_COMMAND;
    tcti_intel->status.tagReceived = 0;
    tcti_intel->status.responseSizeReceived = 0;
    tcti_intel->status.protocolResponseSizeReceived = 0;

    return rval;
}

TSS2_RC SocketCancel(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;

    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    } else if (tcti_intel->status.commandSent != 1) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    } else {
        return PlatformCommand (tctiContext, MS_SIM_CANCEL_ON);
    }
}

TSS2_RC SocketSetLocality(
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;

    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (tcti_intel->status.commandSent == 1) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    tcti_intel->status.locality = locality;

    return TSS2_RC_SUCCESS;
}

TSS2_RC SocketGetPollHandles(
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

void SocketFinalize(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;

    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return;
    }

    send_sim_session_end (tcti_intel->otherSock);
    send_sim_session_end (tcti_intel->tpmSock);

    CloseSockets (tcti_intel->otherSock, tcti_intel->tpmSock);
}

TSS2_RC SocketReceiveTpmResponse(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    unsigned char *response_buffer,
    int32_t timeout
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    UINT32 trash;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    fd_set readFds;
    struct timeval tv, *tvPtr;
    int32_t timeoutMsecs = timeout % 1000;
    int iResult;
    unsigned char responseSizeDelta = 0;

    rval = tcti_receive_checks (tctiContext, response_size, response_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        goto retSocketReceiveTpmResponse;
    }

    if (timeout == TSS2_TCTI_TIMEOUT_BLOCK) {
        tvPtr = 0;
    } else {
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = timeoutMsecs * 1000;
        tvPtr = &tv;
    }

    FD_ZERO (&readFds);
    FD_SET (tcti_intel->tpmSock, &readFds);

    iResult = select (tcti_intel->tpmSock + 1, &readFds, 0, 0, tvPtr);
    if (iResult == 0) {
        LOG_ERROR("select failed due to timeout, socket #: 0x%x",
                  tcti_intel->tpmSock);
        rval = TSS2_TCTI_RC_TRY_AGAIN;
        goto retSocketReceiveTpmResponse;
    } else if (iResult == SOCKET_ERROR) {
        LOG_ERROR("select failed with socket error: %d",
                  WSAGetLastError ());
        rval = TSS2_TCTI_RC_IO_ERROR;
        goto retSocketReceiveTpmResponse;
    } else if (iResult != 1) {
        LOG_ERROR("select failed, read the wrong # of bytes: %d",
                  iResult);
        rval = TSS2_TCTI_RC_IO_ERROR;
        goto retSocketReceiveTpmResponse;
    }

    if (tcti_intel->status.protocolResponseSizeReceived != 1) {
        /* Receive the size of the response. */
        rval = tctiRecvBytes (tctiContext,
                              tcti_intel->tpmSock,
                              (unsigned char *)&tcti_intel->responseSize,
                              4);
        if (rval != TSS2_RC_SUCCESS) {
            goto retSocketReceiveTpmResponse;
        }

        tcti_intel->responseSize = BE_TO_HOST_32 (tcti_intel->responseSize);
        tcti_intel->status.protocolResponseSizeReceived = 1;
    }

    if (response_buffer == NULL) {
        *response_size = tcti_intel->responseSize;
        tcti_intel->status.protocolResponseSizeReceived = 1;
        goto retSocketReceiveTpmResponse;
    }

    if (*response_size < tcti_intel->responseSize) {
        *response_size = tcti_intel->responseSize;
        rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;

        /* If possible, receive tag from TPM. */
        if (*response_size >= sizeof (TPM2_ST) &&
            tcti_intel->status.tagReceived == 0)
        {
            rval = tctiRecvBytes (tctiContext,
                                  tcti_intel->tpmSock,
                                  (unsigned char *)&tcti_intel->tag,
                                  2);
            if (rval != TSS2_RC_SUCCESS) {
                goto retSocketReceiveTpmResponse;
            } else {
                tcti_intel->status.tagReceived = 1;
            }
        }

        /* If possible, receive response size from TPM */
        if (*response_size >= (sizeof (TPM2_ST) + sizeof (TPM2_RC)) &&
            tcti_intel->status.responseSizeReceived == 0)
        {
            rval = tctiRecvBytes (tctiContext,
                                  tcti_intel->tpmSock,
                                  (unsigned char *)&tcti_intel->responseSize,
                                  4);
            if (rval != TSS2_RC_SUCCESS) {
                goto retSocketReceiveTpmResponse;
            } else {
                tcti_intel->responseSize = BE_TO_HOST_32 (tcti_intel->responseSize);
                tcti_intel->status.responseSizeReceived = 1;
            }
        }
    } else {
        if (tcti_intel->responseSize > 0)
        {
            LOG_DEBUG("Response Received: ");
            LOG_DEBUG("from socket #0x%x:",
                      tcti_intel->tpmSock);
        }

        if (tcti_intel->status.tagReceived == 1) {
            *(TPM2_ST *)response_buffer = tcti_intel->tag;
            responseSizeDelta += sizeof (TPM2_ST);
            response_buffer += sizeof (TPM2_ST);
        }

        if (tcti_intel->status.responseSizeReceived == 1) {
            *(TPM2_RC *)response_buffer = HOST_TO_BE_32 (tcti_intel->responseSize);
            responseSizeDelta += sizeof (TPM2_RC);
            response_buffer += sizeof (TPM2_RC);
        }

        /* Receive the TPM response. */
        rval = tctiRecvBytes (tctiContext,
                              tcti_intel->tpmSock,
                              (unsigned char *)response_buffer,
                              tcti_intel->responseSize - responseSizeDelta);
        if (rval != TSS2_RC_SUCCESS) {
            goto retSocketReceiveTpmResponse;
        }
        LOGBLOB_DEBUG(response_buffer, tcti_intel->responseSize,
            "Received response buffer=");

        /* Receive the appended four bytes of 0's */
        rval = tctiRecvBytes (tctiContext,
                              tcti_intel->tpmSock,
                              (unsigned char *)&trash,
                              4);
        if (rval != TSS2_RC_SUCCESS) {
            goto retSocketReceiveTpmResponse;
        }
    }

    if (tcti_intel->responseSize < *response_size) {
        *response_size = tcti_intel->responseSize;
    }

    tcti_intel->status.commandSent = 0;

    /* Turn cancel off. */
    if (rval == TSS2_RC_SUCCESS) {
        rval = PlatformCommand (tctiContext, MS_SIM_CANCEL_OFF);
    } else {
        /* Ignore return value so earlier error code is preserved. */
        PlatformCommand (tctiContext, MS_SIM_CANCEL_OFF);
    }

retSocketReceiveTpmResponse:
    if (rval == TSS2_RC_SUCCESS && response_buffer != NULL) {
        tcti_intel->previousStage = TCTI_STAGE_RECEIVE_RESPONSE;
    }

    return rval;
}

/**
 * This function sends the Microsoft simulator the MS_SIM_POWER_ON and
 * MS_SIM_NV_ON commands using the PlatformCommand mechanism. Without
 * these the simulator will respond with zero sized buffer which causes
 * the TSS to freak out. Sending this command more than once is harmelss
 * so it's advisable to call this function as part of the TCTI context
 * initialization just to be sure.
 *
 * NOTE: The caller will still need to call Tss2_Sys_Startup. If they
 * don't, an error will be returned from each call till they do but
 * the error will at least be meaningful (TPM2_RC_INITIALIZE).
 */
static TSS2_RC InitializeMsTpm2Simulator(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval;

    rval = PlatformCommand (tctiContext ,MS_SIM_POWER_ON);
    if (rval != TSS2_RC_SUCCESS) {
        CloseSockets (tcti_intel->otherSock, tcti_intel->tpmSock);
        return rval;
    }

    rval = PlatformCommand (tctiContext, MS_SIM_NV_ON);
    if (rval != TSS2_RC_SUCCESS) {
        CloseSockets (tcti_intel->otherSock, tcti_intel->tpmSock);
    }

    return rval;
}

TSS2_RC
_InitSocketTcti (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    const TCTI_SOCKET_CONF *conf,
    const uint8_t serverSockets
    )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;
    SOCKET otherSock;
    SOCKET tpmSock;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if( tctiContext == NULL ) {
        *contextSize = sizeof (TSS2_TCTI_CONTEXT_INTEL);
        return TSS2_RC_SUCCESS;
    } else if( conf == NULL ) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    TSS2_TCTI_MAGIC (tctiContext) = TCTI_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = SocketSendTpmCommand;
    TSS2_TCTI_RECEIVE (tctiContext) = SocketReceiveTpmResponse;
    TSS2_TCTI_FINALIZE (tctiContext) = SocketFinalize;
    TSS2_TCTI_CANCEL (tctiContext) = SocketCancel;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = SocketGetPollHandles;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = SocketSetLocality;
    tcti_intel->status.locality = 3;
    tcti_intel->status.commandSent = 0;
    tcti_intel->status.tagReceived = 0;
    tcti_intel->status.responseSizeReceived = 0;
    tcti_intel->status.protocolResponseSizeReceived = 0;
    tcti_intel->currentTctiContext = 0;
    tcti_intel->previousStage = TCTI_STAGE_INITIALIZE;

    rval = (TSS2_RC) InitSockets (conf->hostname,
                                  conf->port,
                                  &otherSock,
                                  &tpmSock);
    if (rval == TSS2_RC_SUCCESS) {
        tcti_intel->otherSock = otherSock;
        tcti_intel->tpmSock = tpmSock;
        rval = InitializeMsTpm2Simulator (tctiContext);
    } else {
        CloseSockets (otherSock, tpmSock);
    }

    return rval;
}
TSS2_RC
InitSocketTcti (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    const TCTI_SOCKET_CONF *conf,
    const uint8_t serverSockets
    )
{
    return _InitSocketTcti (tctiContext, contextSize, conf, serverSockets);
}
/*
 * This is a utility function to extract a TCP port number from a string.
 * The string must be 6 characters long. If the supplied string contains an
 * invalid port number then 0 is returned.
 */
static uint16_t
string_to_port (char port_str[6])
{
    uint32_t port = 0;

    if (sscanf (port_str, "%" SCNu32, &port) == EOF || port > UINT16_MAX) {
        return 0;
    }
    return port;
}

TSS2_RC Tss2_Tcti_Socket_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf
    )
{
    TCTI_SOCKET_CONF sock_conf = { 0 };
    TSS2_RC rc;
    UriParserStateA state;
    UriUriA uri;
    const char *uri_str = conf != NULL ? conf : TCTI_SOCKET_DEFAULT;
    size_t range;
    /* maximum 5 digits in uint16_t + 1 for \0 */
    char port[6] = { 0 };
    char hostname[HOST_NAME_MAX + 1] = { 0 };

    state.uri = &uri;
    if (uriParseUriA (&state, uri_str) != URI_SUCCESS) {
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    }

    /* extract host & domain name / fqdn */
    range = uri.hostText.afterLast - uri.hostText.first;
    if (range > HOST_NAME_MAX) {
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    }
    strncpy (hostname, uri.hostText.first, range);
    sock_conf.hostname = hostname;

    /* extract port number */
    range = uri.portText.afterLast - uri.portText.first;
    if (range <= 5 && range > 0) {
        strncpy (port, uri.portText.first, range);
        sock_conf.port = string_to_port (port);
        if (sock_conf.port == 0) {
            rc = TSS2_TCTI_RC_BAD_VALUE;
            goto out;
        }
    } else if (range == 0) {
        sock_conf.port = DEFAULT_SIMULATOR_TPM_PORT;
    } else { /* range > 5 */
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    }
    rc = _InitSocketTcti (tctiContext, size, &sock_conf, 0);
out:
    uriFreeUriMembersA (&uri);
    return rc;
}

/* public info structure */
const static TSS2_TCTI_INFO tss2_tcti_info = {
    .name = "tcti-socket",
    .description = "TCTI module for communication with the Microsoft TPM2 Simulator.",
    .config_help = "Connection URI in the form tcp://ip_address[:port]. " \
        "Default is: TCTI_SOCKET_DEFAULT.",
    .init = Tss2_Tcti_Socket_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
