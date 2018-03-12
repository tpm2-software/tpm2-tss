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
#include <unistd.h>

#include <uriparser/Uri.h>

#include "sapi/tss2_mu.h"
#include "sockets.h"
#include "tcti/tcti_mssim.h"
#include "tcti.h"
#define LOGMODULE tcti
#include "log/log.h"

#define TCTI_SOCKET_DEFAULT_CONF "tcp://127.0.0.1:2321"
#define TCTI_SOCKET_DEFAULT_PORT 2321

TSS2_RC tcti_platform_command (
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

TSS2_RC
send_sim_session_end (
    SOCKET sock)
{
    uint8_t buf [4] = { 0, };
    TSS2_RC rc;

    rc = Tss2_MU_UINT32_Marshal (TPM_SESSION_END, buf, sizeof (buf), NULL);
    if (rc == TSS2_RC_SUCCESS) {
        return rc;
    }
    return socket_xmit_buf (sock, buf, sizeof (buf));
}

/*
 * This fucntion is used to send the simulator a sort of command message
 * that tells it we're about to send it a TPM command. This requires that
 * we first send it a 4 byte code that's defined by the simulator. Then
 * another byte identifying the locality and finally the size of the TPM
 * command buffer that we're about to send. After these 9 bytes are sent
 * the simulator will accept a TPM command buffer.
 */
#define SIM_CMD_SIZE (sizeof (UINT32) + sizeof (UINT8) + sizeof (UINT32))
TSS2_RC
send_sim_cmd_setup (
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel,
    UINT32 size)
{
    uint8_t buf [SIM_CMD_SIZE] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    rc = Tss2_MU_UINT32_Marshal (MS_SIM_TPM_SEND_COMMAND,
                                 buf,
                                 sizeof (buf),
                                 &offset);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tss2_MU_UINT8_Marshal (tcti_intel->locality,
                                buf,
                                sizeof (buf),
                                &offset);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tss2_MU_UINT32_Marshal (size, buf, sizeof (buf), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    return socket_xmit_buf (tcti_intel->tpmSock, buf, sizeof (buf));
}

TSS2_RC
tcti_mssim_transmit (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t size,
    const uint8_t *cmd_buf)
{
    tpm_header_t header = { 0 };
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tcti_ctx);
    TSS2_RC rc;

    rc = tcti_transmit_checks (tcti_ctx, cmd_buf);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    rc = parse_header (cmd_buf, &header);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (header.size != size) {
        LOG_ERROR ("Buffer size parameter: %zu, and TPM2 command header size "
                   "field: %" PRIu32 " disagree.", size, header.size);
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    LOG_DEBUG ("Sending command with TPM_CC 0x%" PRIx32 " and size %" PRIu32,
               header.code, header.size);
    rc = send_sim_cmd_setup (tcti_intel, header.size);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    rc = socket_xmit_buf (tcti_intel->tpmSock, cmd_buf, size);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_intel->state = TCTI_STATE_RECEIVE;

    return rc;
}

TSS2_RC
tcti_mssim_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;

    /* the TCTI must have executed the transmit function successfully */
    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (tcti_intel->state != TCTI_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    rc = tcti_platform_command (tctiContext, MS_SIM_CANCEL_ON);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_intel->state = TCTI_STATE_TRANSMIT;
    tcti_intel->cancel = 1;

    return rc;
}

TSS2_RC
tcti_mssim_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;

    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (tcti_intel->state != TCTI_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    tcti_intel->locality = locality;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_mssim_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

void
tcti_mssim_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;

    rc = tcti_common_checks (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        return;
    }

    send_sim_session_end (tcti_intel->otherSock);
    send_sim_session_end (tcti_intel->tpmSock);

    socket_close (&tcti_intel->otherSock);
    socket_close (&tcti_intel->tpmSock);
}

TSS2_RC
tcti_mssim_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    unsigned char *response_buffer,
    int32_t timeout)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    UINT32 trash;
    TSS2_RC rc;
    int ret;

    rc = tcti_receive_checks (tctiContext, response_size, response_buffer);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    if (timeout != TSS2_TCTI_TIMEOUT_BLOCK) {
        LOG_WARNING ("Asynchronous I/O not implemented. The 'timeout' "
                     "parameter must be TSS2_TCTI_TIMEOUT_BLOCK.");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (tcti_intel->header.size == 0) {
        /* Receive the size of the response. */
        uint8_t size_buf [sizeof (UINT32)];
        ret = socket_recv_buf (tcti_intel->tpmSock, size_buf, sizeof (UINT32));
        if (ret != sizeof (UINT32)) {
            rc = TSS2_TCTI_RC_IO_ERROR;
            goto trans_state_out;
        }

        rc = Tss2_MU_UINT32_Unmarshal (size_buf,
                                       sizeof (size_buf),
                                       0,
                                       &tcti_intel->header.size);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_WARNING ("Failed to unmarshal size from tpm2 simulator "
                         "protocol: 0x%" PRIu32, rc);
            goto trans_state_out;
        }

        LOG_DEBUG ("response size: %" PRIu32, tcti_intel->header.size);
    }

    *response_size = tcti_intel->header.size;
    if (response_buffer == NULL) {
        return TSS2_RC_SUCCESS;
    }

    if (*response_size < tcti_intel->header.size) {
        *response_size = tcti_intel->header.size;
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    /* Receive the TPM response. */
    LOG_DEBUG ("Reading response of size %" PRIu32, tcti_intel->header.size);
    ret = socket_recv_buf (tcti_intel->tpmSock,
                           (unsigned char *)response_buffer,
                           tcti_intel->header.size);
    if (ret < 0) {
        rc = TSS2_TCTI_RC_IO_ERROR;
        goto trans_state_out;
    }
    LOGBLOB_DEBUG(response_buffer, tcti_intel->header.size,
                  "Response buffer received:");

    /* Receive the appended four bytes of 0's */
    ret = socket_recv_buf (tcti_intel->tpmSock,
                           (unsigned char *)&trash,
                           4);
    if (ret != 4) {
        rc = TSS2_TCTI_RC_IO_ERROR;
        goto trans_state_out;
    }

    if (tcti_intel->cancel) {
        rc = tcti_platform_command (tctiContext, MS_SIM_CANCEL_OFF);
        tcti_intel->cancel = 0;
    }
    /*
     * Executing code beyond this point transitions the state machine to
     * TRANSMIT. Another call to this function will not be possible until
     * another command is sent to the TPM.
     */
trans_state_out:
    tcti_intel->header.size = 0;
    tcti_intel->state = TCTI_STATE_TRANSMIT;

    return rc;
}

/**
 * This function sends the Microsoft simulator the MS_SIM_POWER_ON and
 * MS_SIM_NV_ON commands using the platform command mechanism. Without
 * these the simulator will respond with zero sized buffer which causes
 * the TSS to freak out. Sending this command more than once is harmelss
 * so it's advisable to call this function as part of the TCTI context
 * initialization just to be sure.
 *
 * NOTE: The caller will still need to call Tss2_Sys_Startup. If they
 * don't, an error will be returned from each call till they do but
 * the error will at least be meaningful (TPM2_RC_INITIALIZE).
 */
static TSS2_RC
simulator_setup (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_RC rc;

    LOG_TRACE ("Initializing TCTI context 0x%" PRIxPTR,
               (uintptr_t)tctiContext);
    rc = tcti_platform_command (tctiContext, MS_SIM_POWER_ON);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_WARNING ("Failed to send MS_SIM_POWER_ON platform command.");
        return rc;
    }

    rc = tcti_platform_command (tctiContext, MS_SIM_NV_ON);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_WARNING ("Failed to send MS_SIM_NV_ON platform command.");
    }

    return rc;
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
/*
 * This function extracts the hostname and port part of the provided conf
 * string (which is really just a URI). The hostname parameter is an output
 * buffer that must be large enough to hold the hostname. HOST_NAME_MAX is
 * probably a good size. The 'port' parameter is an output parameter where
 * we store the port from the URI after we convert it to a uint16.
 * If the URI does not contain a port number then the contents of the 'port'
 * parameter will not be changed.
 * This function returns TSS2_RC_SUCCESS when the 'hostname' and 'port' have
 * been populated successfully. On failure it will return
 * TSS2_TCTI_RC_BAD_VALUE to indicate that the provided conf string contains
 * values that we can't parse or are invalid.
 */
TSS2_RC
conf_str_to_host_port (
    const char *conf,
    char *hostname,
    uint16_t *port)
{
    UriParserStateA state;
    UriUriA uri;
    /* maximum 5 digits in uint16_t + 1 for \0 */
    char port_str[6] = { 0 };
    size_t range;
    TSS2_RC rc = TSS2_RC_SUCCESS;

    state.uri = &uri;
    if (uriParseUriA (&state, conf) != URI_SUCCESS) {
        LOG_WARNING ("Failed to parse provided conf string: %s", conf);
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    }

    /* extract host & domain name / fqdn */
    range = uri.hostText.afterLast - uri.hostText.first;
    if (range > HOST_NAME_MAX) {
        LOG_WARNING ("Provided conf string has hostname that exceeds "
                     "HOST_NAME_MAX.");
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    }
    strncpy (hostname, uri.hostText.first, range);

    /* extract port number */
    range = uri.portText.afterLast - uri.portText.first;
    if (range > 5) {
        LOG_WARNING ("conf string contains invalid port.");
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    } else if (range == 0) {
        LOG_INFO ("conf string does not contain a port.");
        goto out;
    }

    strncpy (port_str, uri.portText.first, range);
    *port = string_to_port (port_str);
    if (*port == 0) {
        LOG_WARNING ("Provided conf string contains invalid port: 0");
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto out;
    }
out:
    uriFreeUriMembersA (&uri);
    return rc;
}

void
tcti_mssim_init_context_data (
    TSS2_TCTI_CONTEXT *tcti_ctx)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tcti_ctx);

    TSS2_TCTI_MAGIC (tcti_ctx) = TCTI_MAGIC;
    TSS2_TCTI_VERSION (tcti_ctx) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_ctx) = tcti_mssim_transmit;
    TSS2_TCTI_RECEIVE (tcti_ctx) = tcti_mssim_receive;
    TSS2_TCTI_FINALIZE (tcti_ctx) = tcti_mssim_finalize;
    TSS2_TCTI_CANCEL (tcti_ctx) = tcti_mssim_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_ctx) = tcti_mssim_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_ctx) = tcti_mssim_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_ctx) = tcti_make_sticky_not_implemented;
    tcti_intel->state = TCTI_STATE_TRANSMIT;
    tcti_intel->locality = 3;
    memset (&tcti_intel->header, 0, sizeof (tcti_intel->header));
}
/*
 * This is an implementation of the standard TCTI initialization function for
 * this module.
 */
TSS2_RC
Tss2_Tcti_Mssim_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    TSS2_RC rc;
    SOCKET *tpmSock, *otherSock = NULL;
    const char *uri_str = conf != NULL ? conf : TCTI_SOCKET_DEFAULT_CONF;
    char hostname[HOST_NAME_MAX + 1] = { 0 };
    uint16_t port = TCTI_SOCKET_DEFAULT_PORT;

    LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s",
               (uintptr_t)tctiContext, (uintptr_t)size, uri_str);
    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_CONTEXT_INTEL);
        return TSS2_RC_SUCCESS;
    }

    rc = conf_str_to_host_port (uri_str, hostname, &port);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tpmSock = &tcti_intel->tpmSock;
    otherSock = &tcti_intel->otherSock;

    rc = socket_connect (hostname, port, tpmSock);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = socket_connect (hostname, port + 1, otherSock);
    if (rc != TSS2_RC_SUCCESS) {
        goto fail_out;
    }

    rc = simulator_setup (tctiContext);
    if (rc != TSS2_RC_SUCCESS) {
        goto fail_out;
    }

    tcti_mssim_init_context_data (tctiContext);

    return TSS2_RC_SUCCESS;

fail_out:
    socket_close (tpmSock);
    socket_close (otherSock);

    return TSS2_TCTI_RC_IO_ERROR;
}

/* public info structure */
const static TSS2_TCTI_INFO tss2_tcti_info = {
    .version = {
        .magic = TCTI_MAGIC,
        .version = TCTI_VERSION,
    },
    .name = "tcti-socket",
    .description = "TCTI module for communication with the Microsoft TPM2 Simulator.",
    .config_help = "Connection URI in the form tcp://ip_address[:port]. " \
        "Default is: TCTI_SOCKET_DEFAULT.",
    .init = Tss2_Tcti_Mssim_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
