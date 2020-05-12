/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#endif

#include "tss2_tcti_network.h"

#include "tcti-network.h"
#include "tcti-common.h"
#include "util/key-value-parse.h"
#define LOGMODULE tcti
#include "util/log.h"

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the network TCTI context. If passed a NULL context the function
 * returns a NULL ptr. The function doesn't check magic number anymore
 * It should checked by the appropriate tcti_common_checks.
 */
TSS2_TCTI_NETWORK_CONTEXT*
tcti_network_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx == NULL)
        return NULL;

    return (TSS2_TCTI_NETWORK_CONTEXT*)tcti_ctx;
}
/*
 * This function down-casts the network TCTI context to the common context
 * defined in the tcti-common module.
 */
TSS2_TCTI_COMMON_CONTEXT*
tcti_network_down_cast (TSS2_TCTI_NETWORK_CONTEXT *tcti_network)
{
    if (tcti_network == NULL) {
        return NULL;
    }
    return &tcti_network->common;
}

TSS2_RC
tcti_network_transmit (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t size,
    const uint8_t *cmd_buf)
{
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = tcti_network_context_cast (tcti_ctx);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_network_down_cast (tcti_network);

    TSS2_RC rc = tcti_common_transmit_checks (tcti_common, cmd_buf, TCTI_NETWORK_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = socket_xmit_buf (tcti_network->socket, cmd_buf, size);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;

    return rc;
}

TSS2_RC
tcti_network_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = tcti_network_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_network_down_cast (tcti_network);
    TSS2_RC rc;

    rc = tcti_common_cancel_checks (tcti_common, TCTI_NETWORK_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_network->cancel = 1;

    return rc;
}

TSS2_RC
tcti_network_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = tcti_network_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_network_down_cast (tcti_network);
    TSS2_RC rc;

    rc = tcti_common_set_locality_checks (tcti_common, TCTI_NETWORK_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->locality = locality;
    return TSS2_RC_SUCCESS;
}
// TODO do we need a define for this, this is coupled to device TCTI?
#define TCTI_ASYNC
TSS2_RC
tcti_network_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
#ifdef TCTI_ASYNC
    TSS2_TCTI_NETWORK_CONTEXT *network_tcti = tcti_network_context_cast (tctiContext);

    if (num_handles == NULL || network_tcti == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    if (handles != NULL && *num_handles < 1) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    *num_handles = 1;
    if (handles != NULL) {
        handles->fd = network_tcti->socket;
    }

    return TSS2_RC_SUCCESS;
#else
    (void)(tctiContext);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
#endif
}

void
tcti_network_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = tcti_network_context_cast (tctiContext);

    if (tcti_network == NULL) {
        return;
    }

    socket_close (&tcti_network->socket);
}

TSS2_RC
tcti_network_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    unsigned char *response_buffer,
    int32_t timeout)
{
#ifdef TEST_FAPI_ASYNC
    /* Used for simulating a timeout. */
    static int wait = 0;
#endif
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = tcti_network_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_network_down_cast (tcti_network);
    TSS2_RC rc;
    //int ret;

    rc = tcti_common_receive_checks (tcti_common,
                                     response_size,
                                     TCTI_NETWORK_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    if (timeout != TSS2_TCTI_TIMEOUT_BLOCK) {
        LOG_TRACE("Asynchronous I/O not actually implemented.");
#ifdef TEST_FAPI_ASYNC
        if (wait < 1) {
            LOG_TRACE("Simulating Async by requesting another invocation.");
            wait += 1;
            return TSS2_TCTI_RC_TRY_AGAIN;
        } else {
            LOG_TRACE("Sending the actual result.");
            wait = 0;
        }
#endif /* TEST_FAPI_ASYNC */
    }

    if (!response_buffer) {
        *response_size = 4096;
        // TODO warning
        return TSS2_RC_SUCCESS;
    }

    ssize_t size = 0;
    TEMP_RETRY (size, read (tcti_network->socket, response_buffer,
                *response_size));
	if (size < 0) {
		LOG_ERROR ("Failed to read response from fd %d, got errno %d: %s",
		   tcti_network->socket, errno, strerror (errno));
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto out;
	}

	*response_size = size;
	if (*response_size < TPM_HEADER_SIZE) {
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto out;
	}

	rc = header_unmarshal (
	    response_buffer,
	    &tcti_common->header);
	if (rc) {
		goto out;
	}

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
 * This function is a callback conforming to the KeyValueFunc prototype. It
 * is called by the key-value-parse module for each key / value pair extracted
 * from the configuration string. Its sole purpose is to identify valid keys
 * from the conf string and to store their corresponding values in the
 * network_conf_t structure which is passed through the 'user_data' parameter.
 */
TSS2_RC
network_kv_callback (const key_value_t *key_value,
                   void *user_data)
{
    network_conf_t *network_conf = (network_conf_t*)user_data;

    LOG_TRACE ("key_value: 0x%" PRIxPTR " and user_data: 0x%" PRIxPTR,
               (uintptr_t)key_value, (uintptr_t)user_data);
    if (key_value == NULL || user_data == NULL) {
        LOG_WARNING ("%s passed NULL parameter", __func__);
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }
    LOG_DEBUG ("key: %s / value: %s\n", key_value->key, key_value->value);
    if (strcmp (key_value->key, "host") == 0) {
        network_conf->host = key_value->value;
        return TSS2_RC_SUCCESS;
    } else if (strcmp (key_value->key, "port") == 0) {
        network_conf->port = string_to_port (key_value->value);
        if (network_conf->port == 0) {
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        return TSS2_RC_SUCCESS;
    } else {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
}
void
tcti_network_init_context_data (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common)
{
    TSS2_TCTI_MAGIC (tcti_common) = TCTI_NETWORK_MAGIC;
    TSS2_TCTI_VERSION (tcti_common) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_common) = tcti_network_transmit;
    TSS2_TCTI_RECEIVE (tcti_common) = tcti_network_receive;
    TSS2_TCTI_FINALIZE (tcti_common) = tcti_network_finalize;
    TSS2_TCTI_CANCEL (tcti_common) = tcti_network_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_common) = tcti_network_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_common) = tcti_network_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_common) = tcti_make_sticky_not_implemented;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->locality = 0;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));
}
/*
 * This is an implementation of the standard TCTI initialization function for
 * this module.
 */
TSS2_RC
Tss2_Tcti_Network_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = (TSS2_TCTI_NETWORK_CONTEXT*)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_network_down_cast (tcti_network);
    TSS2_RC rc;
    char *conf_copy = NULL;
    network_conf_t network_conf = NETWORK_CONF_DEFAULT_INIT;

    if (conf == NULL) {
        LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ""
                   " default configuration will be used.",
                   (uintptr_t)tctiContext, (uintptr_t)size);
    } else {
        LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s",
                   (uintptr_t)tctiContext, (uintptr_t)size, conf);
    }
    if (size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_NETWORK_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    if (conf != NULL) {
        LOG_TRACE ("conf is not NULL");
        if (strlen (conf) > TCTI_NETWORK_CONF_MAX) {
            LOG_WARNING ("Provided conf string exceeds maximum of %u",
                         TCTI_NETWORK_CONF_MAX);
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        conf_copy = strdup (conf);
        if (conf_copy == NULL) {
            LOG_ERROR ("Failed to allocate buffer: %s", strerror (errno));
            rc = TSS2_TCTI_RC_GENERAL_FAILURE;
            goto fail_out;
        }
        LOG_DEBUG ("Dup'd conf string to: 0x%" PRIxPTR,
                   (uintptr_t)conf_copy);
        rc = parse_key_value_string (conf_copy,
                                     network_kv_callback,
                                     &network_conf);
        if (rc != TSS2_RC_SUCCESS) {
            goto fail_out;
        }
    }
    LOG_DEBUG ("Initializing network TCTI with host: %s, port: %" PRIu16,
               network_conf.host, network_conf.port);

    tcti_network->socket = -1;
    rc = socket_connect (network_conf.host,
                         network_conf.port,
                         &tcti_network->socket);
    if (rc != TSS2_RC_SUCCESS) {
        goto fail_out;
    }

    tcti_network_init_context_data (tcti_common);

    if (conf_copy != NULL) {
        free (conf_copy);
    }
    return TSS2_RC_SUCCESS;

fail_out:
    if (conf_copy != NULL) {
        free (conf_copy);
    }
    socket_close (&tcti_network->socket);

    return rc;
}

TSS2_RC
Tss2_Tcti_Network_Server_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    TSS2_TCTI_NETWORK_CONTEXT *tcti_network = (TSS2_TCTI_NETWORK_CONTEXT*)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_network_down_cast (tcti_network);
    TSS2_RC rc;
    char *conf_copy = NULL;
    network_conf_t network_conf = NETWORK_CONF_DEFAULT_INIT;

    if (conf == NULL) {
        LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ""
                   " default configuration will be used.",
                   (uintptr_t)tctiContext, (uintptr_t)size);
    } else {
        LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s",
                   (uintptr_t)tctiContext, (uintptr_t)size, conf);
    }
    if (size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_NETWORK_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    if (conf != NULL) {
        LOG_TRACE ("conf is not NULL");
        if (strlen (conf) > TCTI_NETWORK_CONF_MAX) {
            LOG_WARNING ("Provided conf string exceeds maximum of %u",
                         TCTI_NETWORK_CONF_MAX);
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        conf_copy = strdup (conf);
        if (conf_copy == NULL) {
            LOG_ERROR ("Failed to allocate buffer: %s", strerror (errno));
            rc = TSS2_TCTI_RC_GENERAL_FAILURE;
            goto fail_out;
        }
        LOG_DEBUG ("Dup'd conf string to: 0x%" PRIxPTR,
                   (uintptr_t)conf_copy);
        rc = parse_key_value_string (conf_copy,
                                     network_kv_callback,
                                     &network_conf);
        if (rc != TSS2_RC_SUCCESS) {
            goto fail_out;
        }
    }
    LOG_DEBUG ("Initializing network TCTI with host: %s, port: %" PRIu16,
               network_conf.host, network_conf.port);

    tcti_network->socket = -1;
    rc = socket_bind (network_conf.host,
                         network_conf.port,
                         &tcti_network->socket);
    if (rc != TSS2_RC_SUCCESS) {
        goto fail_out;
    }

    tcti_network_init_context_data (tcti_common);

    if (conf_copy != NULL) {
        free (conf_copy);
    }
    return TSS2_RC_SUCCESS;

fail_out:
    if (conf_copy != NULL) {
        free (conf_copy);
    }
    socket_close (&tcti_network->socket);

    return rc;
}

/* public info structure */
const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-socket",
    .description = "TCTI module for communication with tpm2_netlistener.",
    .config_help = "Key / value string in the form \"host=localhost,port=29100\".",
    .init = Tss2_Tcti_Network_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
