/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_tpm2_types.h"
#include "tss2_tcti.h"

#include "tcti-common.h"
#include "tctildr.h"
#include "tctildr-interface.h"
#define LOGMODULE tcti
#include "util/log.h"

TSS2_RC
tcti_from_init(TSS2_TCTI_INIT_FUNC init,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC r;
    size_t size;

    LOG_TRACE("Initializing TCTI for config: %s", conf);

    if (init == NULL || tcti == NULL)
        return TSS2_TCTI_RC_BAD_REFERENCE;
    r = init(NULL, &size, conf);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("TCTI init for function %p failed with %" PRIx32, init, r);
        return r;
    }

    *tcti = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (*tcti == NULL) {
        LOG_ERROR("Memory allocation for tcti failed: %s", strerror(errno));
        return TSS2_ESYS_RC_MEMORY;
    }

    r = init(*tcti, &size, conf);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("TCTI init for function %p failed with %" PRIx32, init, r);
        free(*tcti);
        *tcti=NULL;
        return r;
    }

    LOG_DEBUG("Initialized TCTI for config: %s", conf);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_from_info(TSS2_TCTI_INFO_FUNC infof,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC r;
    LOG_TRACE("Attempting to load TCTI info");

    const TSS2_TCTI_INFO* info = infof();
    if (info == NULL) {
        LOG_ERROR("TCTI info function failed");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    LOG_TRACE("Loaded TCTI info named: %s", info->name);
    LOG_TRACE("TCTI description: %s", info->description);
    LOG_TRACE("TCTI config_help: %s", info->config_help);

    r = tcti_from_init(info->init, conf, tcti);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("Could not initialize TCTI named: %s", info->name);
        return r;
    }

    LOG_DEBUG("Initialized TCTI named: %s", info->name);

    return TSS2_RC_SUCCESS;
}
TSS2_TCTILDR_CONTEXT*
tctildr_context_cast (TSS2_TCTI_CONTEXT *ctx)
{
    if (ctx != NULL && TSS2_TCTI_MAGIC (ctx) == TCTILDR_MAGIC) {
        return (TSS2_TCTILDR_CONTEXT*)ctx;
    }
    return NULL;
}
TSS2_RC
tctildr_transmit (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return Tss2_Tcti_Transmit (ldr_ctx->tcti, command_size, command_buffer);
}
TSS2_RC
tctildr_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return Tss2_Tcti_Receive (ldr_ctx->tcti,
                              response_size,
                              response_buffer,
                              timeout);
}
TSS2_RC
tctildr_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return Tss2_Tcti_Cancel (ldr_ctx->tcti);
}
TSS2_RC
tctildr_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return Tss2_Tcti_GetPollHandles (ldr_ctx->tcti, handles, num_handles);
}
TSS2_RC
tctildr_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return Tss2_Tcti_SetLocality (ldr_ctx->tcti, locality);
}
TSS2_RC
tctildr_make_sticky (
    TSS2_TCTI_CONTEXT *tctiContext,
    TPM2_HANDLE *handle,
    uint8_t sticky)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return Tss2_Tcti_MakeSticky (ldr_ctx->tcti, handle, sticky);
}

void
tctildr_finalize (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return;
    }
    if (ldr_ctx->tcti != NULL) {
        Tss2_Tcti_Finalize (ldr_ctx->tcti);
        free (ldr_ctx->tcti);
        ldr_ctx->tcti = NULL;
    }
}

void
Tss2_TctiLdr_Finalize (TSS2_TCTI_CONTEXT **tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx;
    if (tctiContext == NULL) {
        return;
    }
    ldr_ctx = tctildr_context_cast (*tctiContext);
    if (ldr_ctx == NULL) {
        return;
    }
    tctildr_finalize (*tctiContext);
    tctildr_finalize_data (&ldr_ctx->library_handle);
    free (ldr_ctx);
    *tctiContext = NULL;
}

TSS2_RC
Tss2_TctiLdr_Initialize (const char *name,
                         const char *conf,
                         TSS2_TCTI_CONTEXT **tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = NULL;
    TSS2_RC rc;
    void *dl_handle = NULL;

    if (tctiContext == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    *tctiContext = NULL;
    rc = tctildr_get_tcti (name, conf, tctiContext, &dl_handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to instantiate TCTI");
        goto err;
    }
    ldr_ctx = calloc (1, sizeof (TSS2_TCTILDR_CONTEXT));
    if (ldr_ctx == NULL) {
        goto err;
    }
    TSS2_TCTI_MAGIC (ldr_ctx) = TCTILDR_MAGIC;
    TSS2_TCTI_VERSION (ldr_ctx) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (ldr_ctx) = tctildr_transmit;
    TSS2_TCTI_RECEIVE (ldr_ctx) = tctildr_receive;
    TSS2_TCTI_FINALIZE (ldr_ctx) = tctildr_finalize;
    TSS2_TCTI_CANCEL (ldr_ctx) = tctildr_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (ldr_ctx) = tctildr_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (ldr_ctx) = tctildr_set_locality;
    TSS2_TCTI_MAKE_STICKY (ldr_ctx) = tctildr_make_sticky;
    ldr_ctx->library_handle = dl_handle;
    ldr_ctx->tcti = *tctiContext;
    *tctiContext = (TSS2_TCTI_CONTEXT*)ldr_ctx;
    return rc;
err:
    if (*tctiContext != NULL) {
        Tss2_Tcti_Finalize (*tctiContext);
        free (*tctiContext);
        *tctiContext = NULL;
    }
    tctildr_finalize_data (&dl_handle);
    return rc;
}
