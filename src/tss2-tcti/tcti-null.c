/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 Juergen Repp
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h> // for PRIxPTR, uintptr_t, uint8_t, int32_t
#include <string.h>   // for NULL, size_t, memset

#include "tcti-common.h"     // for TSS2_TCTI_COMMON_CONTEXT, TCTI_STATE_...
#include "tss2_common.h"     // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_TCTI_R...
#include "tss2_tcti.h"       // for TSS2_TCTI_CONTEXT, TSS2_TCTI_INFO
#include "tss2_tpm2_types.h" // for TPM2_RC_SUCCESS
#include "util/aux_util.h"   // for UNUSED

#define LOGMODULE tcti
#include "tcti-null.h"
#include "tss2_tctildr.h" // for Tss2_TctiLdr_Finalize, Tss2_TctiLdr_I...
#include "util/log.h"     // for LOG_WARNING, LOG_ERROR, LOGBLOB_DEBUG

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the null TCTI context. The only safeguard we have to ensure this
 * operation is possible is the magic number in the null TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
TSS2_TCTI_NULL_CONTEXT *
tcti_null_context_cast(TSS2_TCTI_CONTEXT *tcti_ctx) {
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC(tcti_ctx) == TCTI_NULL_MAGIC) {
        return (TSS2_TCTI_NULL_CONTEXT *)tcti_ctx;
    }
    return NULL;
}

/*
 * This function down-casts the null TCTI context to the common context
 * defined in the tcti-common module.
 */
TSS2_TCTI_COMMON_CONTEXT *
tcti_null_down_cast(TSS2_TCTI_NULL_CONTEXT *tcti_null) {
    if (tcti_null == NULL) {
        return NULL;
    }
    return &tcti_null->common;
}

TSS2_RC
tcti_null_transmit(TSS2_TCTI_CONTEXT *tcti_ctx, size_t size, const uint8_t *cmd_buf) {
    UNUSED(tcti_ctx);
    UNUSED(size);
    UNUSED(cmd_buf);
    LOG_WARNING("transmit can't be executed for tcti null.");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_null_receive(TSS2_TCTI_CONTEXT *tctiContext,
                  size_t            *response_size,
                  unsigned char     *response_buffer,
                  int32_t            timeout) {
    UNUSED(tctiContext);
    UNUSED(response_size);
    UNUSED(response_buffer);
    UNUSED(timeout);
    LOG_WARNING("receive can't be executed for tcti null.");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_null_cancel(TSS2_TCTI_CONTEXT *tctiContext) {
    UNUSED(tctiContext);
    LOG_WARNING("cancel can't be executed for tcti null.");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_null_set_locality(TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality) {
    UNUSED(tctiContext);
    UNUSED(locality);
    LOG_WARNING("set_locality can't be executed for tcti null.");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_null_get_poll_handles(TSS2_TCTI_CONTEXT     *tctiContext,
                           TSS2_TCTI_POLL_HANDLE *handles,
                           size_t                *num_handles) {
    UNUSED(tctiContext);
    UNUSED(handles);
    UNUSED(num_handles);
    LOG_WARNING("get_poll_handles can't be executed for tcti null.");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

void
tcti_null_finalize(TSS2_TCTI_CONTEXT *tctiContext) {
    TSS2_TCTI_NULL_CONTEXT   *tcti_null = tcti_null_context_cast(tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_null_down_cast(tcti_null);
    if (tcti_null == NULL) {
        return;
    }

    tcti_common->state = TCTI_STATE_FINAL;
}

/*
 * This is an implementation of the standard TCTI initialization function for
 * this module.
 */
TSS2_RC
Tss2_Tcti_Null_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size, const char *conf) {
    UNUSED(conf);
    TSS2_TCTI_NULL_CONTEXT   *tcti_null = (TSS2_TCTI_NULL_CONTEXT *)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_null_down_cast(tcti_null);

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof(TSS2_TCTI_NULL_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    TSS2_TCTI_MAGIC(tcti_common) = TCTI_NULL_MAGIC;
    TSS2_TCTI_VERSION(tcti_common) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT(tcti_common) = tcti_null_transmit;
    TSS2_TCTI_RECEIVE(tcti_common) = tcti_null_receive;
    TSS2_TCTI_FINALIZE(tcti_common) = tcti_null_finalize;
    TSS2_TCTI_CANCEL(tcti_common) = tcti_null_cancel;
    TSS2_TCTI_GET_POLL_HANDLES(tcti_common) = tcti_null_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY(tcti_common) = tcti_null_set_locality;
    TSS2_TCTI_MAKE_STICKY(tcti_common) = tcti_make_sticky_not_implemented;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->locality = 3;
    memset(&tcti_common->header, 0, sizeof(tcti_common->header));

    return TSS2_RC_SUCCESS;
}

/* public info structure */
const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-null",
    .description = "TCTI module which only provides initialization.",
    .config_help = "",
    .init = Tss2_Tcti_Null_Init,
};

const TSS2_TCTI_INFO *
Tss2_Tcti_Info(void) {
    return &tss2_tcti_info;
}
