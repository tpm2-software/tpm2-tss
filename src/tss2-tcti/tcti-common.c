/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h> // for PRIxPTR
#include <string.h>   // for memcpy

#include "tcti-common.h"
#include "util/tss2_endian.h" // for BE_TO_HOST_16, BE_TO_HOST_32, HOST_TO_BE_16, HOST_TO_BE_32

#define LOGMODULE tcti
#include "util/log.h" // for LOG_ERROR, LOG_TRACE

TSS2_TCTI_COMMON_CONTEXT *
tcti_common_context_cast(TSS2_TCTI_CONTEXT *ctx) {
    return (TSS2_TCTI_COMMON_CONTEXT *)ctx;
}

TSS2_TCTI_CONTEXT *
tcti_common_down_cast(TSS2_TCTI_COMMON_CONTEXT *ctx) {
    return (TSS2_TCTI_CONTEXT *)&ctx->v2;
}

TSS2_RC
tcti_common_cancel_checks(TSS2_TCTI_COMMON_CONTEXT *tcti_common, uint64_t magic) {
    if (tcti_common == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    if (TSS2_TCTI_MAGIC(tcti_common) != magic) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    if (tcti_common->state != TCTI_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_common_transmit_checks(TSS2_TCTI_COMMON_CONTEXT *tcti_common,
                            const uint8_t            *command_buffer,
                            uint64_t                  magic) {
    if (command_buffer == NULL || tcti_common == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    if (TSS2_TCTI_MAGIC(tcti_common) != magic) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    if (tcti_common->state != TCTI_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_common_receive_checks(TSS2_TCTI_COMMON_CONTEXT *tcti_common,
                           size_t                   *response_size,
                           uint64_t                  magic) {
    if (response_size == NULL || tcti_common == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    if (TSS2_TCTI_MAGIC(tcti_common) != magic) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    if (tcti_common->state != TCTI_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_common_set_locality_checks(TSS2_TCTI_COMMON_CONTEXT *tcti_common, uint64_t magic) {
    if (tcti_common == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    if (TSS2_TCTI_MAGIC(tcti_common) != magic) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    if (tcti_common->state != TCTI_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_make_sticky_not_implemented(TSS2_TCTI_CONTEXT *tctiContext, uint32_t *handle, uint8_t sticky) {
    (void)tctiContext;
    (void)handle;
    (void)sticky;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
header_unmarshal(const uint8_t *buf, tpm_header_t *header) {
    uint16_t tag;
    uint32_t size;
    uint32_t code;

    LOG_TRACE("Parsing header from buffer: 0x%" PRIxPTR, (uintptr_t)buf);
    memcpy(&tag, buf, sizeof(tag));
    memcpy(&size, buf + sizeof(tag), sizeof(size));
    memcpy(&code, buf + sizeof(tag) + sizeof(size), sizeof(code));

    header->tag = BE_TO_HOST_16(tag);
    header->size = BE_TO_HOST_32(size);
    header->code = BE_TO_HOST_32(code);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
header_marshal(const tpm_header_t *header, uint8_t *buf) {
    uint16_t tag = HOST_TO_BE_16(header->tag);
    uint32_t size = HOST_TO_BE_32(header->size);
    uint32_t code = HOST_TO_BE_32(header->code);

    LOG_TRACE("Parsing header from buffer: 0x%" PRIxPTR, (uintptr_t)buf);
    memcpy(buf, &tag, sizeof(tag));
    memcpy(buf + sizeof(tag), &size, sizeof(size));
    memcpy(buf + sizeof(tag) + sizeof(size), &code, sizeof(code));
    return TSS2_RC_SUCCESS;
}
