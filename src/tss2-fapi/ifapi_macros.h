/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_MACROS_H
#define IFAPI_MACROS_H

#include <string.h> // IWYU pragma: keep

#include "util/aux_util.h"

#define calloc_check(dest, size, r, label)                                                         \
    {                                                                                              \
        (dest) = callock(size, 1);                                                                 \
        if (!(dest)) {                                                                             \
            (r) = TSS2_FAPI_RC_MEMORY;                                                             \
            LOG_ERROR("Out of memory.");                                                           \
            goto label;                                                                            \
        }                                                                                          \
    }

#define return_if_error_reset_state(r, msg, ...)                                                   \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        context->state = FAPI_STATE_INIT;                                                          \
        return r;                                                                                  \
    }

#define goto_if_error_reset_state(r, msg, label, ...)                                              \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        context->state = FAPI_STATE_INIT;                                                          \
        goto label;                                                                                \
    }

#define goto_error_reset_state(r, v, msg, label)                                                   \
    {                                                                                              \
        (r) = v;                                                                                   \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        context->state = FAPI_STATE_INIT;                                                          \
        goto label;                                                                                \
    }

#define goto_if_null_reset_state(p, msg, r, ec, label)                                             \
    if ((p) == NULL) {                                                                             \
        LOG_ERROR("%s ", (msg));                                                                   \
        context->state = FAPI_STATE_INIT;                                                          \
        (r) = (ec);                                                                                \
        goto label;                                                                                \
    }

#define check_not_null(X)                                                                          \
    if ((X) == NULL) {                                                                             \
        LOG_ERROR(str(X) " is NULL: BAD_REFERENCE");                                               \
        return TSS2_FAPI_RC_BAD_REFERENCE;                                                         \
    }

#define check_in_bounds(X, upper)                                                                  \
    {                                                                                              \
        const size_t _size = (X);                                                                  \
        const size_t _upper = (upper);                                                             \
        if (_size > _upper) {                                                                      \
            LOG_ERROR(str(X) " is larger than %zi", _upper);                                       \
            return TSS2_FAPI_RC_BAD_VALUE;                                                         \
        }                                                                                          \
    }

#define general_failure(VAR)                                                                       \
    default:                                                                                       \
        LOG_ERROR("Bad state for " str(VAR));                                                      \
        return TSS2_FAPI_RC_GENERAL_FAILURE;

#define statecasedefault_error(VAR, r, label)                                                      \
    default:                                                                                       \
        LOG_ERROR("Bad state for " str(VAR) ": %i", VAR);                                          \
        (r) = TSS2_FAPI_RC_BAD_SEQUENCE;                                                           \
        goto label;

#endif /* IFAPI_MACROS_H */
