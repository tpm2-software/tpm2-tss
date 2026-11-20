/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IPOLICY_MACROS_H
#define IPOLICY_MACROS_H

#include <string.h>

#include "tss2_policy.h"
#include "util/aux_util.h"

/* Own errors use the Policy layer; retries preserve their original layer. */
#define ipolicy_strdup_check(dest, str, r, label)                                                  \
    if (str) {                                                                                     \
        (dest) = strdup(str);                                                                      \
        if (!(dest)) {                                                                             \
            (r) = TSS2_POLICY_RC_MEMORY;                                                           \
            LOG_ERROR("Out of memory.");                                                           \
            goto label;                                                                            \
        }                                                                                          \
    } else {                                                                                       \
        (dest) = NULL;                                                                             \
    }

#define ipolicy_check_oom(X)                                                                       \
    if ((X) == NULL) {                                                                             \
        LOG_ERROR("Out of memory");                                                                \
        return TSS2_POLICY_RC_MEMORY;                                                              \
    }

#define ipolicy_statecasedefault(VAR)                                                              \
    default:                                                                                       \
        LOG_ERROR("Bad state for " str(VAR) ": %i", VAR);                                          \
        return TSS2_POLICY_RC_BAD_SEQUENCE;

#define ipolicy_return_try_again(r)                                                                \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN) {                                                    \
        LOG_TRACE("Received TRY_AGAIN; returning TRY_AGAIN");                                      \
        return (r);                                                                                \
    }

#define ipolicy_try_again_or_error(r, msg, ...)                                                    \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)                                                      \
        return (r);                                                                                \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        return r;                                                                                  \
    }

#define ipolicy_try_again_or_error_goto(r, msg, label, ...)                                        \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)                                                      \
        return (r);                                                                                \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        goto label;                                                                                \
    }

#endif /* IPOLICY_MACROS_H */
