/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef AUX_UTIL_H
#define AUX_UTIL_H

#include "util/aux_util.h"
#include <stdbool.h> // for true, bool, false
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <inttypes.h> // for PRIx32
#include <string.h>   // for explicit_bzero

#include "tss2_common.h"     // for TSS2_RC_SUCCESS, TSS2_RC_LAYER_MASK
#include "tss2_tpm2_types.h" // for TPM2_RC_1, TPM2_RC_ASYMMETRIC, TPM2_RC_...
#if defined(_WIN32)
#include <windows.h> // for SecureZeroMemory
#endif
#ifdef __cplusplus
extern "C" {
#endif

/*
 * secure_mem_zero(buf, size)
 *
 * Securely zeroes a memory region that may contain sensitive data.
 *
 * This macro ensures that the memory is actually overwritten and not
 * optimized away by the compile.
 */
#if defined(__GLIBC__)
#define secure_mem_zero(buf, size)                                                                 \
    if ((buf) && (size))                                                                           \
    explicit_bzero((buf), (size))
#elif defined(_WIN32)
#define secure_mem_zero(buf, size)                                                                 \
    if ((buf) && (size))                                                                           \
    SecureZeroMemory((buf), (size))
#else
#define secure_mem_zero(buf, size)                                                                 \
    do {                                                                                           \
        void  *mz_ptr = (buf);                                                                     \
        size_t mz_len = (size);                                                                    \
        if (mz_ptr && mz_len) {                                                                    \
            volatile unsigned char *mz_p = (volatile unsigned char *)mz_ptr;                       \
            while (mz_len--) {                                                                     \
                *mz_p++ = 0;                                                                       \
            }                                                                                      \
        }                                                                                          \
    } while (0)
#endif
#define secure_char_zero(str)                                                                      \
    if ((str))                                                                                     \
    secure_mem_zero((str), strlen((str)))

#define SAFE_FREE(S)                                                                               \
    if ((S) != NULL) {                                                                             \
        free((void *)(S));                                                                         \
        (S) = NULL;                                                                                \
    }

#define ARRAY_LEN(x)       (sizeof(x) / sizeof((x)[0]))

#define TPM2_ERROR_FORMAT  "%s%s (0x%08" PRIx32 ")"
#define TPM2_ERROR_TEXT(r) "Error", "Code", r
#define SIZE_OF_ARY(ary)   (sizeof(ary) / sizeof((ary)[0]))

#if defined(__GNUC__)
#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))
#else
#define COMPILER_ATTR(...)
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#if (MAXLOGLEVEL == LOGL_NONE)
/* Note:
 * MAYBE_UNUSED macro should be used to mark variables used only
 * for assertions i.e. in debug mode, and/or for logging, which
 * might be compiled out. This shuldn't trigger 'unused variable'
 * or 'variable assigned, but not used' warnings when debug and
 * logging is disabled on configure time, but should trigger
 * warnings for variables that are not used for neither.
 */
#define MAYBE_UNUSED COMPILER_ATTR(unused)
#else
#define MAYBE_UNUSED
#endif

#define return_if_error(r, msg)                                                                    \
    if ((r) != TSS2_RC_SUCCESS) {                                                                  \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        return r;                                                                                  \
    }

#define return_state_if_error(r, s, msg)                                                           \
    if ((r) != TSS2_RC_SUCCESS) {                                                                  \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        esysContext->state = s;                                                                    \
        return r;                                                                                  \
    }

#define return_error(r, msg)                                                                       \
    {                                                                                              \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        return r;                                                                                  \
    }

#define goto_state_if_error(r, s, msg, label)                                                      \
    if ((r) != TSS2_RC_SUCCESS) {                                                                  \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        esysContext->state = s;                                                                    \
        goto label;                                                                                \
    }

#define goto_if_null(p, msg, ec, label)                                                            \
    if ((p) == NULL) {                                                                             \
        LOG_ERROR("%s ", (msg));                                                                   \
        r = (ec);                                                                                  \
        goto label;                                                                                \
    }

#define goto_if_error(r, msg, label)                                                               \
    if ((r) != TSS2_RC_SUCCESS) {                                                                  \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        goto label;                                                                                \
    }

#define goto_error(r, v, msg, label, ...)                                                          \
    {                                                                                              \
        r = v;                                                                                     \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        goto label;                                                                                \
    }

#define return_if_null(p, msg, ec)                                                                 \
    if ((p) == NULL) {                                                                             \
        LOG_ERROR("%s ", msg);                                                                     \
        return ec;                                                                                 \
    }

#define return_if_notnull(p, msg, ec)                                                              \
    if ((p) != NULL) {                                                                             \
        LOG_ERROR("%s ", msg);                                                                     \
        return ec;                                                                                 \
    }

#define set_return_code(r_max, r, msg)                                                             \
    if ((r) != TSS2_RC_SUCCESS) {                                                                  \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r));                               \
        (r_max) = r;                                                                               \
    }

#define rc_layer(r)  ((r) & TSS2_RC_LAYER_MASK)
#define base_rc(r)   ((r) & ~TSS2_RC_LAYER_MASK)
#define number_rc(r) ((r) & ~TPM2_RC_N_MASK)

static inline TSS2_RC
tss2_fmt_p1_error_to_rc(UINT16 err) {
    return TPM2_RC_1 + TPM2_RC_P + err;
}

static inline bool
tss2_is_expected_error(TSS2_RC rc) {
    /* Success is always expected */
    if (rc == TSS2_RC_SUCCESS) {
        return true;
    }

    /*
     * drop the layer, any part of the TSS stack can gripe about this error
     * if it wants too.
     */
    rc &= ~TSS2_RC_LAYER_MASK;

    /*
     * Format 1, parameter 1 errors plus the below RC's
     * contain everything we care about:
     *   - TPM2_RC_CURVE
     *   - TPM2_RC_HASH
     *   - TPM2_RC_ASYMMETRIC
     *   - TPM2_RC_KEY_SIZE
     */
    if (rc == tss2_fmt_p1_error_to_rc(TPM2_RC_CURVE) || rc == tss2_fmt_p1_error_to_rc(TPM2_RC_VALUE)
        || rc == tss2_fmt_p1_error_to_rc(TPM2_RC_HASH)
        || rc == tss2_fmt_p1_error_to_rc(TPM2_RC_ASYMMETRIC)
        || rc == tss2_fmt_p1_error_to_rc(TPM2_RC_KEY_SIZE)) {
        return true;
    }

    return false;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AUX_UTIL_H */
