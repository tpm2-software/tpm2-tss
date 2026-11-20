/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_MACROS_H
#define IFAPI_MACROS_H

#include <string.h> // IWYU pragma: keep

#include "util/aux_util.h"

/* FAPI-owned errors retain the FAPI layer. */
/* Use only at calls to helpers with a documented layerless-base-error contract. */
#define ifapi_call_base(call) tss2_rc_from_base((call), TSS2_FEATURE_RC_LAYER)

#define ifapi_strdup_check(dest, str, r, label)                                                    \
    if (str) {                                                                                     \
        (dest) = strdup(str);                                                                      \
        if (!(dest)) {                                                                             \
            (r) = TSS2_FAPI_RC_MEMORY;                                                             \
            LOG_ERROR("Out of memory.");                                                           \
            goto label;                                                                            \
        }                                                                                          \
    } else {                                                                                       \
        (dest) = NULL;                                                                             \
    }

#define ifapi_check_oom(X)                                                                         \
    if ((X) == NULL) {                                                                             \
        LOG_ERROR("Out of memory");                                                                \
        return TSS2_FAPI_RC_MEMORY;                                                                \
    }

#define ifapi_statecasedefault(VAR)                                                                \
    default:                                                                                       \
        LOG_ERROR("Bad state for " str(VAR) ": %i", VAR);                                          \
        return TSS2_FAPI_RC_BAD_SEQUENCE;

#define ifapi_return_try_again(r)                                                                  \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN) {                                                    \
        LOG_TRACE("Received TRY_AGAIN; returning TRY_AGAIN");                                      \
        return TSS2_FAPI_RC_TRY_AGAIN;                                                             \
    }

#define ifapi_try_again_or_error(r, msg, ...)                                                      \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)                                                      \
        return TSS2_FAPI_RC_TRY_AGAIN;                                                             \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        return r;                                                                                  \
    }

#define ifapi_try_again_or_error_goto(r, msg, label, ...)                                          \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)                                                      \
        return TSS2_FAPI_RC_TRY_AGAIN;                                                             \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        goto label;                                                                                \
    }

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

/* Shared-helper calls expanded by macros need the caller layer as well. */
#define ifapi_hash_update(CONTEXT, TYPE, OBJECT, R, LABEL)                                         \
    {                                                                                              \
        uint8_t buffer[sizeof(TYPE)];                                                              \
        size_t  offset = 0;                                                                        \
        (R) = Tss2_MU_##TYPE##_Marshal(OBJECT, &buffer[0], sizeof(TYPE), &offset);                 \
        goto_if_error(R, "Marshal for hash update", LABEL);                                        \
        (R) = ifapi_call_base(                                                                     \
            tss2_crypto_hash_update(CONTEXT, (const uint8_t *)&buffer[0], offset));                \
        goto_if_error(R, "crypto hash update", LABEL);                                             \
    }

#define ifapi_hash_update_buffer(CONTEXT, BUFFER, SIZE, R, LABEL)                                  \
    R = ifapi_call_base(tss2_crypto_hash_update(CONTEXT, (const uint8_t *)(BUFFER), SIZE));        \
    goto_if_error(R, "crypto hash update", LABEL);

#define ifapi_get_optional(name, json_name, type)                                                  \
    if (!ifapi_get_sub_object(jso, json_name, &jso2)) {                                            \
        memset(&out->name, 0, sizeof(type));                                                       \
    } else {                                                                                       \
        r = ifapi_call_base(ifapi_json_##type##_deserialize(jso2, &out->name));                    \
        return_if_error2(r, "Bad value for field \"%s\".", json_name);                             \
    }

#define ifapi_get_conditional_tpm2b(name, json_name, tpm2b_type, type, field_name, cond_cnt)       \
    if (!ifapi_get_sub_object(jso, json_name, &jso2)) {                                            \
        memset(&out->name, 0, sizeof(type));                                                       \
    } else {                                                                                       \
        (cond_cnt)++;                                                                              \
        json_object *jso_size;                                                                     \
        if (ifapi_get_sub_object(jso2, "size", &jso_size)) {                                       \
            tpm2b_type tmp = { 0 };                                                                \
            r = ifapi_call_base(ifapi_json_##tpm2b_type##_deserialize(jso2, &tmp));                \
            return_if_error2(r, "Bad value for field \"%s\".", json_name);                         \
            out->name = tmp.field_name;                                                            \
        } else {                                                                                   \
            r = ifapi_call_base(ifapi_json_##type##_deserialize(jso2, &out->name));                \
            return_if_error2(r, "Bad value for field \"%s\".", json_name);                         \
        }                                                                                          \
    }

#endif /* IFAPI_MACROS_H */
