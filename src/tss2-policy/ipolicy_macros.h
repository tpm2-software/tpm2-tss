/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IPOLICY_MACROS_H
#define IPOLICY_MACROS_H

#include <string.h>

#include "tss2_policy.h"
#include "util/aux_util.h"

/* Own errors use the Policy layer; retries preserve their original layer. */
/* Use only at calls to helpers with a documented layerless-base-error contract. */
#define ipolicy_call_base(call) tss2_rc_from_base((call), TSS2_POLICY_RC_LAYER)

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

/* Shared-helper calls expanded by macros need the caller layer as well. */
#define ipolicy_hash_update(CONTEXT, TYPE, OBJECT, R, LABEL)                                       \
    {                                                                                              \
        uint8_t buffer[sizeof(TYPE)];                                                              \
        size_t  offset = 0;                                                                        \
        (R) = Tss2_MU_##TYPE##_Marshal(OBJECT, &buffer[0], sizeof(TYPE), &offset);                 \
        goto_if_error(R, "Marshal for hash update", LABEL);                                        \
        (R) = ipolicy_call_base(                                                                   \
            tss2_crypto_hash_update(CONTEXT, (const uint8_t *)&buffer[0], offset));                \
        goto_if_error(R, "crypto hash update", LABEL);                                             \
    }

#define ipolicy_hash_update_buffer(CONTEXT, BUFFER, SIZE, R, LABEL)                                \
    R = ipolicy_call_base(tss2_crypto_hash_update(CONTEXT, (const uint8_t *)(BUFFER), SIZE));      \
    goto_if_error(R, "crypto hash update", LABEL);

#define ipolicy_get_optional(name, json_name, type)                                                \
    if (!ifapi_get_sub_object(jso, json_name, &jso2)) {                                            \
        memset(&out->name, 0, sizeof(type));                                                       \
    } else {                                                                                       \
        r = ipolicy_call_base(ifapi_json_##type##_deserialize(jso2, &out->name));                  \
        return_if_error2(r, "Bad value for field \"%s\".", json_name);                             \
    }

#define ipolicy_get_conditional_tpm2b(name, json_name, tpm2b_type, type, field_name, cond_cnt)     \
    if (!ifapi_get_sub_object(jso, json_name, &jso2)) {                                            \
        memset(&out->name, 0, sizeof(type));                                                       \
    } else {                                                                                       \
        (cond_cnt)++;                                                                              \
        json_object *jso_size;                                                                     \
        if (ifapi_get_sub_object(jso2, "size", &jso_size)) {                                       \
            tpm2b_type tmp = { 0 };                                                                \
            r = ipolicy_call_base(ifapi_json_##tpm2b_type##_deserialize(jso2, &tmp));              \
            return_if_error2(r, "Bad value for field \"%s\".", json_name);                         \
            out->name = tmp.field_name;                                                            \
        } else {                                                                                   \
            r = ipolicy_call_base(ifapi_json_##type##_deserialize(jso2, &out->name));              \
            return_if_error2(r, "Bad value for field \"%s\".", json_name);                         \
        }                                                                                          \
    }

#endif /* IPOLICY_MACROS_H */
