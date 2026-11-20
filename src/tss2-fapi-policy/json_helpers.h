/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TSS2_JSON_HELPERS_H
#define TSS2_JSON_HELPERS_H

#include <json.h>
#include <stddef.h>
#include <string.h>

#include "tpm_json_deserialize.h"
#include "tss2_common.h"
#include "tss2_types.h"
#include "util/aux_util.h"

/* Raw field macros propagate base errors. Library callers use the
 * ifapi_/ipolicy_ variants to translate these at the call site. */
#define GET_OPTIONAL(name, json_name, type)                                                        \
    if (!ifapi_get_sub_object(jso, json_name, &jso2)) {                                            \
        memset(&out->name, 0, sizeof(type));                                                       \
    } else {                                                                                       \
        r = ifapi_json_##type##_deserialize(jso2, &out->name);                                     \
        return_if_error2(r, "Bad value for field \"%s\".", json_name);                             \
    }

/*
 * Deserialize an embedded structure of an complex TPM2B.
 * To achieve backward compatibility both JSON representations, of the complex
 * TPM2B, and of the embedded structure will be allowed.
 */
#define GET_CONDITIONAL_TPM2B(name, json_name, tpm2b_type, type, field_name, cond_cnt)             \
    if (!ifapi_get_sub_object(jso, json_name, &jso2)) {                                            \
        memset(&out->name, 0, sizeof(type));                                                       \
    } else {                                                                                       \
        (cond_cnt)++;                                                                              \
        json_object *jso_size;                                                                     \
        if (ifapi_get_sub_object(jso2, "size", &jso_size)) {                                       \
            tpm2b_type tmp = { 0 };                                                                \
            r = ifapi_json_##tpm2b_type##_deserialize(jso2, &tmp);                                 \
            return_if_error2(r, "Bad value for field \"%s\".", json_name);                         \
            out->name = tmp.field_name;                                                            \
        } else {                                                                                   \
            r = ifapi_json_##type##_deserialize(jso2, &out->name);                                 \
            return_if_error2(r, "Bad value for field \"%s\".", json_name);                         \
        }                                                                                          \
    }

/* These three helpers return layerless TSS2_BASE_RC_* for their own failures.
 * They do not issue TPM commands or invoke callbacks. Callers add their layer
 * immediately at the call site. The same convention applies to the TPM JSON, crypto and list
 * helpers in this shared library.
 */
TSS2_RC
ifapi_json_char_serialize(const char *in, json_object **jso);

TSS2_RC
ifapi_json_char_deserialize(json_object *jso, char **out);

TSS2_RC
ifapi_json_UINT8_ARY_serialize(const UINT8_ARY *in, json_object **jso);

void ifapi_check_json_object_fields(json_object *jso, char **field_tab, size_t size_of_tab);

#endif /* TSS2_JSON_HELPERS_H */
