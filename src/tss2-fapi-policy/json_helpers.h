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

TSS2_RC
ifapi_json_char_deserialize(json_object *jso, char **out);

TSS2_RC
ifapi_json_UINT8_ARY_serialize(const UINT8_ARY *in, json_object **jso);

void ifapi_check_json_object_fields(json_object *jso, char **field_tab, size_t size_of_tab);

#endif /* TSS2_JSON_HELPERS_H */
