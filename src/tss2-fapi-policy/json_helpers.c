/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_helpers.h"
#include "util/aux_util.h"

#define LOGMODULE fapijson
#include "util/log.h"

/** Deserialize a character string.
 *
 * @param[in] jso json string object.
 * @param[out] out the pointer to the created string.
 * @retval TSS2_RC_SUCCESS if the function call was a success.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_json_char_deserialize(json_object *jso, char **out) {
    *out = strdup(json_object_get_string(jso));
    return_if_null(*out, "Out of memory.", TSS2_FAPI_RC_MEMORY);
    return TSS2_RC_SUCCESS;
}

/** Serialize value of type UINT8_ARY to json.
 *
 * @param[in] in value to be serialized.
 * @param[out] jso pointer to the json object.
 * @retval TSS2_RC_SUCCESS if the function call was a success.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory.
 * @retval TSS2_FAPI_RC_BAD_VALUE if the value is not of type TPM2B_DIGEST.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 */
TSS2_RC
ifapi_json_UINT8_ARY_serialize(const UINT8_ARY *in, json_object **jso) {
    TSS2_RC r;

    return_if_null(in, "Bad reference.", TSS2_FAPI_RC_BAD_REFERENCE);

    char *hex_string = malloc((in->size) * 2 + 1);
    return_if_null(hex_string, "Out of memory.", TSS2_FAPI_RC_MEMORY);

    if (in->size > 0) {
        uint8_t *buffer = in->buffer;

        for (size_t i = 0, off = 0; i < in->size; i++, off += 2)
            sprintf(&hex_string[off], "%02x", buffer[i]);
    }
    hex_string[(in->size) * 2] = '\0';
    *jso = json_object_new_string(hex_string);
    goto_if_null2(jso, "Out of memory", r, TSS2_FAPI_RC_MEMORY, error);

    SAFE_FREE(hex_string);
    return TSS2_RC_SUCCESS;

error:
    SAFE_FREE(hex_string);
    return r;
}

/** Check valid keys of a json object.
 *
 * @param[in]  jso The json object.
 * @param[out] field_tab the array of strings with allowed fields.
 * @param[out] size_of_tab The number of allowed fields.
 *
 * If a unexpected field occurs a warning will be displayed.
 */
void
ifapi_check_json_object_fields(json_object *jso, char **field_tab, size_t size_of_tab) {
    enum json_type type;
    bool           found;
    size_t         i;

    type = json_object_get_type(jso);
    if (type == json_type_object) {
        /* Object with keys. */
        json_object_object_foreach(jso, key, val) {
            UNUSED(val);
            found = false;
            for (i = 0; i < size_of_tab; i++) {
                if (strcmp(key, field_tab[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                LOG_WARNING("Invalid field: %s", key);
            }
        }
    }
}
