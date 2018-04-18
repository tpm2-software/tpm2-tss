/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "tss2_tpm2_types.h"

#include "util/key-value-parse.h"
#define LOGMODULE tcti
#include "util/log.h"

/*
 * Parse the provided string containing a key / value pair separated by the
 * '=' character.
 * NOTE: The 'kv_str' parameter is not 'const' and this function will modify
 * it as part of the parsing process. The key_value structure will be updated
 * with references pointing to the appropriate location in the key_value_str
 * parameter.
 */
bool
parse_key_value (char *key_value_str,
                 key_value_t *key_value)
{
    const char *delim = "=";
    char *tok, *state;

    LOG_TRACE ("key_value_str: \"%s\" and key_value_t: 0x%" PRIxPTR,
               key_value_str, (uintptr_t)key_value);
    if (key_value_str == NULL || key_value == NULL) {
        LOG_WARNING ("received a NULL parameter, all are required");
        return false;
    }
    tok = strtok_r (key_value_str, delim, &state);
    if (tok == NULL) {
        LOG_WARNING ("key / value string is null.");
        return false;
    }
    key_value->key = tok;

    tok = strtok_r (NULL, delim, &state);
    if (tok == NULL) {
        LOG_WARNING ("key / value string is invalid");
        return false;
    }
    key_value->value = tok;

    return true;
}
/*
 * This function parses the provided configuration string extracting the
 * key/value pairs. Each key/value pair extracted is stored in a key_value_t
 * structure and then passed to the provided callback function for processing.
 *
 * NOTE: The 'kv_str' parameter is not 'const' and this function will modify
 * it as part of the parsing process.
 */
TSS2_RC
parse_key_value_string (char *kv_str,
                        KeyValueFunc callback,
                        void *user_data)
{
    const char *delim = ",";
    char *state, *tok;
    key_value_t key_value = KEY_VALUE_INIT;
    TSS2_RC rc = TSS2_RC_SUCCESS;

    LOG_TRACE ("kv_str: \"%s\", callback: 0x%" PRIxPTR ", user_data: 0x%"
               PRIxPTR, kv_str, (uintptr_t)callback,
               (uintptr_t)user_data);
    if (kv_str == NULL || callback == NULL || user_data == NULL) {
        LOG_WARNING ("all parameters are required");
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    for (tok = strtok_r (kv_str, delim, &state);
         tok;
         tok = strtok_r (NULL, delim, &state)) {
        LOG_DEBUG ("parsing key/value: %s", tok);
        if (parse_key_value (tok, &key_value) != true) {
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        rc = callback (&key_value, user_data);
        if (rc != TSS2_RC_SUCCESS) {
            goto out;
        }
    }
out:
    return rc;
}
