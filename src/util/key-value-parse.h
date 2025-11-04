/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */

#ifndef KEY_VALUE_PARSE_H
#define KEY_VALUE_PARSE_H

#include <stdbool.h>      // for bool
#include <stdlib.h>       // for NULL

#include "tss2_common.h"  // for TSS2_RC

#define KEY_VALUE_INIT { \
    .key = NULL, \
    .value = NULL, \
}

typedef struct {
    char *key;
    char *value;
} key_value_t;

typedef TSS2_RC (*KeyValueFunc) (const key_value_t* key_value,
                                 void *user_data);
bool
parse_key_value (char *key_value_str,
                 key_value_t *key_value);
TSS2_RC
parse_key_value_string (char *kv_str,
                        KeyValueFunc callback,
                        void *user_data);

#endif /* KEY_VALUE_PARSE_H */
