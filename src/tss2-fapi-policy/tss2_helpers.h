/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef TSS2_HELPERS_H
#define TSS2_HELPERS_H

#include <stdbool.h> // for bool
#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t

#include "tss2_common.h" // for TSS2_RC

#include "tss2_policy.h"
#include "tss2_types.h"

#define TSS2_FILE_DELIM_CHAR '/'

void free_string_list(NODE_STR_T *node);

TSS2_RC
append_object_to_list(void *object, NODE_OBJECT_T **object_list);

TSS2_RC
push_object_to_list(void *object, NODE_OBJECT_T **object_list);

TSS2_RC
ifapi_asprintf(char **str, const char *fmt, ...);

void ifapi_free_node_list(NODE_OBJECT_T *node);

TSS2_RC
ifapi_get_name(TPMT_PUBLIC *publicInfo, TPM2B_NAME *name);

TSS2_RC
ifapi_nv_get_name(TPMS_NV_PUBLIC *publicInfo, TPM2B_NAME *name);

#endif /* TSS2_HELPERS_H */
