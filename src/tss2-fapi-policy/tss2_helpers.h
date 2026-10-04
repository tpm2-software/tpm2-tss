/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef TSS2_HELPERS_H
#define TSS2_HELPERS_H

// TODO change Makefile.am #include <json.h>    // for json_object
#include <json-c/json.h> // for json_object
#include <stdbool.h>     // for bool
#include <stddef.h>      // for size_t
#include <stdint.h>      // for uint8_t

#include "tss2_common.h" // for TSS2_RC

#include "fapi_crypto.h"
#include "fapi_types.h"
#include "ifapi_policy_types.h"
#include "tss2_helpers.h"
#include "tss2_policy.h"

#define TSS2_FILE_DELIM_CHAR '/'

void free_string_list(NODE_STR_T *node);

TSS2_RC
append_object_to_list(void *object, NODE_OBJECT_T **object_list);

TSS2_RC
push_object_to_list(void *object, NODE_OBJECT_T **object_list);

TSS2_RC
ifapi_asprintf(char **str, const char *fmt, ...);

void ifapi_check_json_object_fields(json_object *jso, char **field_tab, size_t size_of_tab);

void cleanup_policy_element(TPMT_POLICYELEMENT *policy);

void cleanup_policy_elements(TPML_POLICYELEMENTS *policy);

void ifapi_cleanup_policy(TPMS_POLICY *policy);

TSS2_RC
ifapi_compute_policy_digest(TPML_PCRVALUES     *pcrs,
                            TPML_PCR_SELECTION *pcr_selection,
                            TPMI_ALG_HASH       hash_alg,
                            TPM2B_DIGEST       *pcr_digest);

void ifapi_free_node_list(NODE_OBJECT_T *node);

void ifapi_free_object_list(NODE_OBJECT_T *node);

TSS2_RC
ifapi_get_name(TPMT_PUBLIC *publicInfo, TPM2B_NAME *name);

TSS2_RC
ifapi_nv_get_name(TPMS_NV_PUBLIC *publicInfo, TPM2B_NAME *name);

void ifapi_helper_init_policy_pcr_selections(TSS2_POLICY_PCR_SELECTION *s,
                                             TPMT_POLICYELEMENT        *pol_element);
TSS2_RC
ifapi_set_name_hierarchy_object(IFAPI_OBJECT *hierarchy);

void ifapi_init_hierarchy_object(IFAPI_OBJECT *hierarchy, ESYS_TR esys_handle);

#endif /* TSS2_HELPERS_H */
