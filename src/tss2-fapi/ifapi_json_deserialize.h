/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef IFAPI_JSON_DESERIALIZE_H
#define IFAPI_JSON_DESERIALIZE_H

#include <json.h>    // for json_object
#include <stdbool.h> // for bool

#include "ifapi_eventlog.h" // for IFAPI_EVENT_TYPE, FAPI_QUOTE_INFO, IFAPI...
#include "ifapi_keystore.h" // for IFAPI_KEY, IFAPI_EXT_PUB_KEY, IFAPI_HIER...
#include "ifapi_macros.h"   // for return_if_error2
#include "tss2_common.h"    // for TSS2_RC, UINT32

#include "json_helpers.h"
#include "tss2_policy.h"

TSS2_RC
ifapi_json_TPMS_POLICY_deserialize(json_object *jso, TPMS_POLICY **policy);

#define YES 1
#define NO  0

bool ifapi_get_sub_object(json_object *jso, char *name, json_object **sub_jso);

TSS2_RC
ifapi_json_IFAPI_KEY_deserialize(json_object *jso, IFAPI_KEY *out);

TSS2_RC
ifapi_json_import_IFAPI_KEY_deserialize(json_object *jso, IFAPI_KEY *out);

TSS2_RC
ifapi_json_IFAPI_EXT_PUB_KEY_deserialize(json_object *jso, IFAPI_EXT_PUB_KEY *out);

TSS2_RC
ifapi_json_IFAPI_NV_deserialize(json_object *jso, IFAPI_NV *out);

TSS2_RC
ifapi_json_IFAPI_HIERARCHY_deserialize(json_object *jso, IFAPI_HIERARCHY *out);

TSS2_RC
ifapi_json_IFAPI_OBJECT_deserialize(json_object *jso, IFAPI_OBJECT *out);

TSS2_RC
ifapi_json_FAPI_QUOTE_INFO_deserialize(json_object *jso, FAPI_QUOTE_INFO *out);

TSS2_RC
ifapi_json_IFAPI_EVENT_TYPE_deserialize(json_object *jso, IFAPI_EVENT_TYPE *out);

TSS2_RC
ifapi_json_IFAPI_EVENT_TYPE_deserialize_txt(json_object *jso, IFAPI_EVENT_TYPE *out);

TSS2_RC
ifapi_json_IFAPI_TSS_EVENT_deserialize(json_object *jso, IFAPI_TSS_EVENT *out);

TSS2_RC
ifapi_json_IFAPI_EVENT_UNION_deserialize(UINT32             selector,
                                         json_object       *jso,
                                         IFAPI_EVENT_UNION *out,
                                         bool              *verify);

enum IFAPI_EVENT_ERROR_HANDLING {
    DIGEST_CHECK_WARNING = 0,
    DIGEST_CHECK_ERROR,
    DO_NOT_CHECK_DIGEST
};

TSS2_RC
ifapi_json_IFAPI_EVENT_deserialize(json_object                    *jso,
                                   IFAPI_EVENT                    *out,
                                   enum IFAPI_EVENT_ERROR_HANDLING error_handling);

TSS2_RC
ifapi_json_TPMS_EVENT_CELMGT_deserialize(json_object *jso, TPMS_EVENT_CELMGT *out);

#endif /* IFAPI_JSON_DESERIALIZE_H */
