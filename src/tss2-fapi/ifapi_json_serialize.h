/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef IFAPI_JSON_SERIALIZE_H
#define IFAPI_JSON_SERIALIZE_H

#include <json.h>                // for json_object

#include "fapi_int.h"            // for IFAPI_CAP_INFO, IFAPI_INFO
#include "fapi_types.h"          // for UINT8_ARY
#include "ifapi_config.h"        // for IFAPI_CONFIG
#include "ifapi_eventlog.h"      // for IFAPI_EVENT_TYPE, FAPI_QUOTE_INFO
#include "ifapi_ima_eventlog.h"  // for IFAPI_IMA_EVENT
#include "ifapi_keystore.h"      // for IFAPI_DUPLICATE, IFAPI_EXT_PUB_KEY
#include "tss2_common.h"         // for TSS2_RC, UINT32

#define YES 1
#define NO 0

TSS2_RC
ifapi_json_UINT8_ARY_serialize(const UINT8_ARY *in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_OBJECT_TYPE_CONSTANT_serialize(const IFAPI_OBJECT_TYPE_CONSTANT
        in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_KEY_serialize(const IFAPI_KEY *in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_EXT_PUB_KEY_serialize(const IFAPI_EXT_PUB_KEY *in,
                                       json_object **jso);

TSS2_RC
ifapi_json_IFAPI_NV_serialize(const IFAPI_NV *in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_HIERARCHY_serialize(const IFAPI_HIERARCHY *in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_OBJECT_serialize(const IFAPI_OBJECT *in,
                                  json_object **jso);

TSS2_RC
ifapi_json_FAPI_QUOTE_INFO_serialize(const FAPI_QUOTE_INFO *in,
                                     json_object **jso);

TSS2_RC
ifapi_json_IFAPI_DUPLICATE_serialize(const IFAPI_DUPLICATE *in,
                                     json_object **jso);
TSS2_RC
ifapi_json_IFAPI_CAP_INFO_serialize(const IFAPI_CAP_INFO *in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_INFO_serialize(const IFAPI_INFO *in, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_EVENT_TYPE_serialize(const IFAPI_EVENT_TYPE in,
                                      json_object **jso);

TSS2_RC
ifapi_json_IFAPI_EVENT_TYPE_serialize_txt(const IFAPI_EVENT_TYPE in,
        json_object **jso);

TSS2_RC
ifapi_json_IFAPI_TSS_EVENT_serialize(const IFAPI_TSS_EVENT *in,
                                     json_object **jso);

TSS2_RC
ifapi_json_IFAPI_IMA_EVENT_serialize(const IFAPI_IMA_EVENT *in,
                                     json_object **jso);

TSS2_RC
ifapi_json_IFAPI_EVENT_UNION_serialize(const IFAPI_EVENT_UNION *in,
                                       UINT32 selector, json_object **jso);

TSS2_RC
ifapi_json_IFAPI_EVENT_serialize(const IFAPI_EVENT *in, json_object **jso);


TSS2_RC
ifapi_json_IFAPI_CONFIG_serialize(const IFAPI_CONFIG *in, json_object **jso);


TSS2_RC
ifapi_json_TPMS_EVENT_CELMGT_serialize(const TPMS_EVENT_CELMGT *in, json_object **jso);

#endif /* IFAPI_JSON_SERIALIZE_H */
