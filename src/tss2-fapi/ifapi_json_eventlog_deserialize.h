/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef IFAPI_JSON_EVENTLOG_DESERIALIZE_H
#define IFAPI_JSON_EVENTLOG_DESERIALIZE_H

#include <json.h>                      // for json_object
#include <stddef.h>                    // for size_t
#include <stdint.h>                    // for uint8_t

#include "tss2-fapi/ifapi_eventlog.h"  // for IFAPI_EVENT_TYPE
#include "tss2_common.h"               // for TSS2_RC

TSS2_RC
ifapi_json_TCG_EVENT_TYPE_deserialize(
    json_object *jso,
    IFAPI_EVENT_TYPE *out);

TSS2_RC
ifapi_json_TCG_EVENT_TYPE_deserialize(json_object *jso, IFAPI_EVENT_TYPE *out);

TSS2_RC
ifapi_tcg_event_deserialize(
    json_object *jso,
    size_t max_size,
    uint8_t *buffer,
    size_t *buf_size);

TSS2_RC
ifapi_tcg_event_list_deserialize(
    const char *jso_string,
    size_t max_size, uint8_t *eventlog,
    size_t *eventlog_size);

#endif /* IFAPI_JSON_DESERIALIZE_H */
