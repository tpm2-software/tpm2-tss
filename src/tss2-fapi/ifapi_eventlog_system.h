/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_EVENTLOG_SYSTEM_H
#define IFAPI_EVENTLOG_SYSTEM_H

#include <json.h>         // for json_object
#include <stdbool.h>      // for bool
#include <stddef.h>       // for size_t

#include "efi_event.h"    // for TCG_EVENT_HEADER2, TCG_DIGEST2, TCG_EVENT
#include "fapi_types.h"   // for UINT8_ARY
#include "tss2_common.h"  // for UINT32, BYTE, TSS2_RC

typedef UINT32 TCG_EVENT_TYPE;

typedef struct {
    TCG_EVENT_TYPE in;
    char *name;
} TCG_EVENT_TYPE_ASSIGN;

typedef bool (*DIGEST2_CALLBACK)(TCG_DIGEST2 const *digest, size_t size,
                                 void *data);
typedef bool (*EVENT2_CALLBACK)(TCG_EVENT_HEADER2 const *event_hdr, size_t size,
                                void *data);
typedef bool (*EVENT2DATA_CALLBACK)(TCG_EVENT2 const *event, UINT32 type,
                                    void *data);
typedef bool (*SPECID_CALLBACK)(TCG_EVENT const *event, void *data);
typedef bool (*LOG_EVENT_CALLBACK)(TCG_EVENT const *event_hdr, size_t size,
                                   void *data);

typedef struct {
    void *data;
    SPECID_CALLBACK specid_cb;
    LOG_EVENT_CALLBACK log_eventhdr_cb;
    EVENT2_CALLBACK event2hdr_cb;
    DIGEST2_CALLBACK digest2_cb;
    EVENT2DATA_CALLBACK event2_cb;
} tpm2_eventlog_context;

/** Firmware event information stored in log
 */
typedef struct {
    UINT32 event_type;
    UINT8_ARY data;
} IFAPI_FIRMWARE_EVENT;


bool digest2_accumulator_callback(TCG_DIGEST2 const *digest, size_t size,
                                  void *data);

bool parse_event2body(TCG_EVENT2 const *event, UINT32 type);
bool foreach_digest2(tpm2_eventlog_context *ctx, UINT32 event_type,
                     TCG_DIGEST2 const *event_hdr, size_t count, size_t size);
bool parse_event2(TCG_EVENT_HEADER2 const *eventhdr, size_t buf_size,
                  size_t *event_size, size_t *digests_size);
bool foreach_event2(tpm2_eventlog_context *ctx, TCG_EVENT_HEADER2 const *eventhdr_start, size_t size);
bool specid_event(TCG_EVENT const *event, size_t size, TCG_EVENT_HEADER2 **next);
bool parse_eventlog(tpm2_eventlog_context *ctx, BYTE const *eventlog, size_t size);

TSS2_RC
ifapi_json_IFAPI_FIRMWARE_EVENT_deserialize(
    json_object *jso,
    IFAPI_FIRMWARE_EVENT *out,
    bool *verify);

#endif /* IFAPI_EVENTLOG_SYSTEM_H */
