/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef IFAPI_JSON_EVENTLOG_SERIALIZE_H
#define IFAPI_JSON_EVENTLOG_SERIALIZE_H

#include <json.h>             // for json_object
#include <stdbool.h>          // for bool
#include <stddef.h>           // for size_t
#include <stdint.h>           // for uint32_t

#include "tss2_common.h"      // for TSS2_RC, UINT8
#include "tss2_tpm2_types.h"  // for TPM2_MAX_PCRS

typedef struct {
	json_object *jso_event_list;
    const uint32_t *pcr_list;
    size_t pcr_list_size;
    bool skip_event;
    size_t recnum_tab[TPM2_MAX_PCRS];
} callback_data;

bool ifapi_pcr_used(
    uint32_t pcr,
    const uint32_t *pcr_list,
    size_t pcr_list_size);

TSS2_RC ifapi_tcg_eventlog_serialize(
    UINT8 const *eventlog,
    size_t size,
    const uint32_t *pcr_list,
    size_t  pcr_list_size,
    json_object **eventlog_json);

TSS2_RC ifapi_get_tcg_firmware_event_list(
    char const *filename,
    const uint32_t *pcr_list,
    size_t  pcr_list_size,
    json_object **json_eventlog);

#endif /* IFAPI_JSON_EVENTLOG_SERIALIZE_H */
