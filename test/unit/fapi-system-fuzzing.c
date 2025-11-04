/* SPDX-FileCopyrightText: 2022, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>                       // for uint32_t
#include <json-c/json.h>                    // for json_object, json_object_put, json_object_to_js...
#include <stdio.h>                          // for NULL, size_t

#include "ifapi_json_eventlog_serialize.h"  // for ifapi_get_tcg_firmware_ev...
#include "tss2_common.h"                    // for TSS2_RC
#include "util/aux_util.h"                  // for UNUSED

#define LOGMODULE tests
#include "util/log.h"

int
main(int argc, char *argv[])
{
    uint32_t pcr_list[9] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t pcr_list_size = 9;

    json_object *json_event_list = NULL;
    TSS2_RC r;

    r = ifapi_get_tcg_firmware_event_list(argv[1], pcr_list, pcr_list_size, &json_event_list);
    UNUSED(r);
}
