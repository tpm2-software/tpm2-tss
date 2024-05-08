/* SPDX-FileCopyrightText: 2022, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>            // for uint32_t
#include <json-c/json.h>         // for json_object, json_object_put, json_object_to_js...
#include <stdio.h>               // for NULL

#include "ifapi_ima_eventlog.h"  // for ifapi_read_ima_event_log
#include "tss2_common.h"         // for TSS2_RC
#include "util/aux_util.h"       // for UNUSED

#define LOGMODULE tests
#include "util/log.h"

int
main(int argc, char *argv[])
{
    uint32_t pcr_list[1] = { 10 };
    json_object *json_event_list = NULL;
    TSS2_RC r;

    r = ifapi_read_ima_event_log(argv[1], &pcr_list[0], 1, &json_event_list);
    UNUSED(r);
}
