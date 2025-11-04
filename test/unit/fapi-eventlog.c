/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>                       // for uint32_t, uint8_t, UINT16...
#include <json.h>                           // for json_object_put, json_object
#include <stdbool.h>                        // for bool
#include <stdio.h>                          // for NULL, size_t, fread, fopen
#include <stdlib.h>                         // for calloc, free
#include <string.h>                         // for memcmp, memcpy, strdup

#include "../helper/cmocka_all.h"           // for cmocka_unit_test, assert_...
#include "ifapi_eventlog.h"                 // for ifapi_cleanup_event, IFAP...
#include "ifapi_helpers.h"                  // for IFAPI_PCR_REG, ifapi_calc...
#include "ifapi_json_deserialize.h"         // for ifapi_json_IFAPI_EVENT_de...
#include "ifapi_json_eventlog_serialize.h"  // for ifapi_get_tcg_firmware_ev...
#include "tss2_common.h"                    // for TSS2_RC_SUCCESS, BYTE
#include "tss2_tpm2_types.h"                // for TPM2B_DIGEST, TPM2_ALG_SHA1
#include "util/aux_util.h"                  // for SAFE_FREE

#define LOGMODULE tests
#include "util/log.h"

#define EXIT_SKIP 77

static bool big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

static uint8_t *file_to_buffer(const char *filename, size_t *size)
{
    uint8_t *eventlog = NULL;
    size_t alloc_size = UINT16_MAX;
    size_t alloc_buf_size;
    size_t n_alloc = 1;
    size_t file_size = 0;
    size_t read_size = 0;

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }
    *size = 0;
    eventlog = calloc(1, alloc_size);
    if (!eventlog)
        return NULL;
    read_size = fread(eventlog, 1, alloc_size, fp);
    file_size += read_size;
    alloc_buf_size = alloc_size;

    while (file_size == alloc_buf_size) {
        n_alloc += 1;
        uint8_t* tmp_buff = calloc(1, alloc_size * n_alloc);
        if (!tmp_buff) {
            free(eventlog);
            return NULL;
        }
        alloc_buf_size = alloc_size * n_alloc;
        memcpy(&tmp_buff[0], &eventlog[0], file_size);
        free(eventlog);
        eventlog = tmp_buff;
        read_size = fread(&eventlog[file_size], 1, alloc_size, fp);
        file_size += read_size;
    }
    *size = file_size;
    if (*size) {
        return eventlog;
    } else {
        return NULL;
    }
}

uint32_t pcr_list[9] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
uint32_t pcr_list2[1] = { 2  };

static void
check_eventlog(const char *file, uint32_t *pcr_list, size_t pcr_list_size, int n_events)
{
    TSS2_RC r;
    uint8_t *eventlog;
    size_t size;
    int i, n;
    char *json_string = NULL;
    json_object *json_event_list = NULL, *jso;
    IFAPI_EVENT event;

    /* Read file to get file size for comparison. */
    eventlog = file_to_buffer(file, &size);
    assert_non_null(eventlog);

    r = ifapi_get_tcg_firmware_event_list(file, pcr_list, pcr_list_size, &json_event_list);
    assert_int_equal (r, TSS2_RC_SUCCESS);

    json_string = strdup(json_object_to_json_string_ext(json_event_list, JSON_C_TO_STRING_PRETTY));
    assert_non_null(json_string);

    fprintf(stderr,"\n%s\n", json_string);

    n = json_object_array_length(json_event_list);

    for (i = 0; i < n; i++) {
        jso = json_object_array_get_idx(json_event_list, i);
        r = ifapi_json_IFAPI_EVENT_deserialize(jso, &event, DIGEST_CHECK_ERROR);
        assert_int_equal(r, TSS2_RC_SUCCESS);

        ifapi_cleanup_event(&event);
    }
    json_object_put(json_event_list);
    SAFE_FREE(json_string);
    SAFE_FREE(eventlog);
}

static void
check_eventlog_pcr0(const char *file, uint32_t *pcr_list, size_t pcr_list_size, int n_events)
{
    TSS2_RC r;
    uint8_t *eventlog;
    size_t size;
    json_object *json_event_list = NULL;
    IFAPI_PCR_REG pcrs[TPM2_MAX_PCRS];

    TPML_PCR_SELECTION pcr_selection =
        {
         .count = 1,
        .pcrSelections =
         {
          {
           .hash = TPM2_ALG_SHA1,
           .sizeofSelect = 3,
           .pcrSelect = { 1, 0, 0 } },
         }};

    TPM2B_DIGEST expected_pcr0 =
        {
         .size = 20,
         .buffer = { 0x15, 0xf4, 0xe6, 0xca, 0x45, 0x7d, 0x1a, 0xf6, 0xbc, 0x49,
                     0x51, 0x1a, 0x93, 0xba, 0x35, 0x00, 0xad, 0x69, 0xac, 0xc5 },
        };

    /* Read file to get file size for comparison. */
    eventlog = file_to_buffer(file, &size);
    assert_non_null(eventlog);

    r = ifapi_get_tcg_firmware_event_list(file, pcr_list, pcr_list_size, &json_event_list);
    assert_int_equal (r, TSS2_RC_SUCCESS);

    r = ifapi_calculate_pcrs(json_event_list, &pcr_selection, TPM2_ALG_SHA1, NULL, &pcrs[0]);
    assert_int_equal (r, TSS2_RC_SUCCESS);

    /* Compare with the pcr0 value got from system with HCRTM events */
    assert_true(!memcmp(&expected_pcr0.buffer[0], &pcrs[0].value.buffer[0], 20));

    json_object_put(json_event_list);
    SAFE_FREE(eventlog);
}

static void
check_bios_hcrtm(void **state)
{

#ifdef __FreeBSD__
    /* Free BSD does not support SM3 hashalg */
    skip();
#endif
    check_eventlog_pcr0("test/data/fapi/eventlog/binary_measurements_hcrtm.bin", &pcr_list[0], 9, 111);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_hcrtm.bin", &pcr_list[0], 1, 5);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_hcrtm.bin", &pcr_list[0], 9, 111);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_hcrtm.bin", NULL, 0, 0);
}

static void
check_bios_nuc(void **state)
{
    check_eventlog("test/data/fapi/eventlog/binary_measurements_nuc.bin", &pcr_list[0], 1, 2);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_nuc.bin", &pcr_list[0], 3, 4);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_nuc.bin", NULL, 0, 0);
}

static void
check_bios_pc_client(void **state)
{
    check_eventlog("test/data/fapi/eventlog/binary_measurements_pc_client.bin", &pcr_list[0], 1, 5);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_pc_client.bin", &pcr_list[0], 9, 31);
    check_eventlog("test/data/fapi/eventlog/binary_measurements_pc_client.bin", NULL, 0, 0);
}

static void
check_event_uefiservices(void **state)
{
    check_eventlog("test/data/fapi/eventlog/binary_measurements_nuc.bin", &pcr_list2[0], 1, 1);
    check_eventlog("test/data/fapi/eventlog/event-uefiservices.bin", NULL, 0, 0);
}

static void
check_event_uefiaction(void **state)
{
    check_eventlog("test/data/fapi/eventlog/event-uefiaction.bin", NULL, 0, 0);
}

static void
check_event_uefivar(void **state)
{
    check_eventlog("test/data/fapi/eventlog/event-uefivar.bin", NULL, 0, 0);
}

static void
check_event(void **state)
{
    check_eventlog("test/data/fapi/eventlog/event.bin", NULL, 0, 0);
}

static void
check_specid_vendordata(void **state)
{
    check_eventlog("test/data/fapi/eventlog/specid-vendordata.bin", NULL, 0, 0);
}

int
main(int argc, char *argv[])
{
    if (big_endian()) {
        return EXIT_SKIP;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_bios_hcrtm),
        cmocka_unit_test(check_bios_nuc),
        cmocka_unit_test(check_bios_pc_client),
        cmocka_unit_test(check_event_uefiservices),
        cmocka_unit_test(check_event_uefiaction),
        cmocka_unit_test(check_event_uefivar),
        cmocka_unit_test(check_event),
        cmocka_unit_test(check_specid_vendordata),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
