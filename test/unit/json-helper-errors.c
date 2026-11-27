/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../helper/cmocka_all.h"
#include "ifapi_macros.h"
#include "ipolicy_macros.h"
#include "json_helpers.h"
#include <stdlib.h>

static bool  fail_malloc, fail_strdup, fail_json;
void        *__real_malloc(size_t size);
char        *__real_strdup(const char *text);
json_object *__real_json_object_new_string(const char *text);

void *
__wrap_malloc(size_t size) {
    return fail_malloc ? NULL : __real_malloc(size);
}
char *
__wrap_strdup(const char *text) {
    return fail_strdup ? NULL : __real_strdup(text);
}
json_object *
__wrap_json_object_new_string(const char *text) {
    return fail_json ? NULL : __real_json_object_new_string(text);
}

static void
check_base_errors(void **state) {
    (void)state;
    json_object *json = NULL;
    char        *text = NULL;
    assert_int_equal(ifapi_json_char_serialize("value", NULL), TSS2_BASE_RC_BAD_REFERENCE);
    assert_int_equal(ifapi_json_char_deserialize(NULL, &text), TSS2_BASE_RC_BAD_REFERENCE);
    assert_null(text);
    assert_int_equal(ifapi_json_char_deserialize(NULL, NULL), TSS2_BASE_RC_BAD_REFERENCE);
    assert_int_equal(ifapi_json_UINT8_ARY_serialize(NULL, &json), TSS2_BASE_RC_BAD_REFERENCE);
    assert_null(json);
    UINT8_ARY invalid = { .size = 1 };
    assert_int_equal(ifapi_json_UINT8_ARY_serialize(&invalid, &json), TSS2_BASE_RC_BAD_VALUE);
    invalid.size = SIZE_MAX;
    assert_int_equal(ifapi_json_UINT8_ARY_serialize(&invalid, &json), TSS2_BASE_RC_BAD_VALUE);
}

static void
check_caller_layers(void **state) {
    (void)state;
    assert_int_equal(ifapi_call_base(ifapi_json_char_serialize("value", NULL)),
                     TSS2_FAPI_RC_BAD_REFERENCE);
    assert_int_equal(ipolicy_call_base(ifapi_json_char_serialize("value", NULL)),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(ifapi_call_base(TSS2_RC_SUCCESS), TSS2_RC_SUCCESS);
    assert_int_equal(ipolicy_call_base(TSS2_ESYS_RC_BAD_VALUE), TSS2_ESYS_RC_BAD_VALUE);
    assert_int_equal(ifapi_call_base(TSS2_ESYS_RC_BAD_VALUE), TSS2_ESYS_RC_BAD_VALUE);
}

static void
check_allocations(void **state) {
    (void)state;
    json_object *json = NULL;
    fail_json = true;
    assert_int_equal(ifapi_json_char_serialize("value", &json), TSS2_BASE_RC_MEMORY);
    assert_null(json);
    UINT8_ARY empty = { 0 };
    assert_int_equal(ifapi_json_UINT8_ARY_serialize(&empty, &json), TSS2_BASE_RC_MEMORY);
    assert_null(json);
    fail_json = false;
    fail_malloc = true;
    assert_int_equal(ifapi_json_UINT8_ARY_serialize(&empty, &json), TSS2_BASE_RC_MEMORY);
    assert_null(json);
    fail_malloc = false;
    assert_int_equal(ifapi_json_char_serialize("value", &json), TSS2_RC_SUCCESS);
    char *text = NULL;
    fail_strdup = true;
    assert_int_equal(ifapi_json_char_deserialize(json, &text), TSS2_BASE_RC_MEMORY);
    assert_null(text);
    fail_strdup = false;
    assert_int_equal(ifapi_json_char_deserialize(json, &text), TSS2_RC_SUCCESS);
    assert_string_equal(text, "value");
    free(text);
    json_object_put(json);
    uint8_t   bytes[] = { 0x01, 0xab };
    UINT8_ARY buffer = { .size = sizeof(bytes), .buffer = bytes };
    assert_int_equal(ifapi_json_UINT8_ARY_serialize(&buffer, &json), TSS2_RC_SUCCESS);
    assert_string_equal(json_object_get_string(json), "01ab");
    json_object_put(json);
}

int
main(void) {
    const struct CMUnitTest tests[]
        = { cmocka_unit_test(check_base_errors), cmocka_unit_test(check_caller_layers),
            cmocka_unit_test(check_allocations) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
