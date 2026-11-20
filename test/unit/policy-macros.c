/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../helper/cmocka_all.h"
#include "ifapi_macros.h"
#include "ipolicy_macros.h"
#include <stdlib.h>

#define LOGMODULE test
#include "util/log.h"

static bool fail_strdup;
char       *__real_strdup(const char *text);

char *
__wrap_strdup(const char *text) {
    return fail_strdup ? NULL : __real_strdup(text);
}

static TSS2_RC
policy_oom(void *pointer) {
    ipolicy_check_oom(pointer);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
fapi_oom(void *pointer) {
    ifapi_check_oom(pointer);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
policy_state(int state) {
    switch (state) { ipolicy_statecasedefault(state);
    }
}

static TSS2_RC
fapi_state(int state) {
    switch (state) { ifapi_statecasedefault(state);
    }
}

static TSS2_RC
policy_strdup(const char *text, char **copy) {
    TSS2_RC r = TSS2_RC_SUCCESS;
    ipolicy_strdup_check(*copy, text, r, cleanup);
cleanup:
    return r;
}

static TSS2_RC
fapi_strdup(const char *text, char **copy) {
    TSS2_RC r = TSS2_RC_SUCCESS;
    ifapi_strdup_check(*copy, text, r, cleanup);
cleanup:
    return r;
}

static TSS2_RC
policy_retry(TSS2_RC r) {
    ipolicy_return_try_again(r);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
policy_error(TSS2_RC r) {
    ipolicy_try_again_or_error(r, "Policy error");
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
policy_error_goto(TSS2_RC r, bool *cleaned) {
    ipolicy_try_again_or_error_goto(r, "Policy error", cleanup);
    return TSS2_RC_SUCCESS;
cleanup:
    *cleaned = true;
    return r;
}

static TSS2_RC
fapi_retry(TSS2_RC r) {
    ifapi_return_try_again(r);
    return TSS2_RC_SUCCESS;
}

static void
test_error_layers(void **state) {
    (void)state;
    assert_int_equal(policy_oom(NULL), TSS2_POLICY_RC_MEMORY);
    assert_int_equal(fapi_oom(NULL), TSS2_FAPI_RC_MEMORY);
    assert_int_equal(policy_state(-1), TSS2_POLICY_RC_BAD_SEQUENCE);
    assert_int_equal(fapi_state(-1), TSS2_FAPI_RC_BAD_SEQUENCE);
    char *copy = NULL;
    fail_strdup = true;
    assert_int_equal(policy_strdup("policy", &copy), TSS2_POLICY_RC_MEMORY);
    assert_null(copy);
    assert_int_equal(fapi_strdup("fapi", &copy), TSS2_FAPI_RC_MEMORY);
    assert_null(copy);
    fail_strdup = false;
    assert_int_equal(policy_strdup("policy", &copy), TSS2_RC_SUCCESS);
    assert_string_equal(copy, "policy");
    free(copy);
    copy = NULL;
    assert_int_equal(policy_strdup(NULL, &copy), TSS2_RC_SUCCESS);
    assert_null(copy);
}

static void
test_retry_layers(void **state) {
    (void)state;
    const TSS2_RC layers[] = { TSS2_POLICY_RC_LAYER, TSS2_FEATURE_RC_LAYER, TSS2_ESAPI_RC_LAYER,
                               TSS2_SYS_RC_LAYER, TSS2_TCTI_RC_LAYER };
    for (size_t i = 0; i < sizeof(layers) / sizeof(layers[0]); ++i) {
        TSS2_RC retry = layers[i] | TSS2_BASE_RC_TRY_AGAIN;
        bool    cleaned = false;
        assert_int_equal(policy_retry(retry), retry);
        assert_int_equal(policy_error(retry), retry);
        assert_int_equal(policy_error_goto(retry, &cleaned), retry);
        assert_false(cleaned);
        assert_int_equal(fapi_retry(retry), TSS2_FAPI_RC_TRY_AGAIN);
    }
    bool cleaned = false;
    assert_int_equal(policy_error(TSS2_ESYS_RC_BAD_VALUE), TSS2_ESYS_RC_BAD_VALUE);
    assert_int_equal(policy_error_goto(TSS2_ESYS_RC_BAD_VALUE, &cleaned), TSS2_ESYS_RC_BAD_VALUE);
    assert_true(cleaned);
    cleaned = false;
    assert_int_equal(policy_error_goto(TSS2_RC_SUCCESS, &cleaned), TSS2_RC_SUCCESS);
    assert_false(cleaned);
}

int
main(void) {
    const struct CMUnitTest tests[]
        = { cmocka_unit_test(test_error_layers), cmocka_unit_test(test_retry_layers) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
