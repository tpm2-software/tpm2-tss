/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "../helper/cmocka_all.h"
#include "ifapi_policy.h"
#include "ifapi_policy_store.h"

static const char policy_json[] = "{\"description\":\"string policy\",\"policy\":["
                                  "{\"type\":\"POLICYCOMMANDCODE\",\"code\":349}]}";
static unsigned   read_calls;

TSS2_RC
ifapi_policy_store_load_async(IFAPI_POLICY_STORE *store, IFAPI_IO *io, const char *path) {
    (void)store;
    (void)io;
    assert_string_equal(path, "policy/test");
    return TSS2_RC_SUCCESS;
}

TSS2_RC
ifapi_policy_store_load_finish(IFAPI_POLICY_STORE *store, IFAPI_IO *io, char **policy) {
    (void)store;
    (void)io;
    if (read_calls++ == 0)
        return TSS2_FAPI_RC_TRY_AGAIN;
    *policy = strdup(policy_json);
    return *policy ? TSS2_RC_SUCCESS : TSS2_FAPI_RC_MEMORY;
}

static void
check_calculation(bool from_store) {
    IFAPI_POLICY_CTX context = { 0 };
    char            *policy = from_store ? NULL : strdup(policy_json);
    TPM2B_DIGEST     digest;
    TSS2_RC          r;
    read_calls = 0;
    unsigned retries = 0;
    do {
        r = ifapi_calculate_tree_ex(&context, NULL, NULL, from_store ? "policy/test" : NULL,
                                    &policy, TPM2_ALG_SHA256, &digest);
        if (r == TSS2_FAPI_RC_TRY_AGAIN && policy)
            assert_string_equal(policy, policy_json);
        assert_true(++retries < 20);
    } while (r == TSS2_FAPI_RC_TRY_AGAIN);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    assert_null(context.tss2_policy_ctx);
    assert_int_equal(context.state, POLICY_INIT);
    assert_non_null(policy);
    assert_non_null(strstr(policy, "policyDigests"));
    assert_int_equal(digest.size, 32);

    /* The returned JSON survives Finalize and can initialize another context. */
    TSS2_POLICY_CTX *ctx = NULL;
    TPM2B_DIGEST     restored;
    assert_int_equal(Tss2_PolicyInit(policy, TPM2_ALG_SHA256, &ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyGetCalculatedDigest(ctx, &restored), TSS2_RC_SUCCESS);
    assert_int_equal(restored.size, digest.size);
    assert_memory_equal(restored.buffer, digest.buffer, digest.size);
    Tss2_PolicyFinalize(&ctx);
    free(policy);
}

static void
test_calculate_string(void **state) {
    (void)state;
    check_calculation(false);
    check_calculation(true);
}

static void
test_provision_profile_policy_strings(void **state) {
    (void)state;
    FAPI_CONTEXT *context = calloc(1, sizeof(*context));
    assert_non_null(context);
    IFAPI_PROFILE *profile = &context->profiles.default_profile;
    profile->nameAlg = TPM2_ALG_SHA256;
    char **slots[] = { &profile->ek_policy, &profile->srk_policy, &profile->eh_policy,
                       &profile->sh_policy, &profile->lockout_policy };
    for (size_t i = 0; i < 5; i++) {
        *slots[i] = strdup(policy_json);
        assert_non_null(*slots[i]);
    }
    context->profiles.num_profiles = 1;
    context->profiles.default_name = strdup("test");
    context->profiles.profiles = calloc(1, sizeof(*context->profiles.profiles));
    assert_non_null(context->profiles.default_name);
    assert_non_null(context->profiles.profiles);
    context->profiles.profiles[0].name = strdup("test");
    assert_non_null(context->profiles.profiles[0].name);
    context->profiles.profiles[0].profile = *profile;
    TSS2_RC  r;
    unsigned retries = 0;
    do {
        r = ifapi_instantiate_profile_policies(context);
        assert_true(++retries < 50);
    } while (r == TSS2_FAPI_RC_TRY_AGAIN);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    assert_null(context->policy.tss2_policy_ctx);
    IFAPI_PROFILE *stored = &context->profiles.profiles[0].profile;
    char         **stored_slots[] = { &stored->ek_policy, &stored->srk_policy, &stored->eh_policy,
                                      &stored->sh_policy, &stored->lockout_policy };
    for (size_t i = 0; i < 5; i++) {
        assert_ptr_equal(context->cmd.Provision.policies.policies[i], slots[i]);
        assert_ptr_equal(*stored_slots[i], *slots[i]);
        assert_non_null(strstr(*stored_slots[i], "policyDigests"));
        free(*stored_slots[i]);
        *stored_slots[i] = NULL;
        *slots[i] = NULL;
    }
    free(context->profiles.profiles[0].name);
    free(context->profiles.profiles);
    free(context->profiles.default_name);
    free(context);
}

static void
test_authorize_string(void **state) {
    (void)state;
    char *policy = strdup(policy_json);
    assert_non_null(policy);
    char          *original = policy;
    TPMT_SIGNATURE signature = { .sigAlg = TPM2_ALG_RSASSA };
    signature.signature.rsassa.hash = TPM2_ALG_SHA256;
    TPMT_PUBLIC key = { .type = TPM2_ALG_RSA, .nameAlg = TPM2_ALG_SHA256 };
    key.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    key.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    key.parameters.rsaDetail.keyBits = 2048;
    TPM2B_DIGEST ref = { .size = 1, .buffer = { 0x42 } };
    assert_int_equal(ifapi_policy_add_authorization(&policy, NULL, &ref, &key),
                     TSS2_FAPI_RC_BAD_REFERENCE);
    assert_ptr_equal(policy, original);
    assert_string_equal(policy, policy_json);

    assert_int_equal(ifapi_policy_add_authorization(&policy, &signature, &ref, &key),
                     TSS2_RC_SUCCESS);
    assert_non_null(strstr(policy, "policyAuthorizations"));
    bool           found = false;
    TPMT_SIGNATURE result = { 0 };
    assert_int_equal(ifapi_policy_get_authorization(policy, &key, &ref, &found, &result),
                     TSS2_RC_SUCCESS);
    assert_true(found);
    assert_int_equal(result.sigAlg, signature.sigAlg);
    ref.buffer[0]++;
    assert_int_equal(ifapi_policy_get_authorization(policy, &key, &ref, &found, NULL),
                     TSS2_RC_SUCCESS);
    assert_false(found);
    free(policy);
}

static void
test_calculation_error_keeps_string(void **state) {
    (void)state;
    IFAPI_POLICY_CTX context = { 0 };
    char            *policy = strdup("{\"description\":\"invalid\",\"policy\":42}");
    assert_non_null(policy);
    char        *original = policy;
    TPM2B_DIGEST digest;
    assert_int_equal(
        ifapi_calculate_tree_ex(&context, NULL, NULL, NULL, &policy, TPM2_ALG_SHA256, &digest),
        TSS2_FAPI_RC_BAD_VALUE);
    assert_ptr_equal(policy, original);
    assert_null(context.tss2_policy_ctx);
    assert_int_equal(context.state, POLICY_INIT);
    free(policy);
}

static void
test_authorization_error_clears_found(void **state) {
    (void)state;
    TPMT_PUBLIC    key = { .type = TPM2_ALG_RSA };
    TPMT_SIGNATURE signature = { .sigAlg = TPM2_ALG_NULL };
    bool           found = true;
    assert_int_equal(
        ifapi_policy_get_authorization("{\"policy\":[]}", &key, NULL, &found, &signature),
        TSS2_FAPI_RC_BAD_VALUE);
    assert_false(found);
    assert_int_equal(signature.sigAlg, TPM2_ALG_NULL);
    found = true;
    assert_int_equal(ifapi_policy_get_authorization(NULL, &key, NULL, &found, NULL),
                     TSS2_FAPI_RC_BAD_REFERENCE);
    assert_false(found);
    assert_int_equal(ifapi_policy_get_authorization(policy_json, &key, NULL, NULL, NULL),
                     TSS2_FAPI_RC_BAD_REFERENCE);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_calculate_string),
        cmocka_unit_test(test_authorize_string),
        cmocka_unit_test(test_authorization_error_clears_found),
        cmocka_unit_test(test_provision_profile_policy_strings),
        cmocka_unit_test(test_calculation_error_keeps_string),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
