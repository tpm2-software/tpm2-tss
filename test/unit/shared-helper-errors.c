/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../helper/cmocka_all.h"
#include "ifapi_macros.h"
#include "ipolicy_macros.h"
#include "tpm_json_deserialize.h"
#include "tpm_json_serialize.h"
#include "tss2_crypto.h"
#include "tss2_helpers.h"
#include <stdlib.h>

static bool fail_calloc;
void       *__real_calloc(size_t count, size_t size);
void *
__wrap_calloc(size_t count, size_t size) {
    return fail_calloc ? NULL : __real_calloc(count, size);
}

static void
check_json_layers(void **state) {
    (void)state;
    json_object *json = json_object_new_string("0x10000");
    assert_non_null(json);
    UINT16 value;
    assert_int_equal(ifapi_json_UINT16_deserialize(json, &value), TSS2_BASE_RC_BAD_VALUE);
    assert_int_equal(ifapi_call_base(ifapi_json_UINT16_deserialize(json, &value)),
                     TSS2_FAPI_RC_BAD_VALUE);
    assert_int_equal(ipolicy_call_base(ifapi_json_UINT16_deserialize(json, &value)),
                     TSS2_POLICY_RC_BAD_VALUE);
    json_object_put(json);
    json = NULL;
    assert_int_equal(ifapi_json_TPM2_ALG_ID_serialize(UINT16_MAX, &json), TSS2_BASE_RC_BAD_VALUE);
    assert_null(json);
}

static void
check_crypto_and_lists(void **state) {
    (void)state;
    assert_int_equal(tss2_crypto_hash_start(NULL, TPM2_ALG_SHA256), TSS2_BASE_RC_BAD_REFERENCE);
    assert_int_equal(ipolicy_call_base(tss2_crypto_hash_start(NULL, TPM2_ALG_SHA256)),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(ifapi_call_base(tss2_crypto_hash_start(NULL, TPM2_ALG_SHA256)),
                     TSS2_FAPI_RC_BAD_REFERENCE);
    IFAPI_CRYPTO_CONTEXT_BLOB *ctx = NULL;
    assert_int_equal(tss2_crypto_hash_start(&ctx, TPM2_ALG_SHA256), TSS2_RC_SUCCESS);
    const uint8_t data[] = { 0x42 };
    assert_int_equal(tss2_crypto_hash_update(ctx, data, sizeof(data)), TSS2_RC_SUCCESS);
    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    size_t  size = sizeof(digest);
    assert_int_equal(tss2_crypto_hash_finish(&ctx, digest, &size), TSS2_RC_SUCCESS);
    assert_null(ctx);
    assert_int_equal(size, TPM2_SHA256_DIGEST_SIZE);
    NODE_OBJECT_T *list = NULL;
    fail_calloc = true;
    assert_int_equal(append_object_to_list(NULL, &list), TSS2_BASE_RC_MEMORY);
    fail_calloc = false;
    assert_null(list);
}

static void
check_mu_layer(void **state) {
    (void)state;
    TPMT_PUBLIC public = { .type = TPM2_ALG_RSA, .nameAlg = TPM2_ALG_SHA256 };
    public.authPolicy.size = UINT16_MAX;
    TPM2B_NAME name;
    assert_int_equal(ifapi_get_name(&public, &name), TSS2_MU_RC_INSUFFICIENT_BUFFER);
    assert_int_equal(ifapi_call_base(ifapi_get_name(&public, &name)),
                     TSS2_MU_RC_INSUFFICIENT_BUFFER);
    assert_int_equal(ipolicy_call_base(ifapi_get_name(&public, &name)),
                     TSS2_MU_RC_INSUFFICIENT_BUFFER);
}

int
main(void) {
    const struct CMUnitTest tests[]
        = { cmocka_unit_test(check_json_layers), cmocka_unit_test(check_crypto_and_lists),
            cmocka_unit_test(check_mu_layer) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
