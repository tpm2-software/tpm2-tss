/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <limits.h> // for PATH_MAX
#include <stddef.h> // for NULL, size_t
#include <stdio.h>  // for fclose, fopen, fprintf, fread
#include <stdlib.h> // for calloc
#include <string.h> // for memcpy, memset

#include "../helper/cmocka_all.h" // for assert_int_equal, assert_s...
#include "ipolicy_types.h"        // for borrowed policy construction
#include "tss2_common.h"          // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_policy.h"          // for TSS2_POLICY_PCR_SELECTION
#include "tss2_tpm2_types.h"      // for TPM2B_DIGEST, TPMS_PCR_SEL...

#define LOGMODULE test
#include "test/data/test-fapi-policies.h" // for policy_digests, _test_fapi...
#include "util/aux_util.h"                // for UNUSED, SAFE_FREE, ARRAY_LEN
#include "util/log.h"                     // for LOG_ERROR

#define TEST_LAYER                 TSS2_RC_LAYER(19)
#define TSS2_RC_TEST_NOT_SUPPORTED ((TSS2_RC)(TEST_LAYER | TSS2_BASE_RC_NOT_SUPPORTED))

static char *
read_all(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0) {
        LOG_ERROR("Could not determine size of file %s.", path);
        fclose(f);
        return NULL;
    }

    fseek(f, 0, SEEK_SET);

    char *buffer = calloc(1, fsize + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    size_t count_read = fread(buffer, fsize, 1, f);
    fclose(f);
    if (count_read != 1) {
        return NULL;
    }

    return buffer;
}

TSS2_RC
policy_cb_pcr(TSS2_POLICY_PCR_SELECTION *pcr_selection,
              TPML_PCR_SELECTION        *out_pcr_selection,
              TPML_DIGEST               *out_pcr_digests,
              void                      *ctx) {
    TPML_PCR_SELECTION in_pcr_selection = { 0 };
    TPML_DIGEST        pcr_digests = { 0 };

    /* Raw selector without bank specifier, figure out bank and copy
     * the raw selector over to the input selector */
    if (pcr_selection->type == TSS2_POLICY_PCR_SELECTOR_PCR_SELECT) {
        /* Only one bank will be used. A default algorithm of TPM2_ALG_SHA256 */
        in_pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
        in_pcr_selection.count = 1;
        memcpy(in_pcr_selection.pcrSelections[0].pcrSelect,
               pcr_selection->selections.pcr_select.pcrSelect,
               sizeof(pcr_selection->selections.pcr_select.pcrSelect));
        in_pcr_selection.pcrSelections[0].sizeofSelect
            = pcr_selection->selections.pcr_select.sizeofSelect;
    } else {
        /* we have specified selection with bank, so just copy it. */
        in_pcr_selection = pcr_selection->selections.pcr_selection;
    }

    /* This is in place of something like an ESYS_PCR_Read() */
    /* For each bank */
    UINT32 count;
    for (count = 0; count < in_pcr_selection.count; count++) {

        /* Get the selection */
        TPMS_PCR_SELECTION pcr_select = in_pcr_selection.pcrSelections[count];

        /* for each selection byte */
        UINT32 i;
        for (i = 0; i < pcr_select.sizeofSelect; i++) {

            size_t j;
            /* for each selection bit in the byte */
            for (j = 0; j < sizeof(pcr_select.pcrSelect[i]) * 8; j++) {
                if (pcr_select.pcrSelect[i] & 1 << j) {

                    /* fake a read */
                    if (pcr_select.hash == TPM2_ALG_SHA256) {
                        pcr_digests.digests[pcr_digests.count].size = 32;
                    } else {
                        LOG_ERROR("Only SHA256 is supported, got: 0x%x", pcr_select.hash);
                        return TSS2_RC_TEST_NOT_SUPPORTED;
                    }

                    memset(pcr_digests.digests[pcr_digests.count].buffer, 0,
                           pcr_digests.digests[pcr_digests.count].size);
                    pcr_digests.count++;
                }
            }
        }
    }

    /* copy to caller */
    *out_pcr_selection = in_pcr_selection;
    *out_pcr_digests = pcr_digests;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
policy_cb_nvpublic(const char      *path,
                   TPMI_RH_NV_INDEX nv_index,
                   TPMS_NV_PUBLIC  *nv_public,
                   void            *userdata) {
    UNUSED(path);
    UNUSED(nv_index);
    UNUSED(nv_public);
    UNUSED(userdata);

    LOG_ERROR("Policy NV Public Callback Not Supported");

    return TSS2_RC_TEST_NOT_SUPPORTED;
}

static void
bin2hex(const unsigned char *bin, size_t len, char *out) {
    size_t i;

    if (bin == NULL || len == 0) {
        return;
    }

    for (i = 0; i < len; i++) {
        out[i * 2] = "0123456789abcdef"[bin[i] >> 4];
        out[i * 2 + 1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static void
test_policy_instantiate(void **state) {
    TSS2_POLICY_CALC_CALLBACKS callbacks
        = { .cbpcr = policy_cb_pcr, .cbnvpublic = policy_cb_nvpublic };

    unsigned i;
    for (i = 0; i < ARRAY_LEN(_test_fapi_policy_policies); i++) {
        policy_digests *p = &_test_fapi_policy_policies[i];

        char abs_path[PATH_MAX];
        snprintf(abs_path, sizeof(abs_path), TOP_SOURCEDIR "/test/data/fapi%s.json", p->path);

        fprintf(stderr, "Calculating policy (%u): %s\n", i, p->path);

        unsigned expected_hash_size = 0;
        /* buffer for displaying a hash as a hex string */
        char             hexdigest[2 * sizeof(TPMU_HA) + 1] = { 0 };
        TPM2B_DIGEST     digest = { 0 };
        TSS2_POLICY_CTX *ctx = NULL;

        /* for each hash alg set... */
        TPM2_ALG_ID halgs[] = { TPM2_ALG_SHA256, TPM2_ALG_SHA384 };

        unsigned j;
        for (j = 0; j < ARRAY_LEN(halgs); j++) {
            TPM2_ALG_ID halg = halgs[j];

            if (halg == TPM2_ALG_SHA256) {
                if (!p->sha256) {
                    continue;
                }
                expected_hash_size = 32;
            } else if (halg == TPM2_ALG_SHA384) {
                if (!p->sha384) {
                    continue;
                }
                expected_hash_size = 48;
            }

            char *json = read_all(abs_path);
            assert_non_null(json);

            TSS2_RC rc = Tss2_PolicyInit(json, halg, &ctx);
            SAFE_FREE(json);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            rc = Tss2_PolicySetCalcCallbacks(ctx, &callbacks);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            rc = Tss2_PolicyCalculate(ctx);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            rc = Tss2_PolicyGetCalculatedDigest(ctx, &digest);
            assert_int_equal(rc, TSS2_RC_SUCCESS);
            assert_int_equal(digest.size, expected_hash_size);

            if (halg == TPM2_ALG_SHA256) {
                bin2hex(digest.buffer, digest.size, hexdigest);
                assert_string_equal(p->sha256, hexdigest);
            } else if (halg == TPM2_ALG_SHA384) {
                bin2hex(digest.buffer, digest.size, hexdigest);
                assert_string_equal(p->sha384, hexdigest);
            }

            /* Get the calculated policy digest */
            char  *buffer = NULL;
            size_t size = 0;
            rc = Tss2_PolicyGetCalculatedJSON(ctx, NULL, &size);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            buffer = calloc(1, size);
            assert_non_null(buffer);

            rc = Tss2_PolicyGetCalculatedJSON(ctx, buffer, &size);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            /* done with that policy */
            Tss2_PolicyFinalize(&ctx);

            /* create one from calculated JSON */
            rc = Tss2_PolicyInit(buffer, halg, &ctx);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            rc = Tss2_PolicyCalculate(ctx);
            assert_int_equal(rc, TSS2_RC_SUCCESS);

            rc = Tss2_PolicyGetCalculatedDigest(ctx, &digest);
            assert_int_equal(rc, TSS2_RC_SUCCESS);
            assert_int_equal(digest.size, expected_hash_size);

            if (halg == TPM2_ALG_SHA256) {
                bin2hex(digest.buffer, digest.size, hexdigest);
                assert_string_equal(p->sha256, hexdigest);
            } else if (halg == TPM2_ALG_SHA384) {
                bin2hex(digest.buffer, digest.size, hexdigest);
                assert_string_equal(p->sha384, hexdigest);
            }

            SAFE_FREE(json);
            SAFE_FREE(buffer);
            Tss2_PolicyFinalize(&ctx);
        } /* end for each hash algorithm */
    } /* end for each policy file */
} /* end of cmocka test */

static TSS2_RC
execute_action_retry(const char *action, void *userdata) {
    unsigned *calls = userdata;
    assert_string_equal(action, "test");
    return ++*calls == 1 ? TSS2_POLICY_RC_TRY_AGAIN : TSS2_RC_SUCCESS;
}

static void
test_policy_execute_async(void **state) {
    UNUSED(state);
    TSS2_POLICY_CTX *ctx = NULL;
    /* PolicyAction does not issue TPM commands, so no TPM connection is needed. */
    char                       esys_storage;
    ESYS_CONTEXT              *esys = (ESYS_CONTEXT *)&esys_storage;
    unsigned                   calls = 0;
    TSS2_POLICY_EXEC_CALLBACKS callbacks = {
        .cbaction = execute_action_retry,
        .cbaction_userdata = &calls,
    };

    assert_int_equal(Tss2_PolicyInit("{\"description\":\"test\",\"policy\":[{\"type\":"
                                     "\"POLICYACTION\",\"action\":\"test\"}]}",
                                     TPM2_ALG_SHA256, &ctx),
                     TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_BAD_SEQUENCE);
    assert_int_equal(Tss2_PolicyExecute_Async(ctx), TSS2_POLICY_RC_POLICY_NOT_CALCULATED);
    assert_int_equal(Tss2_PolicyCalculate(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicySetExecCallbacks(ctx, &callbacks), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Async(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(calls, 0);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_NONE), TSS2_POLICY_RC_BAD_VALUE);
    assert_int_equal(Tss2_PolicyExecute_Async(ctx), TSS2_POLICY_RC_BAD_SEQUENCE);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_TRY_AGAIN);
    assert_int_equal(calls, 1);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_PASSWORD), TSS2_RC_SUCCESS);
    assert_int_equal(calls, 2);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_BAD_SEQUENCE);
    assert_int_equal(Tss2_PolicySetExecCallbacks(ctx, NULL), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Async(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_NULL_CALLBACK);
    assert_int_equal(Tss2_PolicyExecute_Finish(ctx, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_BAD_SEQUENCE);
    assert_int_equal(Tss2_PolicySetExecCallbacks(ctx, &callbacks), TSS2_RC_SUCCESS);
    calls = 0;
    assert_int_equal(Tss2_PolicyExecute(ctx, esys, ESYS_TR_PASSWORD), TSS2_RC_SUCCESS);
    assert_int_equal(calls, 2);
    Tss2_PolicyFinalize(&ctx);
}

/* Each frame borrows the same policy but owns independent engine/callback state. */
static void
test_policy_set_policy_execute(void **state) {
    UNUSED(state);
    TPML_POLICYELEMENTS *elements = calloc(1, sizeof(*elements) + sizeof(TPMT_POLICYELEMENT));
    assert_non_null(elements);
    elements->count = 1;
    elements->elements[0].type = POLICYACTION;
    elements->elements[0].element.PolicyAction.action = "test";
    TPMS_POLICY policy = { .policy = elements };
    policy.policyDigests.count = 1;
    policy.policyDigests.digests[0].hashAlg = TPM2_ALG_SHA256;
    TSS2_POLICY_CTX           *first = NULL, *second = NULL;
    unsigned                   first_calls = 0, second_calls = 0;
    TSS2_POLICY_EXEC_CALLBACKS callbacks = {
        .cbaction = execute_action_retry,
        .cbaction_userdata = &first_calls,
    };
    char          esys_storage;
    ESYS_CONTEXT *esys = (ESYS_CONTEXT *)&esys_storage;

    assert_int_equal(Tss2_PolicySetPolicy(&policy, TPM2_ALG_SHA256, &first), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicySetPolicy(&policy, TPM2_ALG_SHA256, &second), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicySetExecCallbacks(first, &callbacks), TSS2_RC_SUCCESS);
    callbacks.cbaction_userdata = &second_calls;
    assert_int_equal(Tss2_PolicySetExecCallbacks(second, &callbacks), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Async(first), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Async(second), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyExecute_Finish(first, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_TRY_AGAIN);
    assert_int_equal(Tss2_PolicyExecute_Finish(second, esys, ESYS_TR_PASSWORD),
                     TSS2_POLICY_RC_TRY_AGAIN);
    assert_int_equal(Tss2_PolicyExecute_Finish(first, esys, ESYS_TR_PASSWORD), TSS2_RC_SUCCESS);
    Tss2_PolicyFinalize(&first);
    assert_int_equal(Tss2_PolicyExecute_Finish(second, esys, ESYS_TR_PASSWORD), TSS2_RC_SUCCESS);
    assert_int_equal(first_calls, 2);
    assert_int_equal(second_calls, 2);
    Tss2_PolicyFinalize(&second);
    assert_string_equal(elements->elements[0].element.PolicyAction.action, "test");
    free(elements);
}

static void
test_cached_policy_digest_metadata(void **state) {
    UNUSED(state);
    TPMS_POLICY policy = { 0 };
    policy.policyDigests.count = 2;
    policy.policyDigests.digests[0].hashAlg = TPM2_ALG_SHA1;
    memset(policy.policyDigests.digests[0].digest.sha1, 0x11, 20);
    policy.policyDigests.digests[1].hashAlg = TPM2_ALG_SHA256;
    memset(policy.policyDigests.digests[1].digest.sha256, 0x22, 32);
    TSS2_POLICY_CTX *ctx = NULL;
    size_t           digest_idx = 99, hash_size = 99;
    TPM2B_DIGEST     digest;

    assert_int_equal(Tss2_PolicySetPolicy(&policy, TPM2_ALG_SHA256, &ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyGetDigestIdx(ctx, &digest_idx, &hash_size), TSS2_RC_SUCCESS);
    assert_int_equal(digest_idx, 1);
    assert_int_equal(hash_size, 32);
    assert_int_equal(Tss2_PolicyCalculate_Async(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyCalculate_Finish(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyGetDigestIdx(ctx, &digest_idx, &hash_size), TSS2_RC_SUCCESS);
    assert_int_equal(digest_idx, 1);
    assert_int_equal(hash_size, 32);
    assert_int_equal(Tss2_PolicyGetCalculatedDigest(ctx, &digest), TSS2_RC_SUCCESS);
    assert_int_equal(digest.size, 32);
    assert_memory_equal(digest.buffer, policy.policyDigests.digests[1].digest.sha256, 32);

    assert_int_equal(Tss2_PolicySetHashAlg(ctx, TPM2_ALG_SHA1), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyCalculate_Async(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyCalculate_Finish(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyGetDigestIdx(ctx, &digest_idx, &hash_size), TSS2_RC_SUCCESS);
    assert_int_equal(digest_idx, 0);
    assert_int_equal(hash_size, 20);
    assert_int_equal(Tss2_PolicyGetCalculatedDigest(ctx, &digest), TSS2_RC_SUCCESS);
    assert_int_equal(digest.size, 20);
    assert_memory_equal(digest.buffer, policy.policyDigests.digests[0].digest.sha1, 20);
    Tss2_PolicyFinalize(&ctx);
}

static TSS2_RC
policy_cb_pcr_retry(TSS2_POLICY_PCR_SELECTION *selection,
                    TPML_PCR_SELECTION        *out_selection,
                    TPML_DIGEST               *out_digest,
                    void                      *userdata) {
    unsigned *calls = userdata;
    if (++*calls == 1)
        return TSS2_POLICY_RC_TRY_AGAIN;
    return policy_cb_pcr(selection, out_selection, out_digest, NULL);
}

static void
test_policy_calculation_retry(void **state) {
    UNUSED(state);
    TSS2_POLICY_CTX           *ctx = NULL;
    unsigned                   calls = 0;
    TSS2_POLICY_CALC_CALLBACKS callbacks = {
        .cbpcr = policy_cb_pcr_retry,
        .cbpcr_userdata = &calls,
    };
    assert_int_equal(
        Tss2_PolicyInit("{\"description\":\"PCR "
                        "retry\",\"policy\":[{\"type\":\"POLICYPCR\",\"currentPCRs\":[16]}]}",
                        TPM2_ALG_SHA256, &ctx),
        TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicySetCalcCallbacks(ctx, &callbacks), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyCalculate_Async(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyCalculate_Finish(ctx), TSS2_POLICY_RC_TRY_AGAIN);
    TPM2B_DIGEST digest;
    assert_int_equal(Tss2_PolicyGetCalculatedDigest(ctx, &digest),
                     TSS2_POLICY_RC_POLICY_NOT_CALCULATED);
    assert_int_equal(Tss2_PolicyCalculate_Finish(ctx), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyGetCalculatedDigest(ctx, &digest), TSS2_RC_SUCCESS);
    assert_int_equal(digest.size, 32);
    assert_int_equal(calls, 2);
    Tss2_PolicyFinalize(&ctx);
}

static void
test_policy_authorization(void **state) {
    UNUSED(state);
    TPMS_POLICY    policy = { 0 };
    TPMT_SIGNATURE signature = { .sigAlg = TPM2_ALG_RSASSA };
    TPMT_PUBLIC    key = { .type = TPM2_ALG_RSA, .nameAlg = TPM2_ALG_SHA256 };
    TPM2B_DIGEST   ref = { .size = 1, .buffer = { 0x42 } };
    assert_int_equal(Tss2_PolicyAddAuthorization(NULL, &signature, ref, &key),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(Tss2_PolicyAddAuthorization(&policy, NULL, ref, &key),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(Tss2_PolicyAddAuthorization(&policy, &signature, ref, NULL),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    TPM2B_DIGEST invalid_ref = { .size = sizeof(ref.buffer) + 1 };
    assert_int_equal(Tss2_PolicyAddAuthorization(&policy, &signature, invalid_ref, &key),
                     TSS2_POLICY_RC_BAD_VALUE);
    assert_null(policy.policyAuthorizations);
    for (unsigned i = 0; i < 2; ++i) {
        ref.buffer[0] = 0x42 + i;
        assert_int_equal(Tss2_PolicyAddAuthorization(&policy, &signature, ref, &key),
                         TSS2_RC_SUCCESS);
    }
    /* The API retains copies, including entries present before an append. */
    ref.buffer[0] = 0;
    signature.sigAlg = TPM2_ALG_NULL;
    key.nameAlg = TPM2_ALG_SHA1;
    assert_int_equal(policy.policyAuthorizations->count, 2);
    for (unsigned i = 0; i < 2; ++i) {
        TPMS_POLICYAUTHORIZATION *entry = &policy.policyAuthorizations->authorizations[i];
        assert_string_equal(entry->type, "tpm");
        assert_int_equal(entry->signature.sigAlg, TPM2_ALG_RSASSA);
        assert_int_equal(entry->key.nameAlg, TPM2_ALG_SHA256);
        assert_int_equal(entry->policyRef.size, 1);
        assert_int_equal(entry->policyRef.buffer[0], 0x42 + i);
        free(entry->type);
    }
    free(policy.policyAuthorizations);
}

static void
test_policy_get_authorization(void **state) {
    UNUSED(state);
    TPMS_POLICY policy = { 0 };
    TPMT_PUBLIC key = { .type = TPM2_ALG_RSA };
    key.unique.rsa.size = 1;
    key.unique.rsa.buffer[0] = 0x42;
    TPMT_SIGNATURE signature = { .sigAlg = TPM2_ALG_RSASSA };
    signature.signature.rsassa.sig.size = 1;
    TPM2B_NONCE    ref = { .size = 1, .buffer = { 1 } };
    bool           found = true;
    TPMT_SIGNATURE result = { .sigAlg = TPM2_ALG_NULL };
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, &result), 0);
    assert_false(found);
    assert_int_equal(result.sigAlg, TPM2_ALG_NULL);
    /* Two authorizations for the same key must be distinguished by policyRef. */
    for (unsigned i = 0; i < 2; ++i) {
        ref.buffer[0] = i + 1;
        signature.signature.rsassa.sig.buffer[0] = 0x80 + i;
        assert_int_equal(Tss2_PolicyAddAuthorization(&policy, &signature, ref, &key), 0);
    }
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, &result), 0);
    assert_true(found);
    assert_int_equal(result.signature.rsassa.sig.buffer[0], 0x81);
    ref.buffer[0] = 1;
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, NULL), 0);
    assert_true(found);
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, &result), 0);
    assert_int_equal(result.signature.rsassa.sig.buffer[0], 0x80);
    ref.buffer[0] = 3;
    result.sigAlg = TPM2_ALG_NULL;
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, &result), 0);
    assert_false(found);
    assert_int_equal(result.sigAlg, TPM2_ALG_NULL);
    ref.buffer[0] = 1;
    key.unique.rsa.buffer[0]++;
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, NULL), 0);
    assert_false(found);
    key.unique.rsa.buffer[0]--;
    TPM2B_NONCE empty = { 0 };
    assert_int_equal(Tss2_PolicyAddAuthorization(&policy, &signature, empty, &key), 0);
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, NULL, &found, NULL), 0);
    assert_true(found);
    assert_int_equal(Tss2_PolicyGetAuthorization(NULL, &key, &ref, &found, NULL),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    assert_false(found);
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, NULL, &ref, &found, NULL),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, NULL, NULL),
                     TSS2_POLICY_RC_BAD_REFERENCE);
    ref.size = sizeof(ref.buffer) + 1;
    assert_int_equal(Tss2_PolicyGetAuthorization(&policy, &key, &ref, &found, NULL),
                     TSS2_POLICY_RC_BAD_VALUE);
    for (size_t i = 0; i < policy.policyAuthorizations->count; ++i)
        free(policy.policyAuthorizations->authorizations[i].type);
    free(policy.policyAuthorizations);
}

static void
test_init_tpms_policy(void **state) {
    UNUSED(state);
    TPMS_POLICY *policy = Tss2_InitTpmsPolicy();
    assert_non_null(policy);
    assert_null(policy->description);
    assert_int_equal(policy->policyDigests.count, 0);
    assert_null(policy->policyAuthorizations);
    assert_null(policy->policy);
    Tss2_PolicyCleanup(&policy);
    assert_null(policy);
    Tss2_PolicyCleanup(&policy);
    Tss2_PolicyCleanup(NULL);
}

static void
test_policy_json_api(void **state) {
    UNUSED(state);
    const char  *input = "{\"description\":\"json api\",\"policy\":["
                         "{\"type\":\"POLICYCOMMANDCODE\",\"code\":349}]}";
    TPMS_POLICY *policy = NULL;
    TPMS_POLICY *copy = NULL;
    char        *json = NULL;
    char        *json_copy = NULL;
    assert_int_equal(Tss2_PolicyJsonDeserialize(input, NULL), TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(Tss2_PolicyJsonDeserialize(NULL, &policy), TSS2_POLICY_RC_BAD_REFERENCE);
    assert_null(policy);
    const char *invalid[]
        = { "{", "[]", "null", "{}",
            "{\"description\":\"invalid\",\"policy\":[{\"type\":\"POLICYOR\"}]}" };
    for (size_t i = 0; i < ARRAY_LEN(invalid); ++i) {
        assert_int_equal(Tss2_PolicyJsonDeserialize(invalid[i], &policy), TSS2_POLICY_RC_BAD_VALUE);
        assert_null(policy);
    }
    assert_int_equal(Tss2_PolicyJsonSerialize(NULL, &json), TSS2_POLICY_RC_BAD_REFERENCE);
    assert_null(json);
    assert_int_equal(Tss2_PolicyJsonDeserialize(input, &policy), TSS2_RC_SUCCESS);
    assert_int_equal(Tss2_PolicyJsonSerialize(policy, NULL), TSS2_POLICY_RC_BAD_REFERENCE);
    /* Serialization works without a TPM, a context or calculated digests. */
    assert_int_equal(Tss2_PolicyJsonSerialize(policy, &json), TSS2_RC_SUCCESS);
    assert_non_null(json);
    Tss2_PolicyCleanup(&policy);
    assert_int_equal(Tss2_PolicyJsonDeserialize(json, &copy), TSS2_RC_SUCCESS);
    assert_string_equal(copy->description, "json api");
    assert_int_equal(copy->policy->elements[0].element.PolicyCommandCode.code, 349);
    assert_int_equal(Tss2_PolicyJsonSerialize(copy, &json_copy), TSS2_RC_SUCCESS);
    assert_string_equal(json, json_copy);
    Tss2_PolicyCleanup(&copy);
    free(json);
    free(json_copy);
}

static void
test_policy_copy(void **state) {
    UNUSED(state);
    TPMS_POLICY *source = Tss2_InitTpmsPolicy();
    TPMS_POLICY *copy = NULL;
    assert_non_null(source);
    source->description = strdup("copy source");
    source->policyDigests.count = 1;
    source->policyDigests.digests[0].hashAlg = TPM2_ALG_SHA256;
    source->policyDigests.digests[0].digest.sha256[0] = 0x42;
    source->policy = calloc(1, sizeof(*source->policy) + sizeof(TPMT_POLICYELEMENT));
    assert_non_null(source->policy);
    source->policy->count = 1;
    source->policy->elements[0].type = POLICYOR;
    TPML_POLICYBRANCHES *branches = calloc(1, sizeof(*branches) + sizeof(TPMS_POLICYBRANCH));
    assert_non_null(branches);
    source->policy->elements[0].element.PolicyOr.branches = branches;
    branches->count = 1;
    branches->authorizations[0].name = strdup("branch");
    branches->authorizations[0].description = strdup("nested policy");
    branches->authorizations[0].policy
        = calloc(1, sizeof(TPML_POLICYELEMENTS) + sizeof(TPMT_POLICYELEMENT));
    assert_non_null(branches->authorizations[0].policy);
    branches->authorizations[0].policy->count = 1;
    branches->authorizations[0].policy->elements[0].type = POLICYACTION;
    branches->authorizations[0].policy->elements[0].element.PolicyAction.action = strdup("action");
    source->policyAuthorizations
        = calloc(1, sizeof(*source->policyAuthorizations) + 2 * sizeof(TPMS_POLICYAUTHORIZATION));
    assert_non_null(source->policyAuthorizations);
    source->policyAuthorizations->count = 2;
    TPMS_POLICYAUTHORIZATION *pem = &source->policyAuthorizations->authorizations[0];
    pem->type = strdup("pem");
    pem->keyPEM = strdup("PEM key");
    pem->pemSignature.size = 3;
    pem->pemSignature.buffer = malloc(3);
    assert_non_null(pem->pemSignature.buffer);
    memcpy(pem->pemSignature.buffer, "sig", 3);
    source->policyAuthorizations->authorizations[1].type = strdup("tpm");
    source->policyAuthorizations->authorizations[1].signature.sigAlg = TPM2_ALG_RSASSA;

    assert_int_equal(Tss2_PolicyCopy(source, &copy), TSS2_RC_SUCCESS);
    assert_non_null(copy);
    assert_ptr_not_equal(source, copy);
    assert_ptr_not_equal(source->description, copy->description);
    assert_ptr_not_equal(source->policy, copy->policy);
    assert_ptr_not_equal(branches, copy->policy->elements[0].element.PolicyOr.branches);
    assert_ptr_not_equal(pem->keyPEM, copy->policyAuthorizations->authorizations[0].keyPEM);
    assert_ptr_not_equal(pem->pemSignature.buffer,
                         copy->policyAuthorizations->authorizations[0].pemSignature.buffer);
    /* All data in the copy must remain valid after freeing the source. */
    Tss2_PolicyCleanup(&source);
    assert_string_equal(copy->description, "copy source");
    assert_int_equal(copy->policyDigests.digests[0].digest.sha256[0], 0x42);
    branches = copy->policy->elements[0].element.PolicyOr.branches;
    assert_string_equal(branches->authorizations[0].name, "branch");
    assert_string_equal(branches->authorizations[0].description, "nested policy");
    assert_string_equal(branches->authorizations[0].policy->elements[0].element.PolicyAction.action,
                        "action");
    assert_int_equal(copy->policyAuthorizations->count, 2);
    assert_string_equal(copy->policyAuthorizations->authorizations[0].keyPEM, "PEM key");
    assert_memory_equal(copy->policyAuthorizations->authorizations[0].pemSignature.buffer, "sig",
                        3);
    assert_int_equal(copy->policyAuthorizations->authorizations[1].signature.sigAlg,
                     TPM2_ALG_RSASSA);
    Tss2_PolicyCleanup(&copy);
    assert_null(copy);
}

static void
test_policy_copy_empty_and_invalid(void **state) {
    UNUSED(state);
    TPMS_POLICY *source = Tss2_InitTpmsPolicy();
    TPMS_POLICY *copy = NULL;
    assert_non_null(source);
    assert_int_equal(Tss2_PolicyCopy(source, NULL), TSS2_POLICY_RC_BAD_REFERENCE);
    assert_int_equal(Tss2_PolicyCopy(NULL, &copy), TSS2_POLICY_RC_BAD_REFERENCE);
    assert_null(copy);
    assert_int_equal(Tss2_PolicyCopy(source, &copy), TSS2_RC_SUCCESS);
    assert_null(copy->description);
    assert_null(copy->policy);
    assert_null(copy->policyAuthorizations);
    Tss2_PolicyCleanup(&copy);

    source->policy = calloc(1, sizeof(*source->policy) + sizeof(TPMT_POLICYELEMENT));
    assert_non_null(source->policy);
    source->policy->count = 1;
    source->policy->elements[0].type = POLICYAUTHORIZENV;
    source->policy->elements[0].element.PolicyAuthorizeNv.nvPath = strdup("NV/path");
    source->policy->elements[0].element.PolicyAuthorizeNv.policy_buffer = malloc(1);
    assert_non_null(source->policy->elements[0].element.PolicyAuthorizeNv.policy_buffer);
    assert_int_equal(Tss2_PolicyCopy(source, &copy), TSS2_POLICY_RC_BAD_VALUE);
    assert_null(copy);
    assert_string_equal(source->policy->elements[0].element.PolicyAuthorizeNv.nvPath, "NV/path");
    Tss2_PolicyCleanup(&source);
}

int
main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    const struct CMUnitTest tests[] = { cmocka_unit_test(test_policy_instantiate),
                                        cmocka_unit_test(test_policy_execute_async),
                                        cmocka_unit_test(test_policy_set_policy_execute),
                                        cmocka_unit_test(test_cached_policy_digest_metadata),
                                        cmocka_unit_test(test_policy_calculation_retry),
                                        cmocka_unit_test(test_policy_authorization),
                                        cmocka_unit_test(test_policy_get_authorization),
                                        cmocka_unit_test(test_init_tpms_policy),
                                        cmocka_unit_test(test_policy_copy),
                                        cmocka_unit_test(test_policy_json_api),
                                        cmocka_unit_test(test_policy_copy_empty_and_invalid) };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
