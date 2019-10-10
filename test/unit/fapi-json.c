/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <json-c/json_util.h>
#include <json-c/json_tokener.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_fapi.h"
#include "tpm_json_serialize.h"
#include "tpm_json_deserialize.h"
#include "ifapi_json_serialize.h"
#include "ifapi_json_deserialize.h"
#include "fapi_policy.h"

#include "util/aux_util.h"

#define LOGMODULE tests
#include "util/log.h"

/* 3 copies from ifapi_helpers.c */
static void
cleanup_policy_element(TPMT_POLICYELEMENT *policy)
{
        switch (policy->type) {
        case POLICYSECRET:
            SAFE_FREE(policy->element.PolicySecret.objectPath);
            break;
        case POLICYAUTHORIZE:
            SAFE_FREE(policy->element.PolicyAuthorize.keyPath);
            SAFE_FREE(policy->element.PolicyAuthorize.keyPEM);
            break;
        case POLICYAUTHORIZENV:
            SAFE_FREE( policy->element.PolicyAuthorizeNv.nvPath);
            SAFE_FREE( policy->element.PolicyAuthorizeNv.policy_buffer);
            break;
        case POLICYSIGNED:
            SAFE_FREE(policy->element.PolicySigned.keyPath);
            SAFE_FREE(policy->element.PolicySigned.keyPEM);
            break;
        case POLICYPCR:
            SAFE_FREE(policy->element.PolicyPCR.pcrs);
            break;
        case POLICYNV:
            SAFE_FREE(policy->element.PolicyNV.nvPath);
            break;
        case POLICYDUPLICATIONSELECT:
            SAFE_FREE(policy->element.PolicyDuplicationSelect.newParentPath);
            break;
        }
}

static void cleanup_policy_elements(TPML_POLICYELEMENTS *policy)
{
    size_t i, j;
    if (policy != NULL) {
        for (i = 0; i < policy->count; i++) {
            if (policy->elements[i].type ==  POLICYOR) {
                /* Policy with sub policies */
                TPML_POLICYBRANCHES *branches = policy->elements[i].element.PolicyOr.branches;
                for (j = 0; j < branches->count; j++) {
                    SAFE_FREE(branches->authorizations[j].name);
                    SAFE_FREE(branches->authorizations[j].description);
                    cleanup_policy_elements(branches->authorizations[j].policy);
                }
                SAFE_FREE(branches);
            } else {
                cleanup_policy_element(&policy->elements[i]);
            }
        }
        SAFE_FREE(policy);
    }
}

/** Free memory allocated during deserialization of policy.
 *
 * The object will not be freed (might be declared on the stack).
 *
 * @param[in]  object The policy to be cleaned up.
 *
 */
static void ifapi_cleanup_policy_harness(TPMS_POLICY_HARNESS *harness)
{
    if (harness) {
       SAFE_FREE(harness->description);
       SAFE_FREE(harness->policyAuthorizations);
       cleanup_policy_elements(harness->policy);
    }
}

char * normalize(const char *string) {
    char *string2 = malloc(strlen(string)+1);
    int i;
    int j = 0;
    for(i = 0; string[i] != '\0'; i++) {
        if ((string[i] != '\n' && string[i] != ' ')) {
            string2[j] = string[i];
            j += 1;
        }
    }
    string2[j] = '\0';
	return string2;
}

#define CHECK_ERROR(TYPE, SRC, RC) \
        { \
            TYPE out; \
            TSS2_RC rc; \
            json_object *jso = json_tokener_parse((SRC)); \
            assert_non_null(jso); \
            rc = ifapi_json_ ## TYPE ## _deserialize (jso, &out); \
            assert_int_equal (rc, RC); \
            json_object_put(jso); \
        }



#define CHECK_JSON2(TYPE, SRC, DST, PSERIALIZE)  \
        { \
            TYPE out; \
            TSS2_RC rc; \
            json_object *jso = json_tokener_parse((SRC)); \
            if (!jso) fprintf(stderr, "JSON parsing failed\n"); \
            assert_non_null(jso); \
            rc = ifapi_json_ ## TYPE ## _deserialize (jso, &out); \
            if (rc) fprintf(stderr, "Deserialization failed\n"); \
            assert_int_equal (rc, TSS2_RC_SUCCESS); \
            json_object_put(jso); \
            jso = NULL; \
            rc = ifapi_json_ ## TYPE ## _serialize (PSERIALIZE, &jso); \
            assert_int_equal (rc, TSS2_RC_SUCCESS); \
            assert_non_null(jso); \
            const char *jso_string = json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY); \
            assert_non_null(jso_string); \
            char *string1 = normalize(jso_string); \
            char *string2 =  normalize(DST); \
            assert_string_equal(string1, string2); \
            json_object_put(jso); \
            free(string1); \
            free(string2); \
        }

#define CHECK_JSON(TYPE, SRC, DST)  \
    CHECK_JSON2(TYPE, SRC, DST, &out)

#define CHECK_JSON_SIMPLE(TYPE, SRC, DST)  \
    CHECK_JSON2(TYPE, SRC, DST, out)

#define CHECK_JSON_TO_BIN(TYPE, SRC, DST) \
        { \
            TYPE out; \
            TSS2_RC rc; \
            TYPE expected = DST; \
            json_object *jso = json_tokener_parse((SRC)); \
            assert_non_null(jso); \
            rc = ifapi_json_ ## TYPE ## _deserialize (jso, &out); \
            assert_int_equal (rc, TSS2_RC_SUCCESS); \
            json_object_put(jso); \
            assert_true(out == expected);       \
        }

#define CHECK_BIN2(TYPE, BIN, PSERIALIZE)                  \
    TYPE BIN ## 2; \
    { \
        char *jso_string1, *jso_string2; \
        json_object *jso = NULL; \
        TSS2_RC rc = ifapi_json_ ## TYPE ## _serialize (PSERIALIZE, &jso); \
        jso_string1 = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY)); \
        assert_int_equal (rc, TSS2_RC_SUCCESS); \
        rc = ifapi_json_ ## TYPE ## _deserialize (jso, &BIN ## 2); \
        assert_int_equal (rc, TSS2_RC_SUCCESS); \
        json_object_put(jso); \
        jso = NULL; \
        rc = ifapi_json_ ## TYPE ## _serialize (PSERIALIZE ## 2, &jso); \
        jso_string2 = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY)); \
        assert_int_equal (rc, TSS2_RC_SUCCESS); \
        if (strcmp(jso_string1, jso_string2)) { \
            fprintf(stderr,"\n jso: %s\n", jso_string1); \
            fprintf(stderr,"\n jso: %s\n", jso_string2); \
        } \
        assert_string_equal(jso_string1, jso_string2); \
        json_object_put(jso); \
        free(jso_string1); \
        free(jso_string2); \
    }

#define CHECK_BIN(TYPE, BIN) \
    CHECK_BIN2(TYPE, BIN, &BIN)

#define CHECK_BIN_SIMPLE(TYPE, BIN) \
    CHECK_BIN2(TYPE, BIN, BIN)

static void
check_bin(void **state)
{
    TPM2B_PUBLIC inPublicAES = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT),

            .authPolicy = {
                 .size = 0,
             },
            .parameters.symDetail = {
                 .sym = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits = {.aes = 128},
                     .mode = {.aes = TPM2_ALG_CFB}}
             },
            .unique.sym = {
                 .size = 0,
                 .buffer = {}
             }
        }
    };

    CHECK_BIN(TPM2B_PUBLIC, inPublicAES);

    TPM2B_PUBLIC inPublicECC = {
            .size = 0,
            .publicArea = {
                .type = TPM2_ALG_ECC,
                .nameAlg = TPM2_ALG_SHA1,
                .objectAttributes = (
                             TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN
                             ),
                .authPolicy = {
                         .size = 0,
                     },

                .parameters.eccDetail = {
                     .symmetric = {
                         .algorithm = TPM2_ALG_NULL,
                         .keyBits.aes = 128,
                         .mode.aes = TPM2_ALG_ECB,
                     },
                     .scheme = {
                          .scheme = TPM2_ALG_ECDAA,
                          .details = { .ecdaa = { .hashAlg = TPM2_ALG_SHA256 }},
                      },
                     .curveID = TPM2_ECC_BN_P256,
                     .kdf = { .scheme = TPM2_ALG_NULL, .details = {} }
                 },
                /*
                  .parameters.asymDetail.symmetric.algorithm = TPM2_ALG_NULL,
                */
                .unique.ecc = {
                     .x = { .size = 0, .buffer = {} } ,
                     .y = { .size = 0, .buffer = {} } ,
                 },
            },
        };


    CHECK_BIN(TPM2B_PUBLIC, inPublicECC);

    TPM2B_PUBLIC inPublicRSA2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT  |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_RSAPSS,
                      .details = {
                          .rsapss = { .hashAlg = TPM2_ALG_SHA1 }
                      }
                  },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };

    CHECK_BIN(TPM2B_PUBLIC, inPublicRSA2);

    TPMT_SIG_SCHEME ecc_scheme = { .scheme = TPM2_ALG_ECDSA, .details.ecdsa = TPM2_ALG_SHA1 };

    CHECK_BIN(TPMT_SIG_SCHEME, ecc_scheme);

    TPMT_SIG_SCHEME rsa_scheme = { .scheme = TPM2_ALG_NULL };

    CHECK_BIN(TPMT_SIG_SCHEME, rsa_scheme);

    TPMA_NV testNV = 0xffffff0f ;

    CHECK_BIN_SIMPLE(TPMA_NV, testNV);

    TPML_PCR_SELECTION pcr_selection = {
        .count = 3,
        .pcrSelections = {
         {
            .hash = TPM2_ALG_SHA1,
            .sizeofSelect = 3,
            .pcrSelect = { 01, 00, 03 }},
        {
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 01 ,00 ,03 }},
        {
            .hash = TPM2_ALG_SHA384,
            .sizeofSelect = 3,
            .pcrSelect = { 02, 00, 02 }}
        }
    };

    CHECK_BIN(TPML_PCR_SELECTION, pcr_selection);

    IFAPI_ENCRYPTED_DATA encryptedData = {
        .type = 0,
        .key_name = {
            .size = 1,
            .name = {1}
        },
        .cipher = {
            .size = 0,
            .buffer = NULL
        },
        .sym_private = {
            .size = 0,
            .buffer = NULL
        },
        .sym_public = {
            .size = 0,
            .publicArea = {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA1,
                .objectAttributes =
                (TPMA_OBJECT_USERWITHAUTH |
                 TPMA_OBJECT_SIGN_ENCRYPT |
                 TPMA_OBJECT_FIXEDTPM |
                 TPMA_OBJECT_FIXEDPARENT |
                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
                .authPolicy = {
                    .size = 0,
                    .buffer = { 0 }
                },
                .parameters.rsaDetail = {
                    .symmetric = {.algorithm = TPM2_ALG_NULL, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
                    .scheme = {.scheme = TPM2_ALG_RSAPSS, .details = {.rsapss = {.hashAlg = TPM2_ALG_SHA1}}},
                    .keyBits = 2048,
                    .exponent = 0,
                },
                .unique.rsa = {
                    .size = 0,
                    .buffer = { 0 },
                },
            },
        },
        .sym_key_size = 0,
        .sym_iv = {.size = 0, .buffer = {0}},
        .sym_policy_harness = {
            .description = "",
            .policyDigests = {
                .count = 1,
                .digests = {
                    {
                        .hashAlg = TPM2_ALG_SHA256,
                        .digest = {
                            .sha256 = {0}
                        }
                    }
                }
            }
        }
    };

    CHECK_BIN(IFAPI_ENCRYPTED_DATA, encryptedData);
    free(encryptedData2.cipher.buffer);

    IFAPI_IMA_EVENT imaEvent = {
        .eventData = {
            .size = 0,
            .buffer = { 0 }
        },
        .eventName = "Event"
    };

    CHECK_BIN(IFAPI_IMA_EVENT, imaEvent);
    free(imaEvent2.eventName);
}

static void
check_policy_bin(void **state)
{
    TPMS_PCRVALUE pcr_value;
    TPML_PCRVALUES *pcr_value_list;
    TPML_POLICYBRANCHES *or_branch_list;
    TPMS_POLICYPCR pcr_policy;
    TPMT_POLICYELEMENT policy_element0;
    TPMT_POLICYELEMENT policy_element1;
    TPMT_POLICYELEMENT policy_element_or;
    TPML_POLICYELEMENTS *policy_elements_or;
    TPML_POLICYELEMENTS *policy_elements0;
    TPML_POLICYELEMENTS *policy_elements1;
    TPMS_POLICY_HARNESS policy_harness;
    TPMS_POLICYBRANCH branch0;
    TPMS_POLICYBRANCH branch1;

    pcr_value.pcr = 16;
    pcr_value.hashAlg = TPM2_ALG_SHA1;
    memset(&pcr_value.digest, 0, sizeof(TPMU_HA));
    memset(&pcr_policy, 0, sizeof(TPMS_POLICYPCR));
    pcr_value_list = calloc(1, sizeof(TPML_PCRVALUES) + sizeof(TPMS_PCRVALUE));
    if (pcr_value_list == NULL) {
        LOG_ERROR("%s", "Out of memory.");
        return;
    }
    pcr_value_list->count = 1;
    pcr_value_list->pcrs[0] = pcr_value;
    pcr_policy.pcrs = pcr_value_list;
    memset(&policy_element0, 0, sizeof(TPMT_POLICYELEMENT));
    policy_element0.element.PolicyPCR = pcr_policy;
    policy_element0.type = POLICYPCR;
    memset(&policy_element1, 0, sizeof(TPMT_POLICYELEMENT));
    policy_element1.element.PolicyPCR = pcr_policy;
    policy_element1.type = POLICYPCR;
    policy_elements0 = calloc(1, sizeof(TPML_POLICYELEMENTS) + sizeof(TPMT_POLICYELEMENT));
    if (policy_elements0 == NULL) {
        LOG_ERROR("%s", "Out of memory.");
        if (pcr_policy.pcrs){
            free(pcr_policy.pcrs);
        }
        return;
    }
    policy_elements0->count = 1;
    policy_elements0->elements[0] = policy_element0;
    policy_harness.policy = policy_elements0;
    policy_harness.description = "hareness description";
    policy_harness.policyAuthorizations = NULL;
    memset(&policy_harness.policyDigests, 0, sizeof(TPML_DIGEST_VALUES));

    //CHECK_BIN(TPMS_POLICY_HARNESS, policy_harness);
    {
        char *jso_string1, *jso_string2;
        json_object *jso = NULL;
        TSS2_RC rc = ifapi_json_TPMS_POLICY_HARNESS_serialize (&policy_harness, &jso);
        jso_string1 = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_int_equal (rc, TSS2_RC_SUCCESS);
        rc = ifapi_json_TPMS_POLICY_HARNESS_deserialize (jso, &policy_harness);
        assert_int_equal (rc, TSS2_RC_SUCCESS);
        json_object_put(jso);
        jso = NULL;
        rc = ifapi_json_TPMS_POLICY_HARNESS_serialize (&policy_harness, &jso);
        jso_string2 = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_int_equal (rc, TSS2_RC_SUCCESS);
        if (strcmp(jso_string1, jso_string2)) {
            fprintf(stderr,"\n jso: %s\n", jso_string1);
            fprintf(stderr,"\n jso: %s\n", jso_string2);
        }
        assert_string_equal(jso_string1, jso_string2);
        json_object_put(jso);
        free(jso_string1);
        free(jso_string2);
    }
    ifapi_cleanup_policy_harness(&policy_harness);

    or_branch_list = calloc(2, sizeof(TPML_POLICYBRANCHES) + (2 * sizeof(TPMS_POLICYBRANCH)));
    if (or_branch_list == NULL) {
        LOG_ERROR("%s", "Out of memory.");
        return;
    }
    or_branch_list->count = 2;

    policy_elements1 = calloc(1, sizeof(TPML_POLICYELEMENTS) + sizeof(TPMT_POLICYELEMENT));
    if (policy_elements1 == NULL) {
        LOG_ERROR("%s", "Out of memory.");
        if (or_branch_list){
            free(or_branch_list);
        }
        return;
    }
    policy_elements1->count = 1;
    policy_elements1->elements[0] = policy_element1;

    memset(&branch0, 0, sizeof(TPMS_POLICYBRANCH));
    memset(&branch1, 0, sizeof(TPMS_POLICYBRANCH));
    branch0.policy = policy_elements0;
    branch0.name = "branch0";
    branch0.description = "description branch 0";
    branch1.policy = policy_elements1;
    branch1.name = "branch1";
    branch1.description = "description branch 1";
    memcpy(&or_branch_list->authorizations[0], &branch0, sizeof(TPMS_POLICYBRANCH));
    memcpy(&or_branch_list->authorizations[1], &branch1, sizeof(TPMS_POLICYBRANCH));
    //or_policy.pcrs = pcr_branch_list;

    policy_elements_or = calloc(1, sizeof(TPML_POLICYELEMENTS) + sizeof(TPMT_POLICYELEMENT));
    if (policy_elements_or == NULL) {
        LOG_ERROR("%s", "Out of memory.");
        if (or_branch_list) {
            free(or_branch_list);
        }
        return;
    }
    policy_elements_or->count = 1;

    memset(&policy_element_or, 0, sizeof(TPMT_POLICYELEMENT));
    policy_element_or.element.PolicyOr.branches = or_branch_list;
    policy_element_or.type = POLICYOR;
    policy_elements_or->elements[0] = policy_element_or;
    policy_harness.policy =  policy_elements_or;

    //CHECK_BIN(TPMS_POLICY_HARNESS, policy_harness);
    {
        char *jso_string1, *jso_string2;
        json_object *jso = NULL;
        TSS2_RC rc = ifapi_json_TPMS_POLICY_HARNESS_serialize (&policy_harness, &jso);
        jso_string1 = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_int_equal (rc, TSS2_RC_SUCCESS);
        rc = ifapi_json_TPMS_POLICY_HARNESS_deserialize (jso, &policy_harness);
        assert_int_equal (rc, TSS2_RC_SUCCESS);
        json_object_put(jso);
        jso = NULL;
        rc = ifapi_json_TPMS_POLICY_HARNESS_serialize (&policy_harness, &jso);
        jso_string2 = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_int_equal (rc, TSS2_RC_SUCCESS);
        if (strcmp(jso_string1, jso_string2)) {
            fprintf(stderr,"\n jso: %s\n", jso_string1);
            fprintf(stderr,"\n jso: %s\n", jso_string2);
        }
        assert_string_equal(jso_string1, jso_string2);
        json_object_put(jso);
        free(jso_string1);
        free(jso_string2);
    }
    ifapi_cleanup_policy_harness(&policy_harness);

    free(policy_elements_or);
    free(policy_elements0);
    free(policy_elements1);
    free(or_branch_list);
    free(pcr_value_list);
}

static void
check_json_to_bin(void **state)
{
    CHECK_JSON_TO_BIN(UINT64, "22147483647", 22147483647);
    CHECK_JSON_TO_BIN(UINT64, "\"0xffffffff\"", 0xffffffff);
    CHECK_JSON_TO_BIN(UINT64, "\"0xfffffffff\"", 0xfffffffff);
    CHECK_JSON_TO_BIN(UINT32,  "\"0xFfffffff\"", 0xffffffff);
    CHECK_JSON_TO_BIN(UINT16, "\"0xffff\"", 0xffff);
}

static void
check_json_structs(void **state)
{
    const char *test_json_TPMS_POLICYTEMPLATE =
        "{\n"
        "  \"templateHash\": \"0011223344556677889900112233445566778899\"\n"
        "}";
    CHECK_JSON(TPMS_POLICYTEMPLATE, test_json_TPMS_POLICYTEMPLATE, test_json_TPMS_POLICYTEMPLATE);

    const char *test_json_TPM2B_PUBLIC_expected =
        "{\n"
        "  \"size\":0,\n"
        "  \"publicArea\":{\n"
        "    \"type\":\"ECC\",\n"
        "    \"nameAlg\":\"SHA1\",\n"
        "\"objectAttributes\":{"
        "      \"fixedTPM\":1,"
        "      \"stClear\":0,"
        "      \"fixedParent\":1,"
        "      \"sensitiveDataOrigin\":1,"
        "      \"userWithAuth\":1,"
        "      \"adminWithPolicy\":0,"
        "      \"noDA\":0,"
        "      \"encryptedDuplication\":0,"
        "      \"restricted\":1,"
        "      \"decrypt\":0,"
        "      \"sign\":1"
        "    },"
        "    \"authPolicy\":\"\",\n"
        "    \"parameters\":{\n"
        "      \"symmetric\":{\n"
        "        \"algorithm\":\"NULL\"\n"
        "      },\n"
        "      \"scheme\":{\n"
        "        \"scheme\":\"ECDAA\",\n"
        "        \"details\":{\n"
        "          \"hashAlg\":\"SHA256\",\n"
        "          \"count\":0\n"
        "        }\n"
        "      },\n"
        "      \"curveID\":\"BN_P256\",\n"
        "      \"kdf\":{\n"
        "        \"scheme\":\"NULL\"\n"
        "      }\n"
        "    },\n"
        "    \"unique\":{\n"
        "      \"x\": \"\",\n"
        "      \"y\": \"\"\n"
        "    }\n"
        "  }\n"
        "}";

    const char *test_json_TPM2B_PUBLIC_src=
        "{"
        "  \"size\":0,"
        "  \"publicArea\":{"
        "    \"type\":\"ECC\","
        "    \"nameAlg\":\"SHA1\","
        "    \"objectAttributes\":["
        "      \"fixedTPM\","
        "      \"fixedParent\","
        "      \"sensitiveDataOrigin\","
        "      \"userWithAuth\","
        "      \"restricted\","
        "      \"sign\""
        "    ],"
        "    \"authPolicy\":\"\","
        "    \"parameters\":{"
        "      \"symmetric\":{"
        "        \"algorithm\":\"NULL\""
        "      },"
        "      \"scheme\":{"
        "        \"scheme\":\"ECDAA\","
        "        \"details\":{"
        "          \"hashAlg\":\"SHA256\","
        "          \"count\":0"
        "        }"
        "      },"
        "      \"curveID\":\"ECC_BN_P256\","
        "      \"kdf\":{"
        "        \"scheme\":\"NULL\""
        "      }"
        "    },"
        "    \"unique\":{"
        "      \"x\": \"\",\n"
        "      \"y\": \"\"\n"
        "    }"
        "  }"
        "}"
        "";
    const char *test_json_TPM2B_PUBLIC_dwnc_src =
        "{"
        "  \"size\":0,"
        "  \"publicArea\":{"
        "    \"type\":\"ecc\","
        "    \"nameAlg\":\"sha1\","
        "    \"objectAttributes\":["
        "      \"fixedTPM\","
        "      \"fixedParent\","
        "      \"sensitiveDataOrigin\","
        "      \"userWithAuth\","
        "      \"restricted\","
        "      \"sign\""
        "    ],"
        "    \"authPolicy\":\"\","
        "    \"parameters\":{"
        "      \"symmetric\":{"
        "        \"algorithm\":\"null\""
        "      },"
        "      \"scheme\":{"
        "        \"scheme\":\"ecdaa\","
        "        \"details\":{"
        "          \"hashAlg\":\"sha256\","
        "          \"count\":0"
        "        }"
        "      },"
        "      \"curveID\":\"ecc_BN_P256\","
        "      \"kdf\":{"
        "        \"scheme\":\"null\""
        "      }"
        "    },"
        "    \"unique\":{"
        "      \"x\": \"\",\n"
        "      \"y\": \"\"\n"
        "      }"
        "    }"
        "  }"
        "}"
        "";

    CHECK_JSON(TPM2B_PUBLIC, test_json_TPM2B_PUBLIC_src, test_json_TPM2B_PUBLIC_expected);
    CHECK_JSON(TPM2B_PUBLIC, test_json_TPM2B_PUBLIC_dwnc_src, test_json_TPM2B_PUBLIC_expected);

    const char *test_json_TPMS_ATTEST_certify_src =
        "{\n"
        "    \"magic\": \"0xff544347\",\n"
        "    \"type\": \"ST_ATTEST_CERTIFY\",\n"
        "    \"qualifiedSigner\": \"0x00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"0x00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"yes\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"name\": \"0x00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"qualifiedName\": \"0x00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMS_ATTEST_certify_expt =
        "{\n"
        "    \"magic\": \"VALUE\",\n"
        "    \"type\": \"ATTEST_CERTIFY\",\n"
        "    \"qualifiedSigner\": \"00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"YES\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"name\": \"00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"qualifiedName\": \"00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMS_ATTEST, test_json_TPMS_ATTEST_certify_src, test_json_TPMS_ATTEST_certify_expt);

    const char *test_json_TPMS_ATTEST_sessionaudit_src =
        "{\n"
        "    \"magic\": \"0xff544347\",\n"
        "    \"type\": \"ST_ATTEST_SESSION_AUDIT\",\n"
        "    \"qualifiedSigner\": \"0x00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"0x00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": [12345,0],\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"yes\"\n"
        "    },\n"
        "    \"firmwareVersion\": [783783,0],\n"
        "    \"attested\": {\n"
        "        \"exclusiveSession\": \"yes\",\n"
        "        \"sessionDigest\": \"0x00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMS_ATTEST_sessionaudit_expt =
        "{\n"
        "    \"magic\": \"VALUE\",\n"
        "    \"type\": \"ATTEST_SESSION_AUDIT\",\n"
        "    \"qualifiedSigner\": \"00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 53021371269120,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"YES\"\n"
        "    },\n"
        "    \"firmwareVersion\": [783783,0],\n"
        "    \"attested\": {\n"
        "        \"exclusiveSession\": \"YES\",\n"
        "        \"sessionDigest\": \"00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMS_ATTEST, test_json_TPMS_ATTEST_sessionaudit_src, test_json_TPMS_ATTEST_sessionaudit_expt);

    const char *test_json_TPMS_ATTEST_certifycreation_src =
        "{\n"
        "    \"magic\": \"0xff544347\",\n"
        "    \"type\": \"ST_ATTEST_CREATION\",\n"
        "    \"qualifiedSigner\": \"0x00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"0x00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"yes\"\n"
        "    },\n"
        "    \"firmwareVersion\": [0,783],\n"
        "    \"attested\": {\n"
        "        \"objectName\": \"0x00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"creationHash\": \"0x00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMS_ATTEST_certifycreation_expt =
        "{\n"
        "    \"magic\": \"VALUE\",\n"
        "    \"type\": \"ATTEST_CREATION\",\n"
        "    \"qualifiedSigner\": \"00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"YES\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"objectName\": \"00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"creationHash\": \"00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMS_ATTEST, test_json_TPMS_ATTEST_certifycreation_src, test_json_TPMS_ATTEST_certifycreation_expt);

    const char *test_json_TPMS_ATTEST_commandaudit_src =
        "{\n"
        "    \"magic\": \"0xff544347\",\n"
        "    \"type\": \"ST_ATTEST_COMMAND_AUDIT\",\n"
        "    \"qualifiedSigner\": \"0x00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"0x00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"yes\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"auditCounter\": 456,\n"
        "        \"digestAlg\": \"sha1\",\n"
        "        \"auditDigest\": \"0x00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"commandDigest\": \"0x00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMS_ATTEST_commandaudit_expt =
        "{\n"
        "    \"magic\": \"VALUE\",\n"
        "    \"type\": \"ATTEST_COMMAND_AUDIT\",\n"
        "    \"qualifiedSigner\": \"00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"YES\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"auditCounter\": 456,\n"
        "        \"digestAlg\": \"SHA1\",\n"
        "        \"auditDigest\": \"00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"commandDigest\": \"00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMS_ATTEST, test_json_TPMS_ATTEST_commandaudit_src, test_json_TPMS_ATTEST_commandaudit_expt);

    const char *test_json_TPMS_ATTEST_time_src =
        "{\n"
        "    \"magic\": \"0xff544347\",\n"
        "    \"type\": \"ST_ATTEST_TIME\",\n"
        "    \"qualifiedSigner\": \"0x00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"0x00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"yes\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"time\": {\n"
        "            \"time\": 234,\n"
        "            \"clockInfo\": {\n"
        "                \"clock\": 123,\n"
        "                \"resetCount\": 23,\n"
        "                \"restartCount\": 1,\n"
        "                \"safe\": \"yes\"\n"
        "            }\n"
        "        },\n"
        "        \"firmwareVersion\": 783\n"
        "    }\n"
        "}";
    const char *test_json_TPMS_ATTEST_time_expt =
        "{\n"
        "    \"magic\": \"VALUE\",\n"
        "    \"type\": \"ATTEST_TIME\",\n"
        "    \"qualifiedSigner\": \"00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"YES\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"time\": {\n"
        "            \"time\": 234,\n"
        "            \"clockInfo\": {\n"
        "                \"clock\": 123,\n"
        "                \"resetCount\": 23,\n"
        "                \"restartCount\": 1,\n"
        "                \"safe\": \"YES\"\n"
        "            }\n"
        "        },\n"
        "        \"firmwareVersion\": 783\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMS_ATTEST, test_json_TPMS_ATTEST_time_src, test_json_TPMS_ATTEST_time_expt);

    const char *test_json_TPMS_ATTEST_certifynv_src =
        "{\n"
        "    \"magic\": \"0xff544347\",\n"
        "    \"type\": \"ST_ATTEST_NV\",\n"
        "    \"qualifiedSigner\": \"0x00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"0x00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"yes\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"indexName\": \"0x00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"offset\": 10,\n"
        "        \"nvContents\": \"0x00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMS_ATTEST_certifynv_expt =
        "{\n"
        "    \"magic\": \"VALUE\",\n"
        "    \"type\": \"ATTEST_NV\",\n"
        "    \"qualifiedSigner\": \"00010203040506070809a0a1a2a3a4a5a6a7a8a9\",\n"
        "    \"extraData\": \"00010203040506070809b0b1b2b3b4b5b6b7b8b9\",\n"
        "    \"clockInfo\": {\n"
        "        \"clock\": 123,\n"
        "        \"resetCount\": 23,\n"
        "        \"restartCount\": 1,\n"
        "        \"safe\": \"YES\"\n"
        "    },\n"
        "    \"firmwareVersion\": 783,\n"
        "    \"attested\": {\n"
        "        \"indexName\": \"00010203040506070809c0c1c2c3c4c5c6c7c8c9\",\n"
        "        \"offset\": 10,\n"
        "        \"nvContents\": \"00010203040506070809d0d1d2d3d4d5d6d7d8d9\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMS_ATTEST, test_json_TPMS_ATTEST_certifynv_src, test_json_TPMS_ATTEST_certifynv_expt);

    const char *test_json_TPMT_KEYEDHASH_SCHEME_hmac_src =
        "{\n"
        "    \"scheme\": \"HMAC\",\n"
        "    \"details\": {\n"
        "        \"hashAlg\": \"SHA256\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMT_KEYEDHASH_SCHEME_hmac_expt =
        "{\n"
        "    \"scheme\": \"HMAC\",\n"
        "    \"details\": {\n"
        "        \"hashAlg\": \"SHA256\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMT_KEYEDHASH_SCHEME, test_json_TPMT_KEYEDHASH_SCHEME_hmac_src, test_json_TPMT_KEYEDHASH_SCHEME_hmac_expt);

    const char *test_json_TPMT_KEYEDHASH_SCHEME_xor_src =
        "{\n"
        "    \"scheme\": \"XOR\",\n"
        "    \"details\": {\n"
        "        \"hashAlg\": \"SHA256\",\n"
        "        \"kdf\": \"MGF1\"\n"
        "    }\n"
        "}";
    const char *test_json_TPMT_KEYEDHASH_SCHEME_xor_expt =
        "{\n"
        "    \"scheme\": \"XOR\",\n"
        "    \"details\": {\n"
        "        \"hashAlg\": \"SHA256\",\n"
        "        \"kdf\": \"MGF1\"\n"
        "    }\n"
        "}";
    CHECK_JSON(TPMT_KEYEDHASH_SCHEME, test_json_TPMT_KEYEDHASH_SCHEME_xor_src, test_json_TPMT_KEYEDHASH_SCHEME_xor_expt);

}

static void
check_json_constants(void **state)
{
    CHECK_JSON_SIMPLE(TPMI_ALG_HASH, "\"sha1\"", "\"SHA1\"");
    CHECK_JSON_SIMPLE(TPMI_ALG_HASH, "\"0x04\"", "\"SHA1\"");
    CHECK_JSON_SIMPLE(TPMI_ALG_HASH, "4", "\"SHA1\"");
}

static void
check_json_numbers(void **state)
{
    CHECK_JSON_SIMPLE(UINT16, "10", "10");
    CHECK_JSON_SIMPLE(UINT16, "\"0x0a\"", "10");
    CHECK_JSON_SIMPLE(UINT64, "10000000000000000","[2328306,1874919424]");
}

static void
check_json_bits(void **state)
{
      const char *test_json_TPMA_NV_expected =\
                    "{"
                    "  \"PPWRITE\":0,"
                    "  \"OWNERWRITE\":1,"
                    "  \"AUTHWRITE\":1,"
                    "  \"POLICYWRITE\":1,"
                    "  \"POLICY_DELETE\":1,"
                    "  \"WRITELOCKED\":0,"
                    "  \"WRITEALL\":0,"
                    "  \"WRITEDEFINE\":0,"
                    "  \"WRITE_STCLEAR\":0,"
                    "  \"GLOBALLOCK\":0,"
                    "  \"PPREAD\":0,"
                    "  \"OWNERREAD\":1,"
                    "  \"AUTHREAD\":1,"
                    "  \"POLICYREAD\":1,"
                    "  \"NO_DA\":0,"
                    "  \"ORDERLY\":1,"
                    "  \"CLEAR_STCLEAR\":1,"
                    "  \"READLOCKED\":1,"
                    "  \"WRITTEN\":1,"
                    "  \"PLATFORMCREATE\":0,"
                    "  \"READ_STCLEAR\":0,"
                    "  \"TPM2_NT\":\"COUNTER\""
                    "}";

    const char *test_json_TPMA_NV_src_array =\
                    "["
                    "  \"nv_ownerwrite\","
                    "  \"nv_authwrite\","
                    "  \"nv_policywrite\","
                    "  \"nv_policy_delete\","
                    "  \"nv_ownerread\","
                    "  \"nv_authread\","
                    "  \"nv_policyread\","
                    "  \"nv_orderly\","
                    "  \"nv_clear_stclear\","
                    "  \"nv_readlocked\","
                    "  \"nv_written\","
                    "  {"
                    "    \"TPM2_NT\": \"NT_COUNTER\""
                    "  }"
                    "]";

       const char *test_json_TPMA_NV_src_struct =\
                    "{"
                    "  \"TPMA_NV_OWNERWRITE\":\"YES\","
                    "  \"TPMA_NV_AUTHWRITE\":\"yes\","
                    "  \"TPMA_NV_POLICYWRITE\":\"TPM2_YES\","
                    "  \"TPMA_NV_POLICY_DELETE\":\"tpm2_yes\","
                    "  \"TPMA_NV_OWNERREAD\":\"SET\","
                    "  \"TPMA_NV_AUTHREAD\":\"set\","
                    "  \"TPMA_NV_POLICYREAD\":1,"
                    "  \"TPMA_NV_ORDERLY\":1,"
                    "  \"TPMA_NV_CLEAR_STCLEAR\":1,"
                    "  \"TPMA_NV_READLOCKED\":1,"
                    "  \"TPMA_NV_WRITTEN\":1,"
                    "  \"TPM2_NT\":1"
                    "  }";

    CHECK_JSON_SIMPLE(TPMA_NV, test_json_TPMA_NV_src_array, test_json_TPMA_NV_expected);
    CHECK_JSON_SIMPLE(TPMA_NV, test_json_TPMA_NV_src_struct, test_json_TPMA_NV_expected);
}

static void
check_json_policy(void **state)
{
     const char *test_json_policy_nv_src =       \
        "{"
        "  \"description\":\"Description pol_nv\","
        "  \"policyDigests\":["
        "  ],"
        "  \"policyAuthorizations\":["
        "  ],"
        "    \"policy\":["
        "        {"
        "            \"type\": \"POLICYNV\","
        "                   \"nvPath\": \"myNV\","
        "                   \"operandB\": \"01030304\""
        "      }"
        "  ]"
        "}";

       const char *test_json_policy_nv_expected =       \
        "{"
        "  \"description\":\"Description pol_nv\","
        "  \"policyDigests\":["
        "  ],"
        "  \"policyAuthorizations\":["
        "  ],"
        "    \"policy\":["
        "        {"
        "            \"type\": \"POLICYNV\","
        "                   \"nvPath\": \"myNV\","
        "                   \"operandB\": \"01030304\""
        "     }"
        "  ]"
        "}";


//    CHECK_JSON(TPMS_POLICY_HARNESS, test_json_policy_nv_src, test_json_policy_nv_expected);
        {
            TPMS_POLICY_HARNESS out;
            TSS2_RC rc;
            json_object *jso = json_tokener_parse(test_json_policy_nv_src);
            if (!jso) fprintf(stderr, "JSON parsing failed\n");
            assert_non_null(jso);
            rc = ifapi_json_TPMS_POLICY_HARNESS_deserialize (jso, &out);
            if (rc) fprintf(stderr, "Deserialization failed\n");
            assert_int_equal (rc, TSS2_RC_SUCCESS);
            json_object_put(jso);
            jso = NULL;
            rc = ifapi_json_TPMS_POLICY_HARNESS_serialize (&out, &jso);
            assert_int_equal (rc, TSS2_RC_SUCCESS);
            assert_non_null(jso);
            const char *jso_string = json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
            assert_non_null(jso_string);
            char *string1 = normalize(jso_string);
            char *string2 =  normalize(test_json_policy_nv_expected);
            assert_string_equal(string1, string2);
            json_object_put(jso);
            ifapi_cleanup_policy_harness(&out);
            free(string1);
            free(string2);
        }

    const char *test_json_policy_or_src =       \
        "{"
        "  \"description\":\"hareness description\","
        "  \"policyDigests\":["
        "    {"
        "      \"hashAlg\":\"SHA256\","
        "      \"digest\":\"59215cb6c21a60e26b2cc479334a021113611903795507c1227659e2aef23d16\""
        "    }"
        "  ],"
        "  \"policy\":["
        "    {"
        "      \"type\":\"POLICYOR\","
        "      \"policyDigests\":["
        "        {"
        "          \"hashAlg\":\"SHA256\","
        "          \"digest\":\"59215cb6c21a60e26b2cc479334a021113611903795507c1227659e2aef23d16\""
        "        }"
        "      ],"
        "        \"branches\":["
        "          {"
        "            \"name\":\"branch1\","
        "            \"description\":\"description branch 1\","
        "            \"policy\":["
        "              {"
        "                \"type\":\"POLICYPCR\","
        "                \"policyDigests\":["
        "                  {"
        "                    \"hashAlg\":\"SHA256\","
        "                    \"digest\":\"17d552f8e39ad882f6b3c09ae139af59616bf6a63f4093d6d20e9e1b9f7cdb6e\""
        "                  }"
        "                ],"
        "                  \"pcrs\":["
        "                    {"
        "                      \"pcr\":16,"
        "                      \"hashAlg\":\"SHA1\","
        "                      \"digest\":\"0000000000000000000000000000000000000000\""
        "                    }"
        "                  ]"
        "              }"
        "            ],"
        "            \"policyDigests\":["
        "              {"
        "                \"hashAlg\":\"SHA256\","
        "                \"digest\":\"17d552f8e39ad882f6b3c09ae139af59616bf6a63f4093d6d20e9e1b9f7cdb6e\""
        "              }"
        "            ]"
        "          },"
        "          {"
        "            \"name\":\"branch1\","
        "            \"description\":\"description branch 1\","
        "            \"policy\":["
        "              {"
        "                \"type\":\"POLICYPCR\","
        "                \"policyDigests\":["
        "                  {"
        "                    \"hashAlg\":\"SHA256\","
        "                    \"digest\":\"17d552f8e39ad882f6b3c09ae139af59616bf6a63f4093d6d20e9e1b9f7cdb6e\""
        "                  }"
        "                ],"
        "                  \"pcrs\":["
        "                    {"
        "                      \"pcr\":16,"
        "                      \"hashAlg\":\"SHA1\","
        "                      \"digest\":\"0000000000000000000000000000000000000000\""
        "                    }"
        "                  ]"
        "              }"
        "            ],"
        "            \"policyDigests\":["
        "              {"
        "                \"hashAlg\":\"SHA256\","
        "                \"digest\":\"17d552f8e39ad882f6b3c09ae139af59616bf6a63f4093d6d20e9e1b9f7cdb6e\""
        "              }"
        "            ]"
        "          }"
        "        ]"
        "    }"
        "  ]"
        "}";

    char *test_json_policy_or_expected = strdup(test_json_policy_or_src);
    if (test_json_policy_or_expected == NULL){
        LOG_ERROR("%s", "Out of memory.");
        return;
    }
//    CHECK_JSON(TPMS_POLICY_HARNESS, test_json_policy_or_src, test_json_policy_or_expected);
        {
            TPMS_POLICY_HARNESS out;
            TSS2_RC rc;
            json_object *jso = json_tokener_parse(test_json_policy_or_src);
            if (!jso) fprintf(stderr, "JSON parsing failed\n");
            assert_non_null(jso);
            rc = ifapi_json_TPMS_POLICY_HARNESS_deserialize (jso, &out);
            if (rc) fprintf(stderr, "Deserialization failed\n");
            assert_int_equal (rc, TSS2_RC_SUCCESS);
            json_object_put(jso);
            jso = NULL;
            rc = ifapi_json_TPMS_POLICY_HARNESS_serialize (&out, &jso);
            assert_int_equal (rc, TSS2_RC_SUCCESS);
            assert_non_null(jso);
            const char *jso_string = json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
            assert_non_null(jso_string);
            char *string1 = normalize(jso_string);
            char *string2 =  normalize(test_json_policy_or_expected);
            assert_string_equal(string1, string2);
            json_object_put(jso);
            ifapi_cleanup_policy_harness(&out);
            free(string1);
            free(string2);
        }
    free(test_json_policy_or_expected);
}


static void
check_json_tpm2bs(void **state)
{
    CHECK_JSON(TPM2B_DIGEST, "\"0x0102\"", "\"0102\"");
    CHECK_JSON(TPM2B_DIGEST, "\"0102\"", "\"0102\"");
    CHECK_JSON(TPM2B_DIGEST, "\"caffee\"", "\"caffee\"");
}

static void
check_error(void **state)
{
   /* Value is > then max value for UINT */
    CHECK_ERROR(UINT16, "\"0x10000\"", TSS2_FAPI_RC_BAD_VALUE);
    CHECK_ERROR(UINT32, "\"0x100000000\"", TSS2_FAPI_RC_BAD_VALUE);

    /* Digest/list is too large*/
    CHECK_ERROR(TPM2B_DIGEST, "\"0x0102222222222222222222222222222222222222222222222222222"
                "22222222222222222222222222222222222222222222222222222222222222222222222222222\"",
                TSS2_FAPI_RC_BAD_VALUE);

    /* Illegal values */
    CHECK_ERROR(TPMI_ALG_HASH, "\"SHA9999\"", TSS2_FAPI_RC_BAD_VALUE);
    CHECK_ERROR(TPM2B_DIGEST, "\"xxxx\"", TSS2_FAPI_RC_BAD_VALUE);
    CHECK_ERROR(TPM2B_DIGEST, "\"0x010x\"", TSS2_FAPI_RC_BAD_VALUE);
}


static void
check_tpmjson_tofromtxt(void **state)
{
    const char *testcase_alg_id[] = { "\"TPM_ALG_ID_SHA1\"", "\"TPM2_ALG_ID_SHA1\"",
                                      "\"ALG_ID_SHA1\"", "\"SHA1\"", "\"ALG_SHA1\"",
                                      "\"tpm2_alg_id_sha1\"", "\"sha1\"", "\"0x0004\"" };
    const char *expected_ald_id = { "\"SHA1\"" };
    for (size_t i = 0; i < sizeof(testcase_alg_id) / sizeof(testcase_alg_id[0]); i++) {
        CHECK_JSON_SIMPLE(TPM2_ALG_ID, testcase_alg_id[i], expected_ald_id);
    }

    const char *testcase_ecc_curve[] = { "\"TPM2_ECC_NIST_P256\"", "\"ECC_NIST_P256\"",
                                         "\"NIST_P256\"", "\"0x0003\"", "\"nist_p256\"" };
    const char *expected_ecc_curve = { "\"NIST_P256\"" };
    for (size_t i = 0; i < sizeof(testcase_ecc_curve) / sizeof(testcase_ecc_curve[0]); i++) {
        CHECK_JSON_SIMPLE(TPM2_ECC_CURVE, testcase_ecc_curve[i], expected_ecc_curve);
    }

    const char *testcase_cc[] = { "\"TPM2_CC_Startup\"", "\"CC_Startup\"",
                                  "\"Startup\"", "\"0x00000144\"" };
    const char *expected_cc = { "\"Startup\"" };
    for (size_t i = 0; i < sizeof(testcase_cc) / sizeof(testcase_cc[0]); i++) {
        CHECK_JSON_SIMPLE(TPM2_CC, testcase_cc[i], expected_cc);
    }

    const char *testcase_eo[] = { "\"TPM2_EO_EQ\"", "\"EO_EQ\"",
                                  "\"EQ\"", "\"0x0000\"" };
    const char *expected_eo = { "\"EQ\"" };
    for (size_t i = 0; i < sizeof(testcase_eo) / sizeof(testcase_eo[0]); i++) {
        CHECK_JSON_SIMPLE(TPM2_EO, testcase_eo[i], expected_eo);
    }

    const char *testcase_st[] = { "\"TPM2_ST_NO_SESSIONS\"", "\"ST_NO_SESSIONS\"",
                                  "\"no_SESSIONS\"", "\"0x8001\"" };
    const char *expected_st = { "\"NO_SESSIONS\"" };
    for (size_t i = 0; i < sizeof(testcase_st) / sizeof(testcase_st[0]); i++) {
        CHECK_JSON_SIMPLE(TPM2_ST, testcase_st[i], expected_st);
    }

    const char *testcase_pt_pcr[] = { "\"TPM2_PT_PCR_EXTEND_L0\"", "\"PT_PCR_EXTEND_L0\"",
                                  "\"PCR_EXTEND_L0\"", "\"EXTEND_L0\"" };
    const char *expected_pt_pcr = { "\"EXTEND_L0\"" };
    for (size_t i = 0; i < sizeof(testcase_pt_pcr) / sizeof(testcase_pt_pcr[0]); i++) {
        CHECK_JSON_SIMPLE(TPM2_PT_PCR, testcase_pt_pcr[i], expected_pt_pcr);
    }

    const char *testcase_alg_public[] = { "\"TPM2_ALG_RSA\"", "\"ALG_RSA\"",
                                          "\"RSA\"", "\"0x0001\"" };
    const char *expected_alg_public = { "\"RSA\"" };
    for (size_t i = 0; i < sizeof(testcase_alg_public) / sizeof(testcase_alg_public[0]); i++) {
        CHECK_JSON_SIMPLE(TPMI_ALG_PUBLIC, testcase_alg_public[i], expected_alg_public);
    }
}

int
main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_tpmjson_tofromtxt),
        cmocka_unit_test(check_json_structs),
        cmocka_unit_test(check_json_constants),
        cmocka_unit_test(check_json_numbers),
        cmocka_unit_test(check_json_bits),
        cmocka_unit_test(check_json_tpm2bs),
        cmocka_unit_test(check_json_to_bin),
        cmocka_unit_test(check_bin),
        cmocka_unit_test(check_policy_bin),
        cmocka_unit_test(check_error),
        cmocka_unit_test(check_json_policy),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
