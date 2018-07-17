/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"
#include "tss2_mu.h"

#include "esys_iutil.h"
#include "test-esapi.h"
#define LOGMODULE test
#include "util/log.h"

#define FLUSH true
#define NOT_FLUSH false

/*
 * Function to compare policy digest with expected digest.
 * The digest is computed with Esys_PolicyGetDigest.
 */
bool
cmp_policy_digest(ESYS_CONTEXT * esys_context,
                  ESYS_TR * session,
                  TPM2B_DIGEST * expected_digest,
                  char *comment, bool flush_session)
{

    TSS2_RC r;
    TPM2B_DIGEST *policyDigest;

    r = Esys_PolicyGetDigest(esys_context,
                             *session,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);
    goto_if_error(r, "Error: PolicyGetDigest", error);

    LOGBLOB_DEBUG(&policyDigest->buffer[0], policyDigest->size,
                  "POLICY DIGEST");

    if (policyDigest->size != 20
        || memcmp(&policyDigest->buffer[0], &expected_digest->buffer[0],
                  policyDigest->size)) {
        free(policyDigest);
        LOG_ERROR("Error: Policy%s digest did not match expected policy.",
                  comment);
        return false;
    }
    free(policyDigest);
    if (flush_session) {
        r = Esys_FlushContext(esys_context, *session);
        goto_if_error(r, "Error: PolicyGetDigest", error);
        *session = ESYS_TR_NONE;
    }

    return true;

 error:
    return false;
}

/** This test is intended to test the ESAPI policy commands, not tested
 *  in other test cases.
 *  When possoble the commands are tested with a
 * trial session and the policy digest is compared with the expected digest.
 *
 * Tested ESAPI commands:
 *  - Esys_FlushContext() (M)
 *  - Esys_NV_DefineSpace() (M)
 *  - Esys_NV_UndefineSpace() (M)
 *  - Esys_PolicyCounterTimer() (M)
 *  - Esys_PolicyDuplicationSelect() (M)
 *  - Esys_PolicyGetDigest() (M)
 *  - Esys_PolicyNV() (M)
 *  - Esys_PolicyNameHash() (M)
 *  - Esys_PolicyNvWritten() (M)
 *  - Esys_PolicyOR() (M)
 *  - Esys_PolicyPCR() (M)
 *  - Esys_PolicyPhysicalPresence() (O)
 *  - Esys_PolicyRestart() (M)
 *  - Esys_SetPrimaryPolicy() (M)
 *  - Esys_StartAuthSession() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */
int
test_esys_policy_regression(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    ESYS_TR sessionTrialNV = ESYS_TR_NONE;
    ESYS_TR sessionTrialPCR = ESYS_TR_NONE;

    /* Dummy parameters for trial sessoin  */
    ESYS_TR sessionTrial = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetricTrial = {.algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };
    TPM2B_NONCE nonceCallerTrial = {
        .size = 20,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
    };

    /*
     * Test PolicyPCR
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    sessionTrialPCR = sessionTrial;
    TPML_PCR_SELECTION pcrSelection = {
        .count = 1,
        .pcrSelections = {
                          {.hash = TPM2_ALG_SHA1,
                           .sizeofSelect = 3,
                           .pcrSelect = {00, 00, 01},
                           },
                          }
    };
    /* SHA1 digest for PCR register with zeros */
    TPM2B_DIGEST pcr_digest_zero = {
        .size = 20,
        .buffer = {0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
                   0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f}
    };

    r = Esys_PolicyPCR(esys_context,
                       sessionTrial,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE, &pcr_digest_zero, &pcrSelection);
    goto_if_error(r, "Error: pcr digest can not be computed.", error);

    TPM2B_DIGEST expectedPolicyPCR = {
        .size = 20,
        .buffer = {0x85, 0x33, 0x11, 0x83, 0x19, 0x03, 0x12, 0xf5, 0xe8, 0x3c,
                   0x60, 0x43, 0x34, 0x6f, 0x9f, 0x37, 0x21, 0x04, 0x76, 0x8e},
    };

    if (!cmp_policy_digest(esys_context, &sessionTrial, &expectedPolicyPCR,
                           "PCR", NOT_FLUSH))
        goto error;

    /* Create valid NV handle */
    TPM2B_AUTH auth = {.size = 20,
        .buffer = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                   20, 21, 22, 23, 24, 25, 26, 27, 28, 29}
    };

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
                     .nvIndex = TPM2_NV_INDEX_FIRST,
                     .nameAlg = TPM2_ALG_SHA1,
                     .attributes = (TPMA_NV_OWNERWRITE |
                                    TPMA_NV_AUTHWRITE |
                                    TPMA_NV_WRITE_STCLEAR |
                                    TPMA_NV_READ_STCLEAR |
                                    TPMA_NV_AUTHREAD | TPMA_NV_OWNERREAD),
                     .authPolicy = {
                                    .size = 0,
                                    .buffer = {}
                                    ,
                                    }
                     ,
                     .dataSize = 32,
                     }
    };

    r = Esys_NV_DefineSpace(esys_context,
                            ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE, &auth, &publicInfo, &nvHandle);

    goto_if_error(r, "Error esys define nv space", error);

    /*
     * Test PolicyNV
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    sessionTrialNV = sessionTrial;
    UINT16 offset = 0;
    TPM2_EO operation = TPM2_EO_EQ;
    TPM2B_OPERAND operandB = {
        .size = 8,
        .buffer = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09}
    };

    r = Esys_PolicyNV(esys_context,
                      ESYS_TR_RH_OWNER,
                      nvHandle,
                      sessionTrial,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE, ESYS_TR_NONE, &operandB, offset, operation);
    goto_if_error(r, "Error: PolicyNV", error);

    TPM2B_DIGEST expectedPolicyNV = {
        .size = 20,
        .buffer = {0x09, 0x92, 0x96, 0x4c, 0x18, 0x4c, 0x29, 0xde, 0x53, 0x52,
                   0xc0, 0x20, 0x86, 0x81, 0xca, 0xe9, 0x94, 0x23, 0x09, 0x24}
    };

    if (!cmp_policy_digest(esys_context, &sessionTrial, &expectedPolicyNV,
                           "NV", NOT_FLUSH))
        goto error;

    /*
     * Test PolicyOR
     */

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    TPML_DIGEST pHashList = {
        .count = 2,
        .digests = {
                    expectedPolicyPCR,
                    expectedPolicyNV}
    };

    r = Esys_PolicyOR(esys_context,
                      sessionTrial,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pHashList);

    goto_if_error(r, "Error: PolicyOR", error);

    TPM2B_DIGEST expectedPolicyOR = {
        .size = 20,
        .buffer = {0x5d, 0x34, 0x38, 0xd3, 0xb8, 0xf0, 0x82, 0xef, 0x22, 0x12,
                   0xeb, 0x29, 0x54, 0xde, 0x66, 0x37, 0x06, 0x2f, 0xd8, 0x70}
    };

    if (!cmp_policy_digest(esys_context, &sessionTrial, &expectedPolicyOR,
                           "OR", FLUSH))
        goto error;

    r = Esys_FlushContext(esys_context, sessionTrialPCR);
    goto_if_error(r, "Error: FlushContext", error);
    sessionTrialPCR = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, sessionTrialNV);
    goto_if_error(r, "Error: FlushContext", error);
    sessionTrial = ESYS_TR_NONE;

    /*
     * Test PolicyCounterTimer
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    r = Esys_PolicyCounterTimer(esys_context,
                                sessionTrial,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE, &operandB, offset, operation);
    goto_if_error(r, "Error: PolicyCounterTimer", error);

    TPM2B_DIGEST expectedPolicyCounterTimer = {
        .size = 20,
        .buffer = {0x93, 0x8a, 0x9c, 0x7f, 0x60, 0xd4, 0xdd, 0xb5, 0x5a, 0x13,
                   0xc1, 0x7e, 0x3c, 0xe4, 0x62, 0x10, 0x82, 0xd0, 0x11, 0xad}
    };

    if (!cmp_policy_digest
        (esys_context, &sessionTrial, &expectedPolicyCounterTimer,
         "CounterTimter", NOT_FLUSH))
        goto error;

    /*
     * Test PolicyRestart
     */
    r = Esys_PolicyRestart(esys_context,
                           sessionTrial,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_error(r, "Error: PolicyRestart", error);

    TPM2B_DIGEST expectedPolicyRestart = {
        .size = 0,
        .buffer = {0}
    };

    if (!cmp_policy_digest(esys_context, &sessionTrial, &expectedPolicyRestart,
                           "Restart", FLUSH))
        goto error;

    /*
     * Test PolicyNameHash
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    TPM2B_DIGEST nameHash = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_PolicyNameHash(esys_context,
                            sessionTrial,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE, ESYS_TR_NONE, &nameHash);
    goto_if_error(r, "Error: PolicyNameHash", error);

    TPM2B_DIGEST expectedPolicyNameHash = {
        .size = 20,
        .buffer = {0xb4, 0x00, 0x9a, 0xb0, 0x80, 0x49, 0x55, 0x5f, 0x8c, 0xf2,
                   0x7b, 0x2e, 0x55, 0x7e, 0x74, 0x7d, 0x44, 0x39, 0x68, 0x7f}
    };

    if (!cmp_policy_digest(esys_context, &sessionTrial, &expectedPolicyNameHash,
                           "NameHash", FLUSH))
        goto error;

    /*
     * Test PolicyDuplicationSelect
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    TPM2B_NAME name1 = {
        .size = 20,
        .name = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    TPM2B_NAME name2 = {
        .size = 20,
        .name = {21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                 31, 32, 33, 34, 35, 36, 37, 38, 39, 30}
    };

    r = Esys_PolicyDuplicationSelect(esys_context,
                                     sessionTrial,
                                     ESYS_TR_NONE,
                                     ESYS_TR_NONE,
                                     ESYS_TR_NONE, &name1, &name2, 0);
    goto_if_error(r, "Error: PolicyDuplicationSelect", error);

    TPM2B_DIGEST expectedPolicyDuplicationSelect = {
        .size = 20,
        .buffer = {0x53, 0x77, 0xf5, 0x82, 0x83, 0x18, 0xa9, 0xee, 0x76, 0x70,
                   0xa8, 0x31, 0x5d, 0x5c, 0x04, 0xb4, 0xaa, 0xaf, 0x96, 0x8f}
    };

    if (!cmp_policy_digest
        (esys_context, &sessionTrial, &expectedPolicyDuplicationSelect,
         "PolicyDuplicationSelect", FLUSH))
        goto error;

    goto_if_error(r, "Error: FlushContext", error);

    /*
     * Test PolicyNvWritten
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    r = Esys_PolicyNvWritten(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 0);
    goto_if_error(r, "Error: PolicyNvWritten", error);

    TPM2B_DIGEST expectedPolicyNvWritten = {
        .size = 20,
        .buffer = {0x5a, 0x91, 0xe7, 0x10, 0x53, 0x86, 0xbd, 0x54, 0x7a, 0x15,
                   0xaa, 0xd4, 0x03, 0x69, 0xb1, 0xe2, 0x5e, 0x46, 0x28, 0x73}
    };

    if (!cmp_policy_digest(esys_context, &sessionTrial, &expectedPolicyNvWritten,
                           "NvWritten", FLUSH))
        goto error;

    /*
     * Space not needed for further tests.
     */

    r = Esys_NV_UndefineSpace(esys_context,
                              ESYS_TR_RH_OWNER,
                              nvHandle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
    goto_if_error(r, "Error: NV_UndefineSpace", error);
    nvHandle = ESYS_TR_NONE;

    /*
     * Test PolicySetPrimaryPolicy
     */

    TPM2B_DIGEST authPolicy = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_SetPrimaryPolicy(esys_context,
                              ESYS_TR_RH_OWNER,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE, ESYS_TR_NONE,
                              &authPolicy,
                              TPM2_ALG_SHA1);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_SetPrimaryPolicy  not supported by TPM.");
    } else {
        goto_if_error(r, "Error: SetPrimaryPolicy", error);
    }

    return EXIT_SUCCESS;

 error:

    if (sessionTrial != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, sessionTrial) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup sessionTrial failed.");
        }
    }

    if (sessionTrialPCR != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, sessionTrialPCR) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup sessionTrialPCR failed.");
        }
    }

    if (nvHandle != ESYS_TR_NONE) {
        if (Esys_NV_UndefineSpace(esys_context,
                                  ESYS_TR_RH_OWNER,
                                  nvHandle,
                                  ESYS_TR_PASSWORD,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE) != TSS2_RC_SUCCESS) {
             LOG_ERROR("Cleanup nvHandle failed.");
        }
    }

    return failure_return;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    return test_esys_policy_regression(esys_context);
}
