/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

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
 *  - Esys_PolicyAuthorizeNV() (F)
 *  - Esys_PolicyNV() (M)
 *  - Esys_PolicyPhysicalPresence() (O)
 *  - Esys_PolicyTemplate() (F)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */
int
test_esys_policy_regression_opt(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;
    ESYS_TR nvHandle = ESYS_TR_NONE;
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
     * Test PolicyAuthorizeNV
     */
    r = Esys_PolicyAuthorizeNV(esys_context,
                               ESYS_TR_RH_OWNER,
                               nvHandle,
                               sessionTrial,
                               ESYS_TR_PASSWORD,
                               ESYS_TR_NONE, ESYS_TR_NONE);
    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_PolicyAuthorizeNV  not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    } else {
        goto_if_error(r, "Error: PolicyAuthorizeNV", error);
    }

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

    r = Esys_FlushContext(esys_context, sessionTrial);
    goto_if_error(r, "Error: FlushContext", error);
    sessionTrial = ESYS_TR_NONE;


    /*
     * Test PolicyTemplate
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    TPM2B_DIGEST templateHash = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_PolicyTemplate(esys_context,
                            sessionTrial,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE, ESYS_TR_NONE, &templateHash);
    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_PolicyTemplate  not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    } else {
        goto_if_error(r, "Error: PolicyTemplate", error);

        TPM2B_DIGEST expectedPolicyTemplate = {
            .size = 20,
            .buffer =
                {0xf6, 0x6d, 0x2a, 0x9c, 0x6e, 0xa8, 0xdf, 0x1a, 0x49, 0x3c,
                 0x42, 0xcc, 0xac, 0x6e, 0x3d, 0x08, 0xc0, 0x84, 0xcf, 0x73}
        };

        if (!cmp_policy_digest
            (esys_context, &sessionTrial, &expectedPolicyTemplate, "Template",
             FLUSH))
            goto error;
    }

    /*
     * Test PolicyPhysicalPresence
     */
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session",
                  error);

    r = Esys_PolicyPhysicalPresence(esys_context,
                                    sessionTrial,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_error(r, "Error: PolicyPhysicalPresence", error);

    TPM2B_DIGEST expectedPolicyPhysicalPresence = {
        .size = 20,
        .buffer = {0x9a, 0xcb, 0x06, 0x39, 0x5f, 0x83, 0x1f, 0x88, 0xe8, 0x9e,
                   0xea, 0xc2, 0x94, 0x42, 0xcb, 0x0e, 0xbe, 0x94, 0x85, 0xab}
    };

    if (!cmp_policy_digest
        (esys_context, &sessionTrial, &expectedPolicyPhysicalPresence,
         "PhysicalPresence", FLUSH))
        goto error;

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
    return test_esys_policy_regression_opt(esys_context);
}
