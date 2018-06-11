/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * Test the ESAPI commands: HMAC_Start, SequenceUpdate, and SequenceComplete.
 * The HMAC key is created by using Esys_CreatePrimary.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

#ifdef TEST_SESSION
    ESYS_TR session;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);

    goto_if_error(r, "Error: During initialization of session", error);
#endif /* TEST_SESSION */

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0 },
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };
    inSensitivePrimary.sensitive.userAuth = authValuePrimary;
    TPM2B_PUBLIC inPublic = { 0 };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    ESYS_TR primaryHandle;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA1;

    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                           &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData,
                           &creationHash, &creationTicket);
    goto_if_error(r, "Error: CreatePrimary", error);

    r = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    ESYS_TR sequenceHandle;

    r = Esys_HMAC_Start(esys_context,
                        primaryHandle,
#ifdef TEST_SESSION
                        session,
#else
                        ESYS_TR_PASSWORD,
#endif
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &auth,
                        hashAlg,
                        &sequenceHandle
                        );
    goto_if_error(r, "Error: HashSequenceStart", error);

    TPM2B_MAX_BUFFER buffer ={.size = 20,
                              .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                       20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};
    r = Esys_TR_SetAuth(esys_context, sequenceHandle, &auth);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    r = Esys_SequenceUpdate(esys_context,
                            sequenceHandle,
#ifdef TEST_SESSION
                            session,
#else
                            ESYS_TR_PASSWORD,
#endif
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &buffer
                            );
    goto_if_error(r, "Error: SequenceUpdate", error);

    TPM2B_DIGEST *result;
    TPMT_TK_HASHCHECK *validation;

    r = Esys_SequenceComplete(esys_context,
                              sequenceHandle,
#ifdef TEST_SESSION
                              session,
#else
                              ESYS_TR_PASSWORD,
#endif
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &buffer,
                              TPM2_RH_OWNER,
                              &result,
                              &validation
                              );
    goto_if_error(r, "Error: SequenceComplete", error);

    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error: FlushContext", error);

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);
#endif

    return 0;

 error:
    return 1;
}
