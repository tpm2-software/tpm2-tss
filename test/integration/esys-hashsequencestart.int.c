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
 * Test the ESAPI commands HashSequenceStart, SequenceUpdate,
 * and SequenceComplete.
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

    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA256;
    ESYS_TR sequenceHandle_handle;

    r = Esys_HashSequenceStart(esys_context,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               &auth,
                               hashAlg,
                               &sequenceHandle_handle
                               );
    goto_if_error(r, "Error: HashSequenceStart", error);

    TPM2B_MAX_BUFFER buffer = {.size = 20,
                              .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                       20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    r = Esys_TR_SetAuth(esys_context, sequenceHandle_handle, &auth);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    r = Esys_SequenceUpdate(esys_context,
                            sequenceHandle_handle,
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
                              sequenceHandle_handle,
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

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);
#endif

    return 0;

 error:
    return 1;
}
