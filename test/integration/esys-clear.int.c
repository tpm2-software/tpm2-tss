/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test of the ESAPI function Esys_Clear */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

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

    ESYS_TR authHandle_handle = ESYS_TR_RH_PLATFORM;

    r = Esys_Clear(esys_context,
                   authHandle_handle,
#ifdef TEST_SESSION
                   session,
#else
                   ESYS_TR_PASSWORD,
#endif
                   ESYS_TR_NONE,
                   ESYS_TR_NONE
                   );
    goto_if_error(r, "Error: Clear", error);

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);
#endif

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}
