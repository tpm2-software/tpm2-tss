/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{

    TSS2_RC r;

    TPM2B_DIGEST *randomBytes;
    r = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       48, &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom FAILED! Response Code : 0x%x", r);
        goto error;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

    LOG_INFO("GetRandom Test Passed!");

    ESYS_TR session;
    const TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

    LOG_INFO("GetRandom with session Test Passed!");

    return 0;

 error_cleansession:
    r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", r);
    }
 error:
    return 1;
}
