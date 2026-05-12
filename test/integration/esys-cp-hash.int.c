/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2025, Juergen Repp
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for free, NULL, EXIT_FAILURE, EXIT_SUCCESS

#include "tss2_common.h"     // for BYTE, TSS2_RC
#include "tss2_esys.h"       // for ESYS_TR_NONE, Esys_GetRandom, Esys_Star...
#include "tss2_tpm2_types.h" // for TPM2B_DIGEST, TPM2_RC_SUCCESS, TPMA_SES...

#define LOGMODULE test
#include "util/log.h" // for LOG_ERROR, LOGBLOB_DEBUG, LOG_INFO

/** Test the ESYS function Esys_GetRandom.
 *
 * Tested ESYS commands:
 *  - Esys_GetRandom() (M)
 *  - Esys_StartAuthSession() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esyscp_hash(ESYS_CONTEXT *esys_context) {

    TSS2_RC r;
    int     i;

    TPM2B_DIGEST *randomBytes;

    uint8_t get_rand_cp_hash[32]
        = { 0xc0, 0x75, 0xb7, 0xe6, 0x37, 0xa7, 0x13, 0x1b, 0x0c, 0x52, 0x3c,
            0xf1, 0x96, 0x5e, 0xba, 0xe2, 0xaf, 0xb1, 0x16, 0x0b, 0x6e, 0xf7,
            0xc7, 0xe9, 0x2d, 0x0d, 0x24, 0xce, 0x0a, 0x5d, 0x94, 0x11 };

    ESYS_TR            session = ESYS_TR_NONE;
    const TPMT_SYM_DEF symmetric
        = { .algorithm = TPM2_ALG_AES, .keyBits = { .aes = 128 }, .mode = { .aes = TPM2_ALG_CFB } };
    uint8_t *cp_hash;
    size_t   cp_hash_size;
    uint8_t *rp_hash;
    size_t   rp_hash_size;

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom_Async(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetCpHash(esys_context, TPM2_ALG_SHA256, &cp_hash, &cp_hash_size);

    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetCpHash FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(cp_hash, cp_hash_size, "cp hash");

    /* Check cp hash for get_random with 48 bytes. */
    for (i = 0; i < 32; i++) {
        if (cp_hash[i] != get_rand_cp_hash[i]) {
            LOG_ERROR("Wrong cp hash value.");
            free(cp_hash);
            goto error_cleansession;
        }
    }
    free(cp_hash);

    do {
        /* Call call finish as long as retry return codes are returned. */
        r = Esys_GetRandom_Finish(esys_context, &randomBytes);
        if (r == TSS2_RC_SUCCESS) {
            break;
        } else if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN) {
            continue;
        } else {
            LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
            goto error_cleansession;
        }
    } while (1);

    r = Esys_GetRpHash(esys_context, TPM2_ALG_SHA256, &rp_hash, &rp_hash_size);

    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRpHash FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }
    free(rp_hash);

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

    r = Esys_GetRandom_Async(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetCpHash(esys_context, TPM2_ALG_SHA256, &cp_hash, &cp_hash_size);

    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetCpHash FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    free(cp_hash);

    /* Check whether call of Esys_GetRandom works after abort. */

    r = Esys_Abort(esys_context);

    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Abort FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }
    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48, &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    free(randomBytes);

    r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", r);
    }

    return EXIT_SUCCESS;

error_cleansession:
    r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", r);
    }
error:
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esyscp_hash(esys_context);
}
