/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for free, NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>           // for memcmp

#include "tss2_common.h"      // for BYTE, TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_EvictControl, Esys_F...
#include "tss2_tpm2_types.h"  // for TPM2B_NAME, TPM2_PERSISTENT_FIRST, TPM2...

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error, LOG_ERROR, LOG_INFO

/** This tests the Esys_TR_FromTPMPublic and Esys_TR_GetName functions by
 *  creating an NV Index and then attempting to retrieve an ESYS_TR object for
 *  it.
 *  Then we call Esys_TR_GetName to see if the correct public name has been
 * retrieved.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_EvictControl() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_ReadPublic() (M)
 *
 * @param[in,out] ectx The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

int
test_esys_tr_fromTpmPublic_key(ESYS_CONTEXT * ectx)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR keyHandle = ESYS_TR_NONE;

    TPM2B_NAME *name1, *name2;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
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

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_NULL
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
    LOG_INFO("\nRSA key will be created.");

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    /*
     * Do this twice to test that Esys_TR_FromTPMPublic doesn't error
     * due to the handle not being closed by Esys_EvictControl
     */
    for (int i = 0; i < 2; i++) {
        /*
         * Change public data to verify that handle is closed on
         * Esys_EvictControl delete
         */
        if (i == 1) {
            inPublic.publicArea.unique.rsa.size = 2048 / 8;
            inPublic.publicArea.unique.rsa.buffer[0] = 1;
        }

        r = Esys_CreatePrimary(ectx, ESYS_TR_RH_OWNER,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &inSensitivePrimary, &inPublic, &outsideInfo,
                               &creationPCR,
                               &primaryHandle, NULL, NULL, NULL, NULL);
        goto_if_error(r, "Create primary", error);

        r = Esys_ReadPublic(ectx, primaryHandle,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            NULL, &name1, NULL);
        goto_if_error(r, "Read Public", error);

        r = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, primaryHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              TPM2_PERSISTENT_FIRST, &keyHandle);
        goto_if_error(r, "EvictControl make persistent", error_name1);

        LOG_ERROR("Key handle (1) 0x%x", keyHandle);

        r = Esys_FlushContext(ectx, primaryHandle);
        goto_if_error(r, "Flushing primary", error_name1);

        r = Esys_TR_Close(ectx, &keyHandle);
        goto_if_error(r, "TR close on object", error_name1);

        r = Esys_TR_FromTPMPublic(ectx, TPM2_PERSISTENT_FIRST,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &keyHandle);
        goto_if_error(r, "TR from TPM public", error_name1);

        r = Esys_TR_FromTPMPublic(ectx, TPM2_PERSISTENT_FIRST,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &keyHandle);
        goto_if_error(r, "TR from TPM public", error_name1);

        r = Esys_TR_Close(ectx, &keyHandle);
        goto_if_error(r, "TR close on object", error_name1)

        LOG_ERROR("Key handle (2) 0x%x", keyHandle);

        r = Esys_TR_GetName(ectx, keyHandle, &name2);
        goto_if_error(r, "TR get name", error_name1);

        r = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, keyHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              TPM2_PERSISTENT_FIRST, &keyHandle);
        goto_if_error(r, "EvictControl delete", error_name2);

        LOG_ERROR("Key handle (after delete) 0x%x", keyHandle);

        if (name1->size != name2->size ||
            memcmp(&name1->name[0], &name2->name[0], name1->size) != 0)
        {
            LOG_ERROR("Names mismatch between NV_GetPublic and TR_GetName");
            goto error_name2;
        }

        free(name1);
        free(name2);
    }

    return EXIT_SUCCESS;

error_name2:
    free(name2);
error_name1:
    free(name1);
error:

    if (keyHandle != ESYS_TR_NONE) {
        if (Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, keyHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              TPM2_PERSISTENT_FIRST, &keyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup: EvictControl delete");
        }
    }

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(ectx, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_tr_fromTpmPublic_key(esys_context);
}
