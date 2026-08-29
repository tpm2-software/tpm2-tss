/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h> // for uint8_t, uint32_t
#include <stdio.h>  // for NULL, fopen, size_t, fclose, fileno, fseek
#include <stdlib.h> // for malloc, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // for memcmp, strlen, strcmp, strncmp
#include <unistd.h> // for read

#include "test-fapi.h"       // for pcr_reset, EXIT_SKIP, FAPI_PROFILE, tes...
#include "tss2_common.h"     // for TSS2_FAPI_RC_GENERAL_FAILURE, TSS2_RC
#include "tss2_fapi.h"       // for Fapi_Free, Fapi_Delete, Fapi_Decrypt
#include "tss2_tpm2_types.h" // for TPM2_ALG_SHA384

#define LOGMODULE test
#include "util/log.h" // for LOG_ERROR, goto_if_error, SAFE_FREE

/** Test the FAPI functions for ECC encryption and decryption.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_CreateKey()
 *  - Fapi_Encrypt()
 *  - Fapi_Decrypt()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

#define SIZE 5
int
test_fapi_ecc_encrypt_decrypt(FAPI_CONTEXT *context) {

    uint8_t  plain[SIZE] = { 1, 2, 3, 4, 5 };
    uint8_t *plain_out = NULL;
    size_t   cipher_size;
    uint8_t *cipher = NULL;
    size_t   plain_out_size;
    int      test_rc = EXIT_SUCCESS;
    TSS2_RC  r;

    if (strcmp(FAPI_PROFILE, "P_ECC") != 0) {
        return EXIT_SKIP;
    }

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_CreateKey(context, "HS/SRK/myEccCryptKey", "decrypt", NULL, NULL);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_Encrypt(context, "HS/SRK/myEccCryptKey", &plain[0], SIZE, &cipher, &cipher_size);

    if ((r == TPM2_RC_COMMAND_CODE) || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        test_rc = EXIT_SKIP;
        goto cleanup;
    }

    goto_if_error(r, "Error Fapi_Encrypt", error);

    r = Fapi_Decrypt(context, "HS/SRK/myEccCryptKey", cipher, cipher_size, &plain_out,
                     &plain_out_size);
    goto_if_error(r, "Error Fapi_Decrypt", error);

    if (plain_out_size != SIZE || memcmp(plain_out, plain, SIZE) != 0) {
        LOG_ERROR("Error: decrypted text not  equal to origin");
        goto error;
    }
    goto cleanup;

error:
    test_rc = EXIT_FAILURE;

cleanup:
    Fapi_Delete(context, "/");
    SAFE_FREE(plain_out);
    SAFE_FREE(cipher);
    return test_rc;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context) {
    return test_fapi_ecc_encrypt_decrypt(fapi_context);
}
