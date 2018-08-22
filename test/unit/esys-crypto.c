/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_esys.h"
#include "esys_crypto.h"

#define LOGMODULE tests
#include "util/log.h"

/**
 * This unit tst checks several error cases of the crypto backends, which are not
 * covered by the integration tests.
 */

static void
check_hash_functions(void **state)
{
    TSS2_RC rc;
    IESYS_CRYPTO_CONTEXT_BLOB *context;
    uint8_t buffer[10] = { 0 };
    TPM2B tpm2b;
    size_t size = 0;
    
    rc = iesys_crypto_hash_start(NULL, TPM2_ALG_SHA384);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

#ifndef OSSL
    rc = iesys_crypto_hash_start(&context, TPM2_ALG_SHA512);
    assert_int_equal (rc, TSS2_ESYS_RC_NOT_IMPLEMENTED);
#endif

    rc = iesys_crypto_hash_start(&context, 0);
    assert_int_equal (rc, TSS2_ESYS_RC_NOT_IMPLEMENTED);

    rc = iesys_crypto_hash_start(&context, TPM2_ALG_SHA384);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    rc = iesys_crypto_hash_finish(NULL, &buffer[0], &size);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hash_finish(&context, &buffer[0], &size);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_SIZE);

    iesys_crypto_hash_abort(NULL);
    iesys_crypto_hash_abort(&context);

    rc = iesys_crypto_hash_update(NULL, &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hash_update2b(NULL, &tpm2b);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    /* Create invalid context */
    rc = iesys_crypto_hmac_start(&context, TPM2_ALG_SHA1, &buffer[0], 10);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    iesys_crypto_hash_abort(&context);

    rc = iesys_crypto_hash_update(context, &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hash_finish(&context, &buffer[0], &size);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);
} 

static void
check_hmac_functions(void **state)
{
    TSS2_RC rc;
    IESYS_CRYPTO_CONTEXT_BLOB *context;
    uint8_t buffer[10] = { 0 };
    TPM2B tpm2b;
    size_t size = 0;
    
    rc = iesys_crypto_hmac_start(NULL, TPM2_ALG_SHA384, &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

#ifndef OSSL
    rc = iesys_crypto_hmac_start(&context, TPM2_ALG_SHA512, &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_NOT_IMPLEMENTED);
#endif

    rc = iesys_crypto_hmac_start(&context, 0,  &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_NOT_IMPLEMENTED);

    rc = iesys_crypto_hmac_start(&context, TPM2_ALG_SHA1,  &buffer[0], 10);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    rc = iesys_crypto_hmac_finish(NULL, &buffer[0], &size);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hmac_finish2b(NULL, &tpm2b);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hmac_finish(&context, &buffer[0], &size);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_SIZE);

    iesys_crypto_hmac_abort(NULL);
    iesys_crypto_hmac_abort(&context);

    rc = iesys_crypto_hmac_update(NULL, &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hmac_update2b(NULL, &tpm2b);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    /* Create invalid context */
    rc = iesys_crypto_hash_start(&context, TPM2_ALG_SHA1);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    iesys_crypto_hmac_abort(&context);

    rc = iesys_crypto_hmac_update(context, &buffer[0], 10);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_hmac_finish(&context, &buffer[0], &size);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);
}

static void
check_random(void **state)
{
    TSS2_RC rc;
    size_t num_bytes = 0;
    TPM2B_NONCE nonce;
    rc = iesys_crypto_random2b(&nonce, num_bytes);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
} 

static void
check_pk_encrypt(void **state)
{
    TSS2_RC rc;
    uint8_t in_buffer[5] = { 1, 2, 3, 4, 5 };
    size_t size = 5;
    uint8_t out_buffer[5];
    TPM2B_PUBLIC inPublicRSA = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
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
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_NULL,
                  },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {}
                 ,
             }
        }
    };
   
    inPublicRSA.publicArea.nameAlg = 0;
    rc = iesys_crypto_pk_encrypt(&inPublicRSA, size, &in_buffer[0], size, &out_buffer[0], &size, "LABEL");
    assert_int_equal (rc, TSS2_ESYS_RC_NOT_IMPLEMENTED);

    inPublicRSA.publicArea.nameAlg = TPM2_ALG_SHA1;
    inPublicRSA.publicArea.parameters.rsaDetail.scheme.scheme = 0;
    rc = iesys_crypto_pk_encrypt(&inPublicRSA, size, &in_buffer[0], size, &out_buffer[0], &size, "LABEL");
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_VALUE);
}

static void
check_aes_encrypt(void **state)
{
    TSS2_RC rc;
    uint8_t key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16  };
    uint8_t buffer[5] = { 1, 2, 3, 4, 5 };
    size_t size = 5;

    rc = iesys_crypto_sym_aes_encrypt(NULL, TPM2_ALG_AES, 192, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);
    
    rc = iesys_crypto_sym_aes_encrypt(&key[0], TPM2_ALG_AES, 192, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    rc = iesys_crypto_sym_aes_encrypt(&key[0], TPM2_ALG_AES, 256, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    rc = iesys_crypto_sym_aes_encrypt(&key[0], 0, 256, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_VALUE);

    rc = iesys_crypto_sym_aes_encrypt(&key[0], TPM2_ALG_AES, 256, 0, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_VALUE);

    rc = iesys_crypto_sym_aes_encrypt(&key[0], TPM2_ALG_AES, 999, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_VALUE);

    rc = iesys_crypto_sym_aes_decrypt(NULL, TPM2_ALG_AES, 192, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);

    rc = iesys_crypto_sym_aes_decrypt(&key[0], 0, 192, TPM2_ALG_CFB, 16,
                                      &buffer[0], size, &key[0]);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_VALUE);
}

static void
check_free(void **state)
{
    uint8_t *buffer;

    buffer = malloc(10);
    esys_free(buffer);
}



int
main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_hash_functions),
        cmocka_unit_test(check_hmac_functions),
        cmocka_unit_test(check_random),
        cmocka_unit_test(check_pk_encrypt),
        cmocka_unit_test(check_aes_encrypt),
        cmocka_unit_test(check_free),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
