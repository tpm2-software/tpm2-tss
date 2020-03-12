#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "tss2_sys.h"
#include "tss2_mu.h"

#define LOGMODULE test
#include "util/log.h"
#include "test-options.h"
#include "context-util.h"

int
main (int argc, char *argv[])
{
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sapi_context;
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {
        .auths = {{ .sessionHandle = TPM2_RS_PW }},
        .count = 1
    };
    TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
    TPM2B_PUBLIC in_public = {
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_ADMINWITHPOLICY |
                TPMA_OBJECT_RESTRICTED |
                TPMA_OBJECT_DECRYPT
             ),
            .authPolicy = {
                 .size = 32,
                 .buffer = 0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
                           0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
                           0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
                           0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                           0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
                           0x69, 0xAA,
             },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 256,
                .buffer = {0},
            }
        }
    };
    TPML_PCR_SELECTION creation_pcr = { 0 };
    TPM2_HANDLE handle;
    TPM2B_PUBLIC out_public = { 0 };
    TSS2L_SYS_AUTH_RESPONSE auth_rsp = {
        .count = 0
    };

    test_opts_t opts = {
        .tcti_type      = TCTI_DEFAULT,
        .device_file    = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port    = PORT_DEFAULT,
    };

    get_test_opts_from_env (&opts);
    if (sanity_check_test_opts (&opts) != 0)
        exit (1);

    sapi_context = sapi_init_from_opts (&opts);
    if (sapi_context == NULL)
        exit (1);

    /* Generate the EK key */

    rc = Tss2_Sys_CreatePrimary(sapi_context, TPM2_RH_ENDORSEMENT, &auth_cmd,
                                &in_sensitive, &in_public, NULL, &creation_pcr,
                                &handle, &out_public, NULL, NULL, NULL, NULL, &auth_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM CreatePrimary FAILED: 0x%"PRIx32, rc);
        exit(1);
    }

    rc = Tss2_Sys_FlushContext(sapi_context, handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM FlushContext FAILED: 0x%"PRIx32, rc);
        exit(1);
    }

    sapi_teardown_full (sapi_context);

    /* Convert the key from out_public to PEM */

    EVP_PKEY *evp = EVP_PKEY_new();
    BIO *bio;
    FILE *out = NULL;

    if (argc == 2) {
	out = fopen(argv[1], "w");
	if (!out) {
	    LOG_ERROR("Can not open file %s", argv[1]);
	    exit(1);
	}
        bio = BIO_new_fp(out, BIO_NOCLOSE);
    }
    else
        bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *dmp1 = BN_new();
    BIGNUM *dmq1 = BN_new();
    BIGNUM *iqmp = BN_new();
    BIGNUM *n = BN_bin2bn(out_public.publicArea.unique.rsa.buffer,
                          out_public.publicArea.unique.rsa.size, NULL);
    BN_set_word(d, 0);
    BN_set_word(p, 0);
    BN_set_word(q, 0);
    BN_set_word(dmp1, 0);
    BN_set_word(dmq1, 0);
    BN_set_word(iqmp, 0);
    uint32_t exp;
    if (out_public.publicArea.parameters.rsaDetail.exponent == 0)
        exp = 65537;
    else
        exp = out_public.publicArea.parameters.rsaDetail.exponent;
    BN_set_word(e, exp);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    rsa->e = e;
    rsa->n = n;
    rsa->d = d;
    rsa->p = p;
    rsa->q = q;
    rsa->dmp1 = dmp1;
    rsa->dmq1 = dmq1;
    rsa->iqmp = iqmp;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    EVP_PKEY_assign_RSA(evp, rsa);

    if (!PEM_write_bio_PUBKEY(bio, evp)) {
        LOG_ERROR("PEM_write failed");
        exit(1);
    }

    EVP_PKEY_free(evp);
    BIO_free(bio);
    fclose(out);

    return 0;
}
