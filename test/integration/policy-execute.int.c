/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"                        // for NDEBUG
#endif

/*
 * All builds should consider this DEBUG code since we need assert()
 * to not be compiled out. Thus is Not Debug NDEBUG is defined, undef
 * it.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>                        // for assert
#include <limits.h>                        // for PATH_MAX
#include <openssl/bio.h>                   // for BIO_free, BIO_new_mem_buf
#include <openssl/bn.h>                    // for BN_bn2bin, BN_num_bytes
#include <openssl/ec.h>                    // for ECDSA_SIG_free, ECDSA_SIG_...
#include <openssl/evp.h>                   // for EVP_DigestSignFinal, EVP_P...
#include <openssl/pem.h>                   // for PEM_read_bio_PUBKEY, PEM_r...
#include <openssl/rsa.h>                   // for EVP_PKEY_CTX_set_rsa_padding
#include <stdbool.h>                       // for false, bool, true
#include <stdint.h>                        // for uint8_t
#include <stdio.h>                         // for NULL, size_t, fclose, fopen
#include <stdlib.h>                        // for calloc, free, malloc, EXIT...
#include <string.h>                        // for memcpy, strcmp, strlen

#include "tss2_common.h"                   // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"                     // for ESYS_TR_NONE, Esys_PolicyG...
#include "tss2_tpm2_types.h"               // for TPM2B_DIGEST, TPMS_PCR_SEL...

#define LOGMODULE test
#include "test/data/test-fapi-policies.h"  // for policy_digests, _test_fapi...
#include "tss2_policy.h"                   // for TSS2_POLICY_PCR_SELECTION
#include "util/log.h"                      // for LOG_ERROR, goto_if_error
#include "util/tss2_endian.h"              // for HOST_TO_BE_32

struct mycb_data;

#define TEST_LAYER        TSS2_RC_LAYER(0)
#define TSS2_RC_TEST_FAIL ((TSS2_RC)(TEST_LAYER | \
                            TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_RC_TEST_NOT_SUPPORTED ((TSS2_RC)(TEST_LAYER | \
                            TSS2_BASE_RC_NOT_SUPPORTED))
#define TSS2_RC_TEST_KEY_NOT_FOUND ((TSS2_RC)(TEST_LAYER | \
                            TSS2_BASE_RC_KEY_NOT_FOUND))
#define TSS2_RC_TEST_MEMORY ((TSS2_RC)(TEST_LAYER | \
                            TSS2_BASE_RC_MEMORY))

#define PCR_8 8

static uint8_t *global_signature = NULL;

static char *read_all(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    char *buffer = calloc(1, fsize + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    size_t count_read = fread(buffer, fsize, 1, f);
    fclose(f);
    if (count_read != 1) {
        return NULL;
    }

    return buffer;
}

typedef struct mycb_data mycb_data;
struct mycb_data {
    ESYS_CONTEXT *esys_ctx;
    ESYS_TR session;
    TPM2B_DIGEST update_digest;
    TPM2_ALG_ID session_halg;
};

static TSS2_RC polsel_cb (
    TSS2_OBJECT *auth_object,
    const char **branch_names,
    size_t branch_count,
    size_t *branch_idx,
    void *userdata)
{
    UNUSED(auth_object);
    UNUSED(branch_names);
    UNUSED(branch_count);
    UNUSED(userdata);
    /* take branch branch0 so the PCR values align */
    *branch_idx = 0;

    return TSS2_RC_SUCCESS;
}
#define RSA_SIG_SCHEME RSA_PKCS1_PSS_PADDING

static TSS2_RC sign_cb (
    char *key_pem,
    char *public_key_hint,
    TPMI_ALG_HASH key_pem_hash_alg,
    uint8_t *buffer,
    size_t buffer_size,
    const uint8_t **signature,
    size_t *signature_size,
    void *userdata)
{
    const char *priv_key_pem = NULL;

    /* these also exist in fapi-key-create-policy-signed.int.c */
    /* see test/data/fapi/policy/ecc.pem */
    static const char *priv_ecc_pem = "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEILE8jic/6w/lKoFTVblkNQ4Ls5IYibQNQ4Dk5B9R09ONoAoGCCqGSM49\n"
            "AwEHoUQDQgAEoJTa3zftdAzHC96IjpqQ/dnLm+p7pEiLMi03Jd0oP0aYnnXFjolz\n"
            "IB/dBZ/t+BLh0PwLM5aAM/jugeLkHgpIyQ==\n"
            "-----END EC PRIVATE KEY-----\n";

    /* see test/data/fapi/policy/ecc.pem */
    static const char *pub_ecc_pem = "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoJTa3zftdAzHC96IjpqQ/dnLm+p7\n"
            "pEiLMi03Jd0oP0aYnnXFjolzIB/dBZ/t+BLh0PwLM5aAM/jugeLkHgpIyQ==\n"
            "-----END PUBLIC KEY-----\n";

    /* see test/data/fapi/policy/rsa2.pem */
    static const char *priv_rsa_pem = "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCgYvoisJIDOeYg\n"
            "jMF6ywiZbu085TLvy5ZMhq5vfYqdgefvwpemutnfKSnpYOs5B4yO/gAD7XiYluDv\n"
            "tqlVhfISeQV04xrWGzNImenpwm/HsgueAu8VTHNtWSL96G+BLedGTrs2NqX6cxN7\n"
            "yGl7dQpB5X8iP4XSvpjP3Vb7gs+adwCJR6xFkt60jYFmwrAdhEzOeakhimi5rU21\n"
            "LxCkRdEyaxS57X15L9dEA+aYJ+dvkFfZOfTqIKmTrA75F8yj161xflwtIC4hgRBg\n"
            "K9Xb/RdN8TDrTu+20E3RjngutU4qejW9Fd3mzHJGV8HRYvjYXhUblN9wmjm7Veru\n"
            "T2b0rnvzAgMBAAECggEBAIwHvoJ5DRJ6A50Zp3dROxHTEphfOEi6xF/OGxBGWLbK\n"
            "C7l+eS9d5gj8BJa5QsXI/IR/6X2EYQ1AdeV04oVD7CUKuqPiALU8jFrv3pV0aGm+\n"
            "3nu37gv3crPe5jkvLeNoM4tkA/oCXom63SDuyoG6nxkHiSdatLlaJUse4em3vRAL\n"
            "QivziZIMyswcleMe0xAoMi7LO+nUFFxBS8/xGya0vsU0dsMQEl1SRITv1VCXmPQD\n"
            "T4dEI4+1cufv6Ax0EDbFKmnjyiGTjOeQKrGIqETUSQolbg5PgL1XZehaaxM822OY\n"
            "Qpnp5T0XhUEmVrOb2Wrboj+dC/2tgAN/fWXjAAxnm2ECgYEA02UTZuZ+QnD6tqo3\n"
            "/y3n5kaM9uA2mdOIqgECI9psGF1IBIC/iP2diKyuvmQL8hzymComb5YzZl3TOAga\n"
            "WHQYbIeU3JhnYTG75/Dv5Zh32H4NjkIJHT2/8LUM25Ove9u6QAniVgIQpBZ47LjX\n"
            "9jHjTYCW5n79qNSfu0egYJUvypECgYEAwjqWzzEINqnX/xIVCoB4XpuDuSdkM0JW\n"
            "MZDIH9xHjZPp07/5XYEoITylk6Zwbh+djvWDNP4gzPtuK26VsqrNxoWMsFZeXn6U\n"
            "xSOYL2UNCZiOgchdZCOr+6r8LRUuo8xHjbawVoJVK1+tZ2WsR3ilt3Gw34O8Z5ep\n"
            "f4v7GOXw+EMCgYAUHjFrgJIRhqkFi0uK+HZyXtJ5iDsKBqyh6Tin6tiQtQfujcYs\n"
            "pl5ArJZwvhq47vJTcud3hSbdHh7E3ViMhHfylDChkct833vPhgl+ozT8oHpvyG8P\n"
            "nlnO8ZwIpZR0yCOAhrBImSe2RgE6HhlHb9X/ATbbNsizMZEGBLoJlwkWUQKBgQCy\n"
            "4U7fh2LvJUF+82JZh7RUPZn1Pmg0JVZI0/TcEv37UEy77kR1b2xMIBTGhTVq1sc/\n"
            "ULIEbkA7SR1P9sr7//8AZSMLjJ/hG2dcoMmabNCzE8O7l5MblRbh87nIs4d+57bG\n"
            "t4h0RBi4l6eWYLdoI59L8fNaB3PPXIiIpZ0eczeZDQKBgQC2vuFYpUZqDb9CaJsn\n"
            "Luee6P6n5v3ZBTAT4E+GG1kWS28BiebcCuLKNAY4ZtLo08ozaTWcMxooOTeka2ux\n"
            "fQDE4M/LTNpam8QOJ2hqECF5a0uBYNcbmaGtfA9KwIgwCZZYuwb5IDq/DRPuR690\n"
            "i8Kp6jR2wY0suObmZHKvbCB1Dw==\n"
            "-----END PRIVATE KEY-----\n";

    /* see test/data/fapi/policy/rsa2.pem */
    static const char *pub_rsa_pem = "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoGL6IrCSAznmIIzBessI\n"
            "mW7tPOUy78uWTIaub32KnYHn78KXprrZ3ykp6WDrOQeMjv4AA+14mJbg77apVYXy\n"
            "EnkFdOMa1hszSJnp6cJvx7ILngLvFUxzbVki/ehvgS3nRk67Njal+nMTe8hpe3UK\n"
            "QeV/Ij+F0r6Yz91W+4LPmncAiUesRZLetI2BZsKwHYRMznmpIYpoua1NtS8QpEXR\n"
            "MmsUue19eS/XRAPmmCfnb5BX2Tn06iCpk6wO+RfMo9etcX5cLSAuIYEQYCvV2/0X\n"
            "TfEw607vttBN0Y54LrVOKno1vRXd5sxyRlfB0WL42F4VG5TfcJo5u1Xq7k9m9K57\n"
            "8wIDAQAB\n"
            "-----END PUBLIC KEY-----\n";

    /* figure out which key to sign with */
    if (strcmp(key_pem, pub_ecc_pem) == 0) {
        priv_key_pem = priv_ecc_pem;
    } else if (strcmp(key_pem, pub_rsa_pem) == 0) {
        priv_key_pem = priv_rsa_pem;
    } else {
        LOG_ERROR("Unknown Key");
        return TSS2_RC_TEST_KEY_NOT_FOUND;
    }

    assert(key_pem_hash_alg == TPM2_ALG_SHA256);

    BIO *bio = BIO_new_mem_buf(priv_key_pem, strlen(priv_key_pem));
    EVP_PKEY *priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(priv_key);

    TSS2_RC r = TSS2_RC_SUCCESS;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    const EVP_MD *ossl_hash = EVP_sha256();

    mdctx = EVP_MD_CTX_create();
    assert(mdctx);

    if (1 != EVP_DigestSignInit(mdctx, &pctx, ossl_hash, NULL, priv_key)) {
        assert(false);
    }

    if (EVP_PKEY_base_id(priv_key) == EVP_PKEY_RSA) {
        int signing_scheme = RSA_SIG_SCHEME;
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, signing_scheme)) {
            assert(false);
        }
    }

    if (1 != EVP_DigestSignUpdate(mdctx, buffer, buffer_size)) {
        assert(false);
    }

    if (1 != EVP_DigestSignFinal(mdctx, NULL, signature_size)) {
        assert(false);
    }

    uint8_t *aux_signature = malloc(*signature_size);
    assert(aux_signature);
    global_signature = aux_signature;

    if (1 != EVP_DigestSignFinal(mdctx, aux_signature, signature_size)) {
        assert(false);
    }

    *signature = aux_signature;

    if (mdctx)
        EVP_MD_CTX_destroy(mdctx);
    if (bio)
        BIO_free(bio);

    bio = BIO_new_mem_buf(key_pem, strlen(key_pem));
    EVP_PKEY *pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    mdctx = EVP_MD_CTX_create();
    pctx = NULL;

    if (1 != EVP_DigestVerifyInit(mdctx, &pctx, ossl_hash, NULL, pub_key)) {
        assert(false);
    }

    if (EVP_PKEY_base_id(pub_key) == EVP_PKEY_RSA) {
        int signing_scheme = RSA_SIG_SCHEME;
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, signing_scheme)) {
            assert(false);
        }
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, buffer, buffer_size)) {
        assert(false);
    }

    if (1 != EVP_DigestVerifyFinal(mdctx, aux_signature, *signature_size)) {
        assert(false);
    }

    if (pub_key)
        EVP_PKEY_free(pub_key);
    if (priv_key)
        EVP_PKEY_free(priv_key);
    if (bio)
        BIO_free(bio);
    if (mdctx)
        EVP_MD_CTX_destroy(mdctx);
    return r;

    return TSS2_RC_SUCCESS;
}

static int ifapi_bn2binpad (
    const BIGNUM *bn,
    unsigned char *bin,
    int binSize)
{
    /* Check for NULL parameters */
    return_if_null(bn, "bn is NULL", 0);
    return_if_null(bin, "bin is NULL", 0);

    /* Convert bn */
    int bnSize = BN_num_bytes(bn);
    int offset = binSize - bnSize;
    memset(bin, 0, offset);
    BN_bn2bin(bn, bin + offset);
    return 1;
}

static TSS2_RC polauth_cb (
    TPMT_PUBLIC *key_public,
    TPMI_ALG_HASH hash_alg,
    TPM2B_DIGEST *digest,
    TPM2B_NONCE *policyRef,
    TPMT_SIGNATURE *signature,
    void *userdata)
{
    mycb_data *cbdata = (mycb_data*) userdata;

    /*
     * Populate the signature for the signed policy
     * the DER signature is already stored in the fapi json
     * test/data/fapi/policy/pol_pcr16_0_ecc_authorized.json
     *
     * NOTE:
     * The callback passes the hash algorithm for the policy NOT
     * the expected signature hash algorithm.
     *
     * NOTE:
     * The key for these policies can be found in:
     *   - test/data/fapi/policy/ecc.pem
     */
    static const unsigned char der_sig_ecdsa_sha384[] = {
            0x30, 0x46, 0x02, 0x21, 0x00, 0xd1, 0xe4, 0x9d, 0x3c, 0x3e, 0xc5, 0x39,
            0x95, 0xd9, 0x0d, 0x72, 0xaf, 0xe1, 0xd6, 0x61, 0x83, 0xce, 0x8b, 0x10,
            0x8d, 0x45, 0xa5, 0x03, 0xe0, 0x25, 0x4e, 0xd8, 0xde, 0xa0, 0xe1, 0xae,
            0x5d, 0x02, 0x21, 0x00, 0xb0, 0x81, 0x12, 0x8d, 0xb0, 0x75, 0x23, 0x99,
            0x64, 0xd2, 0x14, 0xcc, 0xe8, 0xab, 0xb9, 0x1e, 0xc4, 0x34, 0x52, 0x26,
            0xcf, 0x81, 0x3b, 0x18, 0xc3, 0x62, 0x9d, 0x32, 0xcd, 0x22, 0x30, 0xf0 };

    static const unsigned char policy_digest_sha384[] = {
            0xc1, 0x92, 0x33, 0x46, 0xb6, 0xd4, 0x4a, 0x15, 0x4b, 0x58, 0xb5, 0x7b,
            0x43, 0x27, 0xee, 0x70, 0xc2, 0x9a, 0xc5, 0x36, 0xf9, 0x20, 0x9d, 0x94,
            0x88, 0x0d, 0xe6, 0x83, 0x4f, 0x37, 0x05, 0x87, 0x84, 0x6a, 0x28, 0x34,
            0xe3, 0xe8, 0x8a, 0xf6, 0x1e, 0xfd, 0x86, 0x79, 0xfc, 0xcc, 0xed, 0xd5 };

    /* x=deadbeef  # can be obtained via tcti-pcap/tpmstream
     * printf $x | xxd -r -p | openssl pkeyutl -sign -inkey test/data/fapi/policy/ecc.pem | xxd -p
     * https://bits.ondrovo.com/hexc.html
     */
    static const unsigned char der_sig_ecdsa_sha256[] = {
            0x30, 0x45, 0x02, 0x20, 0x2a, 0xc4, 0x01, 0x4e, 0xf8, 0x29, 0xff, 0x97,
            0xa1, 0xae, 0xa3, 0x4c, 0x78, 0xa5, 0x86, 0x12, 0xea, 0xad, 0x9e, 0x3c,
            0xca, 0xe8, 0x7d, 0x5e, 0x9f, 0x6a, 0xbf, 0x16, 0xbc, 0xdd, 0xe5, 0x64,
            0x02, 0x21, 0x00, 0xf0, 0xb3, 0xda, 0x8d, 0x70, 0xe4, 0x36, 0x70, 0x35,
            0x31, 0x8a, 0xe5, 0x49, 0xf1, 0xbf, 0x08, 0x5c, 0x3d, 0x28, 0x98, 0xa9,
            0x15, 0x74, 0xe3, 0x37, 0x5b, 0x6c, 0x47, 0xd3, 0xcb, 0xb2, 0xaa };

    static const unsigned char policy_digest_sha256[] = {
            0xbf, 0xf2, 0xd5, 0x8e, 0x98, 0x13, 0xf9, 0x7c, 0xef, 0xc1, 0x4f,
            0x72, 0xad, 0x81, 0x33, 0xbc, 0x70, 0x92, 0xd6, 0x52, 0xb7, 0xc8,
            0x77, 0x95, 0x92, 0x54, 0xaf, 0x14, 0x0c, 0x84, 0x1f, 0x36 };

    /* on success, the policy digest is set to zero's and the digest is updated
     * to halg(CC_PolicyAuth | key_name | policyRef
     */
    static const unsigned char policy_digest_update_ecdsa_sha256[] = {
            0xb9, 0xb3, 0x70, 0xc6, 0xb4, 0xf8, 0x48, 0x87, 0x51, 0x86, 0x34,
            0xab, 0x40, 0x8c, 0xe2, 0x3d, 0xfc, 0x09, 0x2a, 0xe4, 0x22, 0x81,
            0xa1, 0xb8, 0x43, 0x8b, 0x3f, 0x34, 0xd9, 0xce, 0xb1, 0x8e };

    static const unsigned char policy_digest_update_ecdsa_sha384[] = {
            0xb6, 0xae, 0x94, 0x3e, 0xc8, 0x3e, 0xc7, 0x7e, 0xa5, 0x71, 0x9f, 0x5e,
            0x9e, 0xea, 0xd0, 0x34, 0xf6, 0xa2, 0xb8, 0xe3, 0xb7, 0x5e, 0xf8, 0xc6,
            0x4d, 0xa7, 0x7e, 0xba, 0x10, 0x13, 0x22, 0x8d, 0xbd, 0xcd, 0xe3, 0x09,
            0xd3, 0xa1, 0x77, 0xa6, 0xcf, 0xf2, 0x8d, 0x39, 0x19, 0x5f, 0x77, 0xec };

    /* x=deadbeef  # can be obtained via tcti-pcap/tpmstream
     * printf $x | xxd -r -p | openssl pkeyutl -sign -inkey test/data/fapi/policy/rsa2.pem -pkeyopt digest:sha384 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 | xxd -p
     * https://bits.ondrovo.com/hexc.html
     */
    static const unsigned char rsapss_sig_sha384[] = {
            0x84, 0x2a, 0x2e, 0xd4, 0xf2, 0xf6, 0x5f, 0x1a, 0xcb, 0x18, 0x38, 0x5a,
            0x1d, 0xdc, 0x87, 0x6b, 0x45, 0xcc, 0xf5, 0x07, 0xcb, 0x6f, 0x3f, 0xc0,
            0x0c, 0xfc, 0x5f, 0x41, 0x1e, 0x7f, 0xd4, 0xb6, 0xc5, 0x20, 0xd1, 0xf9,
            0x0c, 0x8e, 0x4f, 0x24, 0x1f, 0xe4, 0x47, 0x95, 0xb9, 0x52, 0x5b, 0x4a,
            0x40, 0xa0, 0x9f, 0xe3, 0x46, 0xf7, 0x0a, 0x2c, 0x61, 0xe5, 0xdc, 0xd9,
            0x61, 0x3c, 0xe2, 0x4a, 0xde, 0x68, 0xc4, 0xfb, 0x2d, 0x88, 0x22, 0x43,
            0x67, 0xab, 0xe3, 0xe7, 0xd4, 0x86, 0x65, 0x81, 0x96, 0xc3, 0x5d, 0x94,
            0x31, 0xc4, 0x90, 0x75, 0x9c, 0x68, 0x24, 0x31, 0xd6, 0x5f, 0x09, 0x7f,
            0x08, 0x7e, 0xbe, 0x0c, 0x7b, 0x73, 0x60, 0x34, 0x66, 0xbe, 0x3b, 0x1d,
            0x02, 0x88, 0xb7, 0xa7, 0xb4, 0xe3, 0xdb, 0x95, 0xe8, 0xde, 0x87, 0x89,
            0x69, 0x24, 0x18, 0xb9, 0x06, 0x0f, 0xb3, 0xb9, 0x29, 0x72, 0x6b, 0x0a,
            0x15, 0x1b, 0x4d, 0x97, 0x88, 0x65, 0x36, 0xf1, 0x4a, 0x54, 0xe1, 0xf9,
            0x04, 0x44, 0x91, 0xad, 0x37, 0xe7, 0xb9, 0x0b, 0x99, 0x74, 0x86, 0x23,
            0x23, 0x02, 0x17, 0xf3, 0xf4, 0x62, 0x7c, 0xa1, 0xcc, 0x03, 0x68, 0x6c,
            0xc3, 0x42, 0x93, 0x73, 0x27, 0xba, 0x0f, 0xb6, 0xaa, 0xaa, 0x4e, 0x5a,
            0xc0, 0xd8, 0xd5, 0x01, 0x52, 0xa2, 0x95, 0xd2, 0x82, 0xc1, 0xc2, 0x39,
            0xf6, 0xaa, 0x28, 0x69, 0x58, 0x08, 0x1c, 0xcd, 0xe7, 0xf2, 0x7f, 0x2b,
            0xaf, 0x06, 0xc8, 0x8d, 0xfc, 0xa2, 0xf3, 0x60, 0x4f, 0xe2, 0x7a, 0xe6,
            0x54, 0x51, 0xa1, 0xd9, 0x6a, 0xe6, 0xea, 0x1b, 0x7d, 0xa8, 0xa8, 0x58,
            0x7d, 0x18, 0xa6, 0x87, 0x23, 0xe4, 0x32, 0x76, 0x4b, 0x72, 0xf6, 0x01,
            0x38, 0xfb, 0x69, 0xc2, 0xa0, 0xd2, 0x95, 0xee, 0x58, 0xe4, 0x1d, 0xbf,
            0xae, 0xf3, 0x6f, 0x5b };

    /* x=deadbeef  # can be obtained via tcti-pcap/tpmstream
     * printf $x | xxd -r -p | openssl pkeyutl -sign -inkey test/data/fapi/policy/rsa2.pem -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 | xxd -p
     * https://bits.ondrovo.com/hexc.html
     */
    static const unsigned char rsapss_sig_sha256[] = {
            0x75, 0x7c, 0xe3, 0xcf, 0xd3, 0x8a, 0x7c, 0x01, 0xbe, 0x76, 0xef, 0xe6,
            0x8f, 0x7b, 0xce, 0x91, 0x7d, 0x0e, 0xb8, 0x4c, 0xf4, 0x96, 0x05, 0x53,
            0x66, 0xd5, 0x9b, 0xc6, 0xf9, 0x58, 0xd4, 0xf5, 0x4f, 0x3b, 0x05, 0xba,
            0x46, 0x47, 0x23, 0xc8, 0x3e, 0x2e, 0xbc, 0x7a, 0xbc, 0xbf, 0xb3, 0x0a,
            0xef, 0x87, 0xf5, 0xbf, 0xd0, 0x84, 0xac, 0x56, 0x1f, 0xab, 0xa6, 0x8c,
            0x9d, 0xd5, 0x88, 0xb4, 0xa1, 0xa4, 0x2b, 0xe9, 0x77, 0xa6, 0x6e, 0xa0,
            0x6e, 0xd0, 0x16, 0x1e, 0x9f, 0x86, 0xed, 0x44, 0x85, 0x32, 0x14, 0xb0,
            0xb9, 0x1b, 0xee, 0xce, 0xc1, 0x32, 0xd2, 0xaa, 0x21, 0xe5, 0x81, 0x2d,
            0x85, 0x27, 0x5d, 0x9f, 0x54, 0x03, 0xe6, 0xc7, 0x68, 0xb0, 0x57, 0x91,
            0xbc, 0x43, 0x20, 0x4c, 0x4a, 0xdb, 0x2d, 0x75, 0xc6, 0xbe, 0x9b, 0x65,
            0xaf, 0x8e, 0x49, 0xee, 0xa1, 0x38, 0x93, 0xaa, 0x5c, 0x73, 0xfe, 0xab,
            0x94, 0xba, 0x6e, 0xbb, 0xae, 0x26, 0xdb, 0xe0, 0x87, 0xcd, 0x3a, 0x03,
            0x7d, 0xfe, 0x4c, 0x06, 0x84, 0x03, 0xae, 0xce, 0x5f, 0xe0, 0x9a, 0x42,
            0x8c, 0xb4, 0x2e, 0xb3, 0x42, 0x18, 0xcf, 0xe9, 0xe0, 0xaa, 0x39, 0xe1,
            0x53, 0x67, 0xe9, 0x6d, 0xfb, 0x5e, 0xaa, 0x78, 0xaa, 0xc0, 0xfc, 0xec,
            0xda, 0x39, 0x0c, 0xb7, 0xf1, 0x44, 0xb9, 0x96, 0x5a, 0xc7, 0x46, 0x28,
            0x85, 0x90, 0x4a, 0x79, 0x13, 0xcb, 0xbe, 0x4b, 0xdb, 0xbb, 0x47, 0x46,
            0xec, 0x28, 0x03, 0x9e, 0xb0, 0xe8, 0xa3, 0xc4, 0xa7, 0x6b, 0x59, 0x5b,
            0xc8, 0x53, 0x6e, 0x55, 0x42, 0x26, 0xc4, 0x7a, 0x8c, 0x66, 0x1e, 0x44,
            0xdd, 0x59, 0x3c, 0x47, 0x34, 0x4e, 0x66, 0xf8, 0x69, 0x14, 0x2c, 0x7c,
            0x23, 0x21, 0x5f, 0xc1, 0x7d, 0x03, 0x39, 0x97, 0x50, 0x3b, 0x08, 0x5e,
            0x1c, 0x10, 0x21, 0xd5 };

    static const unsigned char rsassa_sig_sha384[] = {

    };

    static const unsigned char rsassa_sig_sha256[] = {

    };

    static const unsigned char policy_digest_update_rsa_pss_sha256[] = {
            0x51, 0x64, 0xb8, 0x9f, 0xcf, 0xdc, 0x39, 0x88, 0x06, 0xc0, 0xfd, 0xe7,
            0xa3, 0xeb, 0x52, 0x37, 0x15, 0x95, 0xfc, 0xbe, 0xc1, 0xb1, 0xfc, 0xea,
            0x57, 0x52, 0x4c, 0x56, 0xff, 0xf6, 0x7f, 0x46 };

    static const unsigned char policy_digest_update_rsa_pss_sha384[] = {
            0x32, 0x20, 0x3f, 0x84, 0x64, 0x92, 0xcd, 0xb1, 0x31, 0xfa, 0x1e, 0x72,
            0xdb, 0xb9, 0x25, 0x7c, 0x57, 0xc1, 0x05, 0xb9, 0xca, 0x2e, 0xa4, 0xb3,
            0x1f, 0xdb, 0x73, 0x47, 0xb5, 0xd5, 0xf2, 0xe0, 0x91, 0xc7, 0x81, 0x9d,
            0x5a, 0xf6, 0x39, 0xa0, 0x25, 0x46, 0xdc, 0x41, 0x84, 0xd7, 0x4d, 0x9e };

    /* Convert the signature */
    if (key_public->type == TPM2_ALG_ECC) {

        ECDSA_SIG *ecdsaSignature = NULL;
        const BIGNUM *bnr;
        const BIGNUM *bns;

        const unsigned char *p =
                hash_alg == TPM2_ALG_SHA256 ?
                        der_sig_ecdsa_sha256 : der_sig_ecdsa_sha384;
        size_t len =
                hash_alg == TPM2_ALG_SHA256 ?
                        sizeof(der_sig_ecdsa_sha256) :
                        sizeof(der_sig_ecdsa_sha384);
        d2i_ECDSA_SIG(&ecdsaSignature, &p, len);
        return_if_null(ecdsaSignature, "Invalid DER signature",
                TSS2_FAPI_RC_GENERAL_FAILURE);

        ECDSA_SIG_get0(ecdsaSignature, &bnr, &bns);

        UINT16 keysize = key_public->unique.ecc.x.size;

        signature->signature.ecdsa.hash = hash_alg;
        signature->sigAlg = TPM2_ALG_ECDSA; /**< only ECDSA is used by FAPI */
        ifapi_bn2binpad(bnr, &signature->signature.ecdsa.signatureR.buffer[0],
                keysize);
        signature->signature.ecdsa.signatureR.size = keysize;
        ifapi_bn2binpad(bns, &signature->signature.ecdsa.signatureS.buffer[0],
                keysize);
        signature->signature.ecdsa.signatureS.size = keysize;
        ECDSA_SIG_free(ecdsaSignature);

    } else if (key_public->type == TPM2_ALG_RSA) {

        if (key_public->parameters.rsaDetail.scheme.scheme == TPM2_ALG_RSAPSS) {

            const unsigned char *p =
                    hash_alg == TPM2_ALG_SHA256 ?
                            rsapss_sig_sha256 : rsapss_sig_sha384;
            size_t len =
                    hash_alg == TPM2_ALG_SHA256 ?
                            sizeof(rsapss_sig_sha256) : sizeof(rsapss_sig_sha384);

            signature->sigAlg = TPM2_ALG_RSAPSS;
            signature->signature.rsapss.hash = hash_alg;
            signature->signature.rsapss.sig.size = len;
            memcpy(&signature->signature.rsapss.sig.buffer[0], p, len);
        } else if (key_public->parameters.rsaDetail.scheme.scheme
                == TPM2_ALG_RSASSA) {

            const unsigned char *p =
                    hash_alg == TPM2_ALG_SHA256 ?
                            rsassa_sig_sha256 : rsassa_sig_sha384;
            size_t len =
                    hash_alg == TPM2_ALG_SHA256 ?
                            sizeof(rsassa_sig_sha256) : sizeof(rsassa_sig_sha384);

            signature->sigAlg = TPM2_ALG_RSASSA;
            signature->signature.rsassa.hash = hash_alg;
            signature->signature.rsassa.sig.size = len;
            memcpy(&signature->signature.rsassa.sig.buffer[0], p, len);
        }
    } else {
        return TSS2_RC_TEST_NOT_SUPPORTED;
    }

    /* copy the policy hash into the buffer*/
    if (hash_alg == TPM2_ALG_SHA256) {
        digest->size = sizeof(policy_digest_sha256);
        memcpy(digest->buffer, policy_digest_sha256, digest->size);
    } else {
        digest->size = sizeof(policy_digest_sha384);
        memcpy(digest->buffer, policy_digest_sha384, digest->size);
    }

    /* the name algorithm is used to calculate the verification ticket for policy
     * authorize, so if the name halg is sha384 and the hash_alg coming in is for
     * sha256, we need to manipulate that here
     */
    if (hash_alg != key_public->nameAlg) {
        key_public->nameAlg = hash_alg;
    }

    char *policy_path = TOP_SOURCEDIR"/test/data/fapi/policy/pol_pcr16_0.json";

    char *json = read_all(policy_path);
    assert(json);

    TSS2_POLICY_CTX *ctx = NULL;
    TSS2_RC r = Tss2_PolicyInit(json, hash_alg, &ctx);
    SAFE_FREE(json);
    assert(r == TSS2_RC_SUCCESS);

    /* no need to set callbacks as none are needed */
    r = Tss2_PolicyExecute(ctx, cbdata->esys_ctx, cbdata->session);
    assert(r == TSS2_RC_SUCCESS);

    Tss2_PolicyFinalize(&ctx);

    r = Esys_PolicyGetDigest(cbdata->esys_ctx, cbdata->session,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    ESYS_TR_NONE, &digest);
    assert(r == TSS2_RC_SUCCESS);

    if (key_public->type == TPM2_ALG_ECC) {
        cbdata->update_digest.size =
                hash_alg == TPM2_ALG_SHA256 ?
                        sizeof(policy_digest_update_ecdsa_sha256) :
                        sizeof(policy_digest_update_ecdsa_sha384);
        const unsigned char *buffer =
                hash_alg == TPM2_ALG_SHA256 ?
                        policy_digest_update_ecdsa_sha256 :
                        policy_digest_update_ecdsa_sha384;
        memcpy(cbdata->update_digest.buffer, buffer,
                cbdata->update_digest.size);
    } else {

        const unsigned char *buffer = NULL;

        if (key_public->parameters.rsaDetail.scheme.scheme == TPM2_ALG_RSAPSS) {
            cbdata->update_digest.size =
                    hash_alg == TPM2_ALG_SHA256 ?
                            sizeof(policy_digest_update_rsa_pss_sha256) :
                            sizeof(policy_digest_update_rsa_pss_sha384);
            buffer =
                    hash_alg == TPM2_ALG_SHA256 ?
                            policy_digest_update_rsa_pss_sha256 :
                            policy_digest_update_rsa_pss_sha384;
        } else {
            LOG_ERROR("Non RSAPSS signature schemes are unsupported, got: 0x%x",
                    key_public->parameters.rsaDetail.scheme.scheme);
            return TSS2_RC_TEST_NOT_SUPPORTED;
        }

        memcpy(cbdata->update_digest.buffer, buffer,
                cbdata->update_digest.size);
    }
    SAFE_FREE(digest);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC polaction_cb (
    const char *action,
    void *userdata)
{
    if (strcmp(action, "myaction")) {
        LOG_ERROR("Bad action: %s", action);
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    return TSS2_RC_SUCCESS;
}

static void bin2hex (
    const unsigned char *bin,
    size_t len,
    char *out)
{
    size_t i;

    if (bin == NULL || len == 0) {
        return;
    }

    for (i = 0; i < len; i++) {
        out[i * 2] = "0123456789abcdef"[bin[i] >> 4];
        out[i * 2 + 1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static TSS2_RC policy_cb_pcr (
    TSS2_POLICY_PCR_SELECTION *pcr_selection,
    TPML_PCR_SELECTION *out_pcr_selection,
    TPML_DIGEST *out_pcr_digests,
    void *ctx)
{
    TPML_PCR_SELECTION in_pcr_selection = { 0 };
    TPML_DIGEST pcr_digests = { 0 };

    /* Raw selector without bank specifier, figure out bank and copy
     * the raw selector over to the input selector */
    if (pcr_selection->type == TSS2_POLICY_PCR_SELECTOR_PCR_SELECT) {
        /* Only one bank will be used. A default algorithm of TPM2_ALG_SHA256 */
        in_pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
        in_pcr_selection.count = 1;
        memcpy(in_pcr_selection.pcrSelections[0].pcrSelect,
                pcr_selection->selections.pcr_select.pcrSelect,
                sizeof(pcr_selection->selections.pcr_select.pcrSelect));
        in_pcr_selection.pcrSelections[0].sizeofSelect =
                pcr_selection->selections.pcr_select.sizeofSelect;
    } else {
        /* we have specified selection with bank, so just copy it. */
        in_pcr_selection = pcr_selection->selections.pcr_selection;
    }

    /* This is in place of something like an ESYS_PCR_Read() */
    /* For each bank */
    UINT32 count;
    for (count = 0; count < in_pcr_selection.count; count++) {

        /* Get the selection */
        TPMS_PCR_SELECTION pcr_select = in_pcr_selection.pcrSelections[count];

        /* for each selection byte */
        UINT32 i;
        for (i = 0; i < pcr_select.sizeofSelect; i++) {

            UINT8 j;
            /* for each selection bit in the byte */
            for (j = 0; j < sizeof(pcr_select.pcrSelect[i]) * 8; j++) {
                if (pcr_select.pcrSelect[i] & 1 << j) {

                    /* fake a read */
                    if (pcr_select.hash == TPM2_ALG_SHA256) {
                        pcr_digests.digests[pcr_digests.count].size = 48;
                    } else {
                        LOG_ERROR("Can not support hash 0x%x", pcr_select.hash);
                        return TSS2_RC_TEST_NOT_SUPPORTED;
                    }

                    memset(pcr_digests.digests[pcr_digests.count].buffer, 0,
                            pcr_digests.digests[pcr_digests.count].size);
                    pcr_digests.count++;
                }
            }
        }
    }

    /* copy to caller */
    *out_pcr_selection = in_pcr_selection;
    *out_pcr_digests = pcr_digests;

    return TSS2_RC_SUCCESS;
}

TSS2_RC auth_cb (
    TPM2B_NAME *name,
    ESYS_TR *object_handle,
    ESYS_TR *auth_handle,
    ESYS_TR *authSession,
    void *userdata) {

    /* this callback should call SetAuth for the objects? */
    mycb_data *data = (mycb_data *)userdata;

    TPM2_HANDLE endorsement = HOST_TO_BE_32(0x4000000Bu);
    uint8_t *array = (uint8_t *)&endorsement;
    /* endorsmenet hierarchy */
    if (name->size == sizeof(endorsement) &&
            !memcmp(name->name, array, sizeof(endorsement))) {
        *object_handle = ESYS_TR_RH_ENDORSEMENT;
        *auth_handle = ESYS_TR_RH_ENDORSEMENT;
        *authSession = ESYS_TR_PASSWORD;
        static const TPM2B_AUTH auth = { 0 };
        return Esys_TR_SetAuth(data->esys_ctx,
                *object_handle, &auth);
    }

    LOGBLOB_ERROR(name->name, name->size, "Unknown Object Name");
    return TSS2_RC_TEST_NOT_SUPPORTED;
}

static TSS2_RC check_policy (
    const char *policy_path,
    ESYS_CONTEXT *esys_context,
    TPM2_ALG_ID hash_alg,
    const char *expected_hash,
    TSS2_RC expected_fail)
{
    ESYS_TR session = ESYS_TR_NONE;
    TPM2B_DIGEST *digest = NULL;
    TSS2_POLICY_CTX *policy_ctx = NULL;
    char *json = NULL;

    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_AES, .keyBits = { .aes =
            128 }, .mode = { .aes = TPM2_ALG_CFB } };

    TPM2B_NONCE nonceCaller = { .size = 20, .buffer = { 1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 31, 32 } };

    TSS2_RC r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nonceCaller,
    TPM2_SE_POLICY, &symmetric, hash_alg, &session);
    return_if_error(r, "Error: During initialization of session");

    mycb_data userdata = {
        .esys_ctx = esys_context,
        .session = session,
        .update_digest = { 0 },
        .session_halg = hash_alg
    };

    TSS2_POLICY_CALC_CALLBACKS calc_callbacks = {
        .cbpcr = policy_cb_pcr
    };

    TSS2_POLICY_EXEC_CALLBACKS exec_callbacks = {
        .cbaction = polaction_cb,
        .cbaction_userdata = &userdata,

        .cbauthpol = polauth_cb,
        .cbauthpol_userdata = &userdata,

        .cbpolsel = polsel_cb,
        .cbpolsel_userdata = &userdata,

        .cbsign = sign_cb,
        .cbsign_userdata = &userdata,

        .cbauth = auth_cb,
        .cbauth_userdata = &userdata,
    };

    json = read_all(policy_path);
    goto_if_null(json, "Error: During Tss2_PolicyInit", TSS2_RC_TEST_MEMORY, cleanup);

    r = Tss2_PolicyInit(json, hash_alg, &policy_ctx);
    goto_if_error(r, "Error: During Tss2_PolicyInit", cleanup);

    r = Tss2_PolicySetCalcCallbacks(policy_ctx, &calc_callbacks);
    goto_if_error(r, "Error: During Tss2_PolicySetCalcCallbacks", cleanup);

    r = Tss2_PolicySetExecCallbacks(policy_ctx, &exec_callbacks);
    goto_if_error(r, "Error: During Tss2_PolicySetExecCallbacks", cleanup);

    r = Tss2_PolicyExecute(policy_ctx, esys_context, session);
    if (expected_fail != r) {
        goto_if_error(r, "Error: During Tss2_PolicyExecute", cleanup);
    } else if (r != TSS2_RC_SUCCESS) {
        r = TSS2_RC_SUCCESS;
        goto cleanup;
    }

    r = Esys_PolicyGetDigest(esys_context, session,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    ESYS_TR_NONE, &digest);
    goto_if_error(r, "Error: Getting session digest", cleanup);

    size_t expected_size = strlen(expected_hash) / 2;

    if (digest->size != expected_size) {
        LOG_ERROR("Expected digest size to be %zu, got %u", expected_size,
                digest->size);
        r = TSS2_RC_TEST_FAIL;
        goto cleanup;
    }

    if (userdata.update_digest.size == 0) {
        /* compare actual policyDigest to the one specified in test/data/test-fapi-policies.h */
        /* SHA512 buffer size, times 2 for text, + 1 for NUL byte */
        char hexdigest[64 + 64 + 1] = { 0 };
        bin2hex(digest->buffer, digest->size, hexdigest);

        if (strcmp(expected_hash, hexdigest) != 0) {
            LOG_ERROR("Expected digest to match, got \"%s\" expected \"%s\"",
                    hexdigest, expected_hash);
            r = TSS2_RC_TEST_FAIL;
            goto cleanup;
        }
    } else {
        /* compare actual policyDigest to the one specified by callback */
        if (memcmp(digest->buffer, userdata.update_digest.buffer,
                digest->size)) {
            char a[64 + 64 + 1] = { 0 };
            bin2hex(digest->buffer, digest->size, a);
            char b[64 + 64 + 1] = { 0 };
            bin2hex(userdata.update_digest.buffer, userdata.update_digest.size,
                    b);

            LOG_ERROR("Expected digest to match, got \"%s\" expected \"%s\"", b,
                    a);
            r = TSS2_RC_TEST_FAIL;
            goto cleanup;
        }
    }

cleanup:

    Esys_Free(digest);

    TSS2_RC rc = Esys_FlushContext(esys_context, session);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Flush should not fail, got: 0x%x", rc);
        r = rc;
    }
    Tss2_PolicyFinalize(&policy_ctx);

    session = ESYS_TR_NONE;

    SAFE_FREE(json);

    return r;
}

/** Test TSS2_Policy_Execute.
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

static int test_policy_execute (
    ESYS_CONTEXT *esys_context)
{
    unsigned i;
    TSS2_RC rc;
    ESYS_CONTEXT *ectx;

    /* Get the TPM properties */
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;
    rc = Esys_GetCapability(
        esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        TPM2_CAP_ALGS,
        TPM2_ALG_SHA384,
        1, &more_data, &capability_data);

    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_GetCapability failed: 0x%x\n", rc);
        Esys_Finalize(&ectx);
        goto error;
    }

    /* Check if SHA-384 is supported */
    bool sha384_available = false;
    for (size_t i = 0; i < capability_data->data.algorithms.count; i++) {
        if (capability_data->data.algorithms.algProperties[i].alg == TPM2_ALG_SHA384) {
            sha384_available = true;
            break;
        }
    }

    Esys_Free(capability_data);

    for (i = 0; i < ARRAY_LEN(_test_fapi_policy_policies); i++) {
        policy_digests *p = &_test_fapi_policy_policies[i];

        fprintf(stderr, "Check Policy(%u): %s\n", i,
                _test_fapi_policy_policies[i].path);

        char abs_path[PATH_MAX];
        snprintf(abs_path, sizeof(abs_path),
        TOP_SOURCEDIR"/test/data/fapi%s.json", p->path);

        TSS2_RC expected_fail = TSS2_RC_SUCCESS;
        if (strcmp(_test_fapi_policy_policies[i].path,
                "/policy/pol_pcr16_0_fail") == 0) {
            /*
             * This policy file intentionally fails with the following error code:
             *   - file: policy file: pol_pcr16_0_fail.json
             *   - error: tpm:parameter(1):value is out of range or is not correct for the context
             */
            expected_fail = 0x000001c4;
        }

        if (strcmp(_test_fapi_policy_policies[i].path,
                "/policy/pol_pcr8_0") == 0) {
            TPML_PCR_SELECTION  pcr_selection;
            TSS2_RC rc;
            int j;
            TPML_DIGEST *pcr_values = NULL;
            bool skip = false;

            /*
             * Skip the test if PCR 8 is non-zero - means we're testing against
             * a real device and the PCR has been extended.
             */

            pcr_selection.count = 1;
            pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
            pcr_selection.pcrSelections[0].sizeofSelect = 3;
            pcr_selection.pcrSelections[0].pcrSelect[0] = 0;
            pcr_selection.pcrSelections[0].pcrSelect[1] = 0;
            pcr_selection.pcrSelections[0].pcrSelect[2] = 0;
            pcr_selection.pcrSelections[0].pcrSelect[PCR_8 / 8] = 1 << (PCR_8 % 8);

            rc = Esys_PCR_Read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, &pcr_selection, NULL, NULL,
                               &pcr_values);
            if (rc != TSS2_RC_SUCCESS) {
                LOG_ERROR("PCR_Read FAILED! Response Code : 0x%x", rc);
                goto error;
            }

            for (j = 0; j < pcr_values->digests[0].size; j++) {
                if (pcr_values->digests[0].buffer[j] != 0) {
                    LOG_WARNING("PCR 8 cannot be tested");
                    skip = true;
                    break;
                }
            }

            free(pcr_values);

            if (skip)
                continue;
        }

        if (p->sha256) {
            fprintf(stderr, " - SHA256\n");
            TSS2_RC r = check_policy(abs_path, esys_context, TPM2_ALG_SHA256,
                    p->sha256, expected_fail);
            if ((r == TPM2_RC_COMMAND_CODE) ||
                (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
                (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
                LOG_WARNING("Policy %s not supported by TPM.", p->path);
            } else {
                goto_if_error(r, "Checking policy digest for sha256 failed", error);
            }
        }
        SAFE_FREE(global_signature);

        /*
         * Per the IBM simulator code:
         * A valid cpHash must have the same size as session hash digest
         *
         * NOTE: the size of the digest can't be zero because TPM_ALG_NULL
         *       can't be used for the authHashAlg.
         */
        if (p->sha384 && sha384_available) {
            if (!(strcmp(_test_fapi_policy_policies[i].path, "/policy/pol_cphash") == 0 ||
                  strcmp(_test_fapi_policy_policies[i].path, "/policy/pol_authorize_ecc_pem") == 0)) {
                fprintf(stderr, " - SHA384\n");
                TSS2_RC r = check_policy(abs_path, esys_context, TPM2_ALG_SHA384,
                                         p->sha384, expected_fail);
                if ((r == TPM2_RC_COMMAND_CODE) ||
                    (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
                    (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
                    LOG_WARNING("Policy %s not supported by TPM.", p->path);
                } else {
                    goto_if_error(r, "Checking policy digest for sha384 failed", error);
                }
            }
        }
        SAFE_FREE(global_signature);
    }

    return EXIT_SUCCESS;

/* Return normalized error codes by having a jump label and less logic in code paths*/
error:
    return EXIT_FAILURE;
}

int test_invoke_esys (
    ESYS_CONTEXT *esys_context)
{
    return test_policy_execute(esys_context);
}
