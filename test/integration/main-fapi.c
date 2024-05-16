/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"               // for FAPI_TEST_EK_CERT_LESS
#endif

#include <inttypes.h>             // for PRIx32, int64_t, PRId64, PRIu16
#include <json.h>                 // for json_object_get_string, json_object...
#include <openssl/asn1.h>         // for ASN1_INTEGER_free, ASN1_INTEGER_new
#include <openssl/bio.h>          // for BIO_free_all, BIO_new, BIO_s_file
#include <openssl/bn.h>           // for BN_free, BN_bin2bn, BN_new
#include <openssl/buffer.h>       // for buf_mem_st
#include <openssl/crypto.h>       // for OPENSSL_free
#include <openssl/ec.h>           // for EC_GROUP_free, EC_GROUP_new_by_curv...
#include <openssl/evp.h>          // for EVP_PKEY_free, EVP_PKEY, EVP_PKEY_C...
#include <openssl/obj_mac.h>      // for NID_sm2, NID_X9_62_prime192v1, NID_...
#include <openssl/objects.h>      // for OBJ_nid2sn
#include <openssl/opensslv.h>     // for OPENSSL_VERSION_NUMBER
#include <openssl/pem.h>          // for PEM_read_bio_PrivateKey, PEM_read_b...
#include <openssl/rsa.h>          // for EVP_PKEY_CTX_set_rsa_keygen_bits
#include <openssl/x509.h>         // for X509_REQ_free, X509_free, X509_gmti...
#include <stdbool.h>              // for false, bool, true
#include <stdio.h>                // for NULL, asprintf, size_t, perror, sscanf
#include <stdlib.h>               // for free, calloc, setenv, malloc, mkdtemp
#include <string.h>               // for strtok_r, memcpy, strdup, strcmp
#include <sys/stat.h>             // for stat
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/aes.h>

#include "ifapi_macros.h"         // for goto_if_null2
#else
#include <openssl/core_names.h>   // for OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PK...
#include <openssl/param_build.h>  // for OSSL_PARAM_BLD_free, OSSL_PARAM_BLD...
#include <openssl/params.h>       // for OSSL_PARAM_free
#endif
#include <openssl/err.h>          // for ERR_error_string_n, ERR_get_error

#include "fapi_int.h"             // for OSSL_FREE, FAPI_CONTEXT
#include "linkhash.h"             // for lh_entry
#include "test-common.h"          // for TSS2_TEST_FAPI_CONTEXT, TSS2_TEST_E...
#include "test-fapi.h"            // for EXIT_ERROR, test_invoke_fapi, ASSERT
#include "tss2_common.h"          // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_FAPI...
#include "tss2_esys.h"            // for Esys_Finalize, Esys_Initialize, ESY...
#include "tss2_fapi.h"            // for Fapi_GetTcti, Fapi_Finalize, FAPI_C...
#include "tss2_rc.h"              // for Tss2_RC_Decode
#include "tss2_sys.h"             // for TSS2_SYS_CONTEXT, Tss2_Sys_CreatePr...
#include "tss2_tcti.h"            // for TSS2_TCTI_CONTEXT
#include "tss2_tpm2_types.h"      // for TPM2B_MAX_NV_BUFFER, TPM2B_PUBLIC

#define LOGDEFAULT LOGLEVEL_INFO
#define LOGMODULE test
#include "util/log.h"             // for LOGLEVEL_INFO, LOG_ERROR, SAFE_FREE

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#else
#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates_GFp(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates_GFp(group, tpm_pub_key, bn_x, bn_y, dmy)
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */

#define SYS_CALL(rc,fu,...) \
    do { \
        rc = fu(__VA_ARGS__);                       \
    } while (rc == TPM2_RC_YIELDED); \
    if (rc != TPM2_RC_SUCCESS) {    \
        LOG_ERROR("%s FAILED: 0x%"PRIx32, #fu, rc);            \
        return rc;                                            \
    }

char *fapi_profile = NULL;
TSS2_TEST_FAPI_CONTEXT *fapi_test_ctx = NULL;

struct tpm_state {
    TPMS_CAPABILITY_DATA capabilities[7];
};

bool file_exists (char *path) {
  struct stat   buffer;
  return (stat (path, &buffer) == 0);
}

/* Determine integer number from json object. */
static int64_t
get_number(json_object *jso) {
    const char* token;
    int itoken = 0;
    int pos = 0;
    int64_t num;

    token = json_object_get_string(jso);
    if (strncmp(token, "0x", 2) == 0) {
        itoken = 2;
        sscanf(&token[itoken], "%"PRIx64"%n", &num, &pos);
    } else {
        sscanf(&token[itoken], "%"PRId64"%n", &num, &pos);
    }
    return num;
}

/* Determin number of fields in a json objecd. */
size_t nmb_of_fields(json_object *jso) {
    size_t n = 0;
    json_object_object_foreach(jso, key, val) {
        UNUSED(val);
        UNUSED(key);
        n++;
    }
    return n;
}

/* Compare two json objects.
 *
 * Only strings, integers, array and json objects are supported.
 */
bool cmp_jso(json_object *jso1, json_object *jso2) {
    enum json_type type1, type2;
    size_t i, size;
    type1 = json_object_get_type(jso1);
    type2 = json_object_get_type(jso2);
    if (type1 != type2) {
        return false;
    }
    if (type1 == json_type_object) {
        if (nmb_of_fields(jso1) != nmb_of_fields(jso2)) {
            return false;
        }
        json_object_object_foreach(jso1, key1, jso_sub1) {
            json_object *jso_sub2;
            if (!json_object_object_get_ex(jso2, key1, &jso_sub2)) {
                return false;
            }
            if (!cmp_jso(jso_sub1, jso_sub2)) {
                    return false;
            }
        }
        return true;
    } else if (type1 == json_type_int) {
        return (get_number(jso1) == get_number(jso2));
    } else if (type1 == json_type_array) {
        size = json_object_array_length(jso1);
        /* Cast to size_t due to change in json-c API.
           older versions use result type int */
        if (size != (size_t)json_object_array_length(jso2)) {
            return false;
        }
        for (i = 0; i < size; i++) {
            if (!cmp_jso(json_object_array_get_idx(jso1, i),
                         json_object_array_get_idx(jso2, i))) {
                return false;
            }
        }
        return true;
    } else if (type1 == json_type_string) {
        return (strcmp(json_object_get_string(jso1),
                       json_object_get_string(jso2)) == 0);
    } else {
        return false;
    }
}

/* Compare two delimter sparated token lists. */
bool cmp_strtokens(char* string1, char *string2, char *delimiter) {
    bool found = false;
    char *token1 = NULL;
    char *token2 = NULL;
    char *end_token1;
    char *end_token2;
    char *string2_copy;

    string1 = strdup(string1);
    ASSERT(string1);
    token1 = strtok_r(string1, delimiter, &end_token1);
    while(token1 != NULL) {
        found = false;
        string2_copy = strdup(string2);
        ASSERT(string2_copy);
        token2 = strtok_r(string2_copy, delimiter, &end_token2);
        while (token2 != NULL) {
            if (strcmp(token1, token2) == 0) {
                found = true;
                break;
            }
            token2 = strtok_r(NULL, delimiter, &end_token2);
        }
        free(string2_copy);
        if (!found) {
            break;
        }
        token1 = strtok_r(NULL, delimiter, &end_token1);
    }
    free(string1);
    return found;

 error:
    SAFE_FREE(string1);
    return false;
}

TSS2_RC
pcr_reset(FAPI_CONTEXT *context, UINT32 pcr)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;

    r = Fapi_GetTcti(context, &tcti);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_Initialize(&esys, tcti, NULL);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_PCR_Reset(esys, pcr,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    Esys_Finalize(&esys);
    goto_if_error(r, "Error Eys_PCR_Reset", error);

error:
    return r;
}

TSS2_RC
pcr_bank_sha1_exists(FAPI_CONTEXT *context, bool *exists)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;
    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 1,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA1,
              .sizeofSelect = 3,
              .pcrSelect = { 1, 0, 0}
            },
        }
    };
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION *pcrSelectionOut = NULL;
    TPML_DIGEST *pcrValues = NULL;

    r = Fapi_GetTcti(context, &tcti);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_Initialize(&esys, tcti, NULL);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
    goto_if_error(r, "Error: PCR_Read", error);
    if (!pcrSelectionOut->pcrSelections[0].pcrSelect[0]) {
        *exists = false;
    } else {
        *exists = true;
    }
    Esys_Finalize(&esys);
    goto_if_error(r, "Error Eys_PCR_Reset", error);

error:
    SAFE_FREE(pcrSelectionOut);
    SAFE_FREE(pcrValues);
    return r;
}


TSS2_RC
pcr_extend(FAPI_CONTEXT *context, UINT32 pcr, TPML_DIGEST_VALUES *digest_values)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;

    r = Fapi_GetTcti(context, &tcti);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_Initialize(&esys, tcti, NULL);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_PCR_Extend(esys, pcr,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        digest_values);
    Esys_Finalize(&esys);
    goto_if_error(r, "Error Eys_PCR_Reset", error);

error:
    return r;
}

int init_fapi(char *profile, FAPI_CONTEXT **fapi_context)
{
    TSS2_RC rc;
    int ret, size;
    char *config = NULL;
    char *config_path = NULL;
    char *config_env = NULL;
    char *config_bak = NULL;
    FILE *config_file;
    char *tmpdir;

    fapi_profile = profile;
    tmpdir = fapi_test_ctx->tmpdir;

    /* First we construct a fapi config file */
#if defined(FAPI_NONTPM)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"none\",\n"
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir);
#elif defined(FAPI_TEST_FINGERPRINT)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_fingerprint\": { \"hashAlg\": \"sha256\", \"digest\": \"%s\" },\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv(ENV_TCTI)
#if !defined(FAPI_TEST_EK_CERT_LESS)
                    , getenv("FAPI_TEST_FINGERPRINT")
#endif
                   );
#elif defined(FAPI_TEST_CERTIFICATE)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_cert_file\": \"file:%s\",\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv(ENV_TCTI)
#if !defined(FAPI_TEST_EK_CERT_LESS)
                    , getenv("FAPI_TEST_CERTIFICATE")
#endif
                   );
#elif defined(FAPI_TEST_FINGERPRINT_ECC)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_fingerprint\": { \"hashAlg\": \"sha256\", \"digest\": \"%s\" },\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv(ENV_TCTI)
#if !defined(FAPI_TEST_EK_CERT_LESS)
                    , getenv("FAPI_TEST_FINGERPRINT_ECC")
#endif
                   );
#elif defined(FAPI_TEST_CERTIFICATE_ECC)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_cert_file\": \"file:%s\",\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv(ENV_TCTI)
#if defined(FAPI_TEST_EK_CERT_LESS)
#else
                    , getenv("FAPI_TEST_CERTIFICATE_ECC")
#endif
                   );
#else /* FAPI_NONTPM */
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS) || defined(DLOPEN)
                    "     \"ek_cert_less\": \"yes\",\n"
#endif
                    "",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv(ENV_TCTI));
#endif /* FAPI_NONTPM */

    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }

#if defined (FAPI_TEST_FIRMWARE_LOG_FILE)
    config_bak = config;
    size = asprintf(&config, "%s%s", config_bak, "     \"firmware_log_file\": \""  FAPI_TEST_FIRMWARE_LOG_FILE "\",\n");
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    SAFE_FREE(config_bak);
#endif
#if defined (FAPI_TEST_IMA_LOG_FILE)
    config_bak = config;
    size = asprintf(&config, "%s%s", config_bak, "     \"ima_log_file\": \"" FAPI_TEST_IMA_LOG_FILE "\",\n");
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    SAFE_FREE(config_bak);
#endif
#if defined (FAPI_TEST_FIRMWARE_LOG_FILE_ABS)
    config_bak = config;
    size = asprintf(&config, "%s%s", config_bak, "     \"firmware_log_file\": \"" FAPI_TEST_FIRMWARE_LOG_FILE_ABS "\",\n");
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    SAFE_FREE(config_bak);
#endif
#if defined (FAPI_TEST_IMA_LOG_FILE_ABS)
    config_bak = config;
    size = asprintf(&config, "%s%s", config_bak, "     \"ima_log_file\": \"" FAPI_TEST_IMA_LOG_FILE_ABS "\",\n");
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    SAFE_FREE(config_bak);
#endif


    config_bak = config;
    size = asprintf(&config, "%s}", config_bak);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    SAFE_FREE(config_bak);

    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    LOG_INFO("Using config:\n%s", config);

    /* We construct the path for the config file */
    size = asprintf(&config_path, "%s/fapi-config.json", tmpdir);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }

    /* We write the config file to disk */
    config_file = fopen(config_path, "w");
    if (!config_file) {
        LOG_ERROR("Opening config file for writing");
        perror(config_path);
        ret = EXIT_ERROR;
        goto error;
    }
    size = fprintf(config_file, "%s", config);
    fclose(config_file);
    if (size < 0) {
        LOG_ERROR("Writing config file");
        perror(config_path);
        ret = EXIT_ERROR;
        goto error;
    }

    /* We set the environment variable for FAPI to consume the config file */
    size = asprintf(&config_env, "TSS2_FAPICONF=%s", config_path);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    putenv(config_env);

    /***********
     * Call FAPI
     ***********/


    rc = Fapi_Initialize(fapi_context, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        ret = EXIT_FAILURE;
        goto error;
    }

    fapi_test_ctx->fapi_ctx = *fapi_context;
    SAFE_FREE(config_env);
    SAFE_FREE(config);
    SAFE_FREE(config_path);
    return 0;

 error:
    Fapi_Finalize(fapi_context);

    if (config) free(config);
    if (config_path) free(config_path);
    if (config_env) free(config_env);

    return ret;
}
TSS2_RC
rsa_pub_from_tpm(const TPM2B_PUBLIC *tpmPublicKey, EVP_PKEY **evpPublicKey)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsa = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
#endif

    /* Check for NULL parameters */
    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(evpPublicKey, "evpPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    /* Initialize the RSA parameters */
    BIGNUM *e = NULL;
    BIGNUM *n = BN_bin2bn(tpmPublicKey->publicArea.unique.rsa.buffer,
                          tpmPublicKey->publicArea.unique.rsa.size, NULL);
    if (!n) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error_cleanup);
    }

    uint32_t exp;
    if (tpmPublicKey->publicArea.parameters.rsaDetail.exponent == 0)
        exp = 65537;
    else
        exp = tpmPublicKey->publicArea.parameters.rsaDetail.exponent;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if ((rsa = RSA_new()) == NULL) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error_cleanup);
    }

    if ((e = BN_new()) == NULL) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error_cleanup);
    }
    if (1 != BN_set_word(e, exp)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Could not set exponent.", error_cleanup);
    }

    if (!RSA_set0_key(rsa, n, e, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Could not set public key.", error_cleanup);
    }
    n = NULL; /* ownership transferred */
    e = NULL;

    *evpPublicKey = EVP_PKEY_new();
    goto_if_null2(*evpPublicKey, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, error_cleanup);

    /* Assign the parameters to the key */
    if (!EVP_PKEY_assign_RSA(*evpPublicKey, rsa)) {
        EVP_PKEY_free(*evpPublicKey);
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Assign rsa key",
                   error_cleanup);
    }
    rsa = NULL; /* ownership transferred */
error_cleanup:
    OSSL_FREE(rsa, RSA);
#else /* OPENSSL_VERSION_NUMBER < 0x30000000L */
    if ((build = OSSL_PARAM_BLD_new()) == NULL
            || !OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n)
            || !OSSL_PARAM_BLD_push_uint32(build, OSSL_PKEY_PARAM_RSA_E, exp)
            || (params = OSSL_PARAM_BLD_to_param(build)) == NULL) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Create rsa key parameters",
                   error_cleanup);
    }

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL
            || EVP_PKEY_fromdata_init(ctx) <= 0
            || EVP_PKEY_fromdata(ctx, evpPublicKey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Create rsa key",
                   error_cleanup);
    }
error_cleanup:
    OSSL_FREE(ctx, EVP_PKEY_CTX);
    OSSL_FREE(params, OSSL_PARAM);
    OSSL_FREE(build, OSSL_PARAM_BLD);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
    OSSL_FREE(e, BN);
    OSSL_FREE(n, BN);
    return r;
}

TSS2_RC
ecc_pub_from_tpm(const TPM2B_PUBLIC *tpmPublicKey, EVP_PKEY **evpPublicKey)
{
    /* Check for NULL parameters */
    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(evpPublicKey, "evpPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    EC_GROUP *ecgroup = NULL;
    int curveId;
    BIGNUM *x = NULL, *y = NULL;
    EC_POINT *ecPoint = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EC_KEY *ecKey = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *puboct = NULL;
    size_t bsize;
#endif

    /* Find the curve of the ECC key */
    switch (tpmPublicKey->publicArea.parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        curveId = NID_X9_62_prime192v1;
        break;
    case TPM2_ECC_NIST_P224:
        curveId = NID_secp224r1;
        break;
    case TPM2_ECC_NIST_P256:
        curveId = NID_X9_62_prime256v1;
        break;
    case TPM2_ECC_NIST_P384:
        curveId = NID_secp384r1;
        break;
    case TPM2_ECC_NIST_P521:
        curveId = NID_secp521r1;
        break;
#ifdef NID_sm2
    case TPM2_ECC_SM2_P256:
        curveId = NID_sm2;
        break;
#endif
    default:
        return_error(TSS2_FAPI_RC_BAD_VALUE,
                     "ECC curve not implemented.");
    }

    /* Initialize the OpenSSL ECC key with its group */
    ecgroup = EC_GROUP_new_by_curve_name(curveId);
    goto_if_null(ecgroup, "new EC group.", TSS2_FAPI_RC_GENERAL_FAILURE,
                  error_cleanup);

    /* Set the ECC parameters in the OpenSSL key */
    x = BN_bin2bn(tpmPublicKey->publicArea.unique.ecc.x.buffer,
                  tpmPublicKey->publicArea.unique.ecc.x.size, NULL);

    y = BN_bin2bn(tpmPublicKey->publicArea.unique.ecc.y.buffer,
                  tpmPublicKey->publicArea.unique.ecc.y.size, NULL);

    if (!x || !y) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error_cleanup);
    }

    if ((ecPoint = EC_POINT_new(ecgroup)) == NULL
            || !EC_POINT_set_affine_coordinates_tss(ecgroup, ecPoint, x, y, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EC_POINT_set_affine_coordinates",
                   error_cleanup);
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000
    ecKey = EC_KEY_new();
    return_if_null(ecKey, "Out of memory.", TSS2_FAPI_RC_MEMORY);

    if (!EC_KEY_set_group(ecKey, ecgroup)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EC_KEY_set_group",
                   error_cleanup);
    }

    if (!EC_KEY_set_public_key(ecKey, ecPoint)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "EC_KEY_set_public_key", error_cleanup);
    }

    *evpPublicKey = EVP_PKEY_new();
    goto_if_null2(*evpPublicKey, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, error_cleanup);

    if (!EVP_PKEY_assign_EC_KEY(*evpPublicKey, ecKey)) {
        EVP_PKEY_free(*evpPublicKey);
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Assign ecc key",
                   error_cleanup);
    }
    ecKey = NULL; /* ownership transferred */
error_cleanup:
    OSSL_FREE(ecKey, EC_KEY);
#else
    if ((build = OSSL_PARAM_BLD_new()) == NULL
            || !OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)OBJ_nid2sn(curveId), 0)
            || (bsize = EC_POINT_point2buf(ecgroup, ecPoint,
                                           POINT_CONVERSION_COMPRESSED,
                                           &puboct, NULL)) == 0
            || !OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY,
                                                 puboct, bsize)
            || (params = OSSL_PARAM_BLD_to_param(build)) == NULL) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Create ecc key parameters",
                   error_cleanup);
    }

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL
            || EVP_PKEY_fromdata_init(ctx) <= 0
            || EVP_PKEY_fromdata(ctx, evpPublicKey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Create ecc key",
                   error_cleanup);
    }
error_cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
    OPENSSL_free(puboct);
#endif
    OSSL_FREE(ecPoint, EC_POINT);
    OSSL_FREE(ecgroup, EC_GROUP);
    OSSL_FREE(y, BN);
    OSSL_FREE(x, BN);
    return r;
}

TPM2_RC
get_rsa_ek_public(TSS2_SYS_CONTEXT *sys_context, EVP_PKEY **evp_pub)
{
    TSS2_RC rc;
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {
        .auths = {{ .sessionHandle = TPM2_RH_PW }},
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

    /* Generate the EK key */

    SYS_CALL(rc, Tss2_Sys_CreatePrimary,
             sys_context, TPM2_RH_ENDORSEMENT, &auth_cmd,
             &in_sensitive, &in_public, NULL, &creation_pcr,
             &handle, &out_public, NULL, NULL, NULL, NULL, &auth_rsp);

    SYS_CALL(rc, Tss2_Sys_FlushContext, sys_context, handle);

    rc = rsa_pub_from_tpm(&out_public, evp_pub);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Failed to create EVP key from RSA EK: 0x%"PRIx32, rc);
        return rc;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
get_ecc_ek_public(TSS2_SYS_CONTEXT *sys_context, EVP_PKEY **evp_pub)
{
    TSS2_RC rc;
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {
        .auths = {{ .sessionHandle = TPM2_RH_PW }},
        .count = 1
    };
    TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
    TPM2B_PUBLIC in_public = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
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
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = { 0 }
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = {.scheme = TPM2_ALG_NULL,
                        .details = { 0 }
                }
            },
            .unique.ecc = {
                .x = {.size = 32,.buffer = { 0 }},
                .y = {.size = 32,.buffer = { 0 }}
            }
        }
    };
    TPML_PCR_SELECTION creation_pcr = { 0 };
    TPM2_HANDLE handle;
    TPM2B_PUBLIC out_public = { 0 };
    TSS2L_SYS_AUTH_RESPONSE auth_rsp = {
        .count = 0
    };
    SYS_CALL(rc, Tss2_Sys_CreatePrimary,
             sys_context, TPM2_RH_ENDORSEMENT, &auth_cmd,
             &in_sensitive, &in_public, NULL, &creation_pcr,
             &handle, &out_public, NULL, NULL, NULL, NULL, &auth_rsp);


    SYS_CALL(rc, Tss2_Sys_FlushContext, sys_context, handle);

    rc = ecc_pub_from_tpm(&out_public, evp_pub);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Failed to create EVP key from ECC EK: 0x%"PRIx32, rc);
        return rc;
    }

    return TSS2_RC_SUCCESS;

}

char pwd[6] = "123456";

int pass_cb(char *buf, int size, int rwflag, void *u)
{
    (void)rwflag;
    memcpy(buf, &pwd[0], 6);
    return 6;
}

TSS2_RC
nv_write(TSS2_SYS_CONTEXT *sys_context, TPMI_RH_NV_INDEX nvIndex, X509 *cert)
{
    TSS2_RC rc;
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {
        .auths = {{ .sessionHandle = TPM2_RH_PW }},
        .count = 1
    };

    if (!nvIndex) {
        nvIndex = 0x01c00002;
    }

    TPM2B_AUTH nv_auth = { 0 };
    TPM2B_NV_PUBLIC public_info = {
        .nvPublic = {
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = TPMA_NV_PPWRITE | TPMA_NV_AUTHREAD | TPMA_NV_OWNERREAD |
                TPMA_NV_PLATFORMCREATE | TPMA_NV_NO_DA,
            .dataSize = 0,
            .nvIndex = nvIndex,
        },
    };

    TSS2L_SYS_AUTH_RESPONSE auth_rsp = {
        .count = 0
    };
    TPM2B_MAX_NV_BUFFER buf1 = { 0 };
    TPM2B_MAX_NV_BUFFER buf2 = { 0 };
    unsigned char *cert_buf = NULL;
    int cert_size;

    cert_size = i2d_X509(cert, &cert_buf);
    if (cert_size < 0) {
        LOG_ERROR("Certificate buffer can't be created.");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }
    if (buf1.size >= sizeof(buf1.buffer)) {
        LOG_ERROR("Certificate to large");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }
    buf1.size = cert_size;
    memcpy(&buf1.buffer[0], cert_buf, cert_size);
    free(cert_buf);

    /* First make sure that not EK certificate is currently loaded */
    LOG_WARNING("Cert input size is %"PRIu16, buf1.size);
    public_info.nvPublic.dataSize = buf1.size;

    LOG_WARNING("Define NV cert with nv index: %x", public_info.nvPublic.nvIndex);

    SYS_CALL(rc, Tss2_Sys_NV_DefineSpace,
             sys_context, TPM2_RH_PLATFORM, &auth_cmd,
             &nv_auth, &public_info, &auth_rsp);

    /* Split the input buffer into 2 chunks */
    buf2.size = buf1.size;
    buf1.size /= 2;
    buf2.size -= buf1.size;
    memcpy(&buf2.buffer[0], &buf1.buffer[buf1.size], buf2.size);

    SYS_CALL(rc, Tss2_Sys_NV_Write, sys_context, TPM2_RH_PLATFORM, nvIndex, &auth_cmd,
             &buf1, 0, &auth_rsp);

    SYS_CALL(rc, Tss2_Sys_NV_Write, sys_context, TPM2_RH_PLATFORM, nvIndex, &auth_cmd,
             &buf2, buf1.size, &auth_rsp);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
load_intermed_cert_and_key(const char *ca_key_path, EVP_PKEY **ca_key,
                               const char *ca_cert_path, X509 **ca_crt)
{
    BIO *bio = NULL;
    *ca_crt = NULL;
    *ca_key = NULL;

    /* Load the intermediate certificate */
    bio = BIO_new(BIO_s_file());
    if (!bio || !BIO_read_filename(bio, ca_cert_path)) {
        unsigned long err = ERR_get_error();
        char err_buffer[256];
        ERR_error_string_n(err, err_buffer, sizeof(err_buffer));
        LOG_ERROR("Failure in BIO_read_filename \"%s\" %s", ca_cert_path, err_buffer);
        goto error_cleanup;
    }
    *ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!*ca_crt) {
        LOG_ERROR("Could not read intermediate cert %s", ca_cert_path);
        goto error_cleanup;
    }
    BIO_free_all(bio);

    /* Load the intermediate key. */
    bio = BIO_new(BIO_s_file());
    if (!bio  || !BIO_read_filename(bio, ca_key_path)) {
        unsigned long err = ERR_get_error();
        char err_buffer[256];
        ERR_error_string_n(err, err_buffer, sizeof(err_buffer));
        LOG_ERROR("Failure in BIO_read_filename \"%s\" %s", ca_key_path, err_buffer);
        goto error_cleanup;
    }
    *ca_key = PEM_read_bio_PrivateKey(bio, NULL, pass_cb, NULL);
    if (!*ca_key) {
        LOG_ERROR("Could not read intermediate key %s", ca_key_path);
        goto error_cleanup;
    }
    BIO_free_all(bio);
    return TSS2_RC_SUCCESS;

 error_cleanup:
    BIO_free_all(bio);
    X509_free(*ca_crt);
    EVP_PKEY_free(*ca_key);
    return TSS2_FAPI_RC_GENERAL_FAILURE;
}

TSS2_RC
get_dummy_csr(EVP_PKEY **dmy_key, X509_REQ **req)
{
    *dmy_key = NULL;
    *req = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    *dmy_key = NULL;
    *req = X509_REQ_new();
    if (!*req) {
        LOG_ERROR("Failed to allocate Memory for request");
        goto error_cleanup;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        LOG_ERROR("Failed to allocate Memory for PKEY context");
        goto error_cleanup;
    }

    /* Create dummy key */

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, dmy_key) <= 0) {
        LOG_ERROR("Failed to create key");
        goto error_cleanup;
    }

    X509_REQ_set_pubkey(*req, *dmy_key);

    /* Self-sign the request to prove that we posses the key. */
    if (!X509_REQ_sign(*req, *dmy_key, EVP_sha256())) {
        LOG_ERROR("Failed to sign request.");
        goto error_cleanup;
    }
    EVP_PKEY_CTX_free(ctx);
    return TSS2_RC_SUCCESS;

 error_cleanup:
    if (dmy_key)
        EVP_PKEY_free(*dmy_key);
    if (req)
        X509_REQ_free(*req);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return TSS2_FAPI_RC_GENERAL_FAILURE;
}

TSS2_RC
get_ek_certificate(EVP_PKEY *ca_key, X509 *ca_cert,
                   X509_REQ *req,
                   EVP_PKEY *ek, X509 **ek_cert)
{
    BIGNUM *bn = NULL;
    unsigned char serial_ary[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    ASN1_INTEGER *serial_asn1 = NULL;

    *ek_cert = X509_new();
    if (!*ek_cert) {
        LOG_ERROR("Failed to allocate Memory for PKEY context");
        goto error_cleanup;
    }
    if (X509_set_version(*ek_cert, 2) <= 0) goto error_cleanup;
    bn = BN_new();
    if (!bn) {
        LOG_ERROR("Failed to allocate BN");
        goto error_cleanup;
    }
    BN_bin2bn(&serial_ary[0], sizeof(serial_ary), bn);
    serial_asn1 = ASN1_INTEGER_new();
    if (!serial_asn1) {
        LOG_ERROR("Failed to allocate ASN1 serial.");
        goto error_cleanup;
    }

    BN_to_ASN1_INTEGER(bn, serial_asn1);

    if (X509_set_serialNumber(*ek_cert, serial_asn1) <= 0 ||
        X509_set_issuer_name(*ek_cert, X509_get_subject_name(ca_cert)) <= 0) {
        LOG_ERROR("Failed to initialize EK cert.");
        goto error_cleanup;
    }

    X509_gmtime_adj(X509_get_notBefore(*ek_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(*ek_cert), (long)3*365*24*3600);

    ASN1_INTEGER_free(serial_asn1);
    BN_free(bn);

    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
    if (X509_set_pubkey(*ek_cert, ek) <= 0) {
        LOG_ERROR("Failed to set pubkey of EK cert.");
        goto error_cleanup;
    }
    EVP_PKEY_free(req_pubkey);

    if (X509_sign(*ek_cert, ca_key, EVP_sha256()) == 0) {
        LOG_ERROR("Failed to sign certificate.");
        goto error_cleanup;
    }
    X509_REQ_free(req);
    return TSS2_RC_SUCCESS;

 error_cleanup:
    X509_REQ_free(req);
    if (bn)
        BN_free(bn);
    if (serial_asn1)
        ASN1_INTEGER_free(serial_asn1);
    if (*ek_cert)
        X509_free(*ek_cert);
    return TSS2_FAPI_RC_GENERAL_FAILURE;
}

TSS2_RC
get_pubkey_fingerprint(EVP_PKEY *key, char **fingerprint)
{
    TPM2_RC rc = TSS2_FAPI_RC_GENERAL_FAILURE;
    size_t size_der_pub;
    unsigned char *der_key = NULL;
    BUF_MEM *bio_mem_data = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256_CTX sha256_context;
#else
    size_t size_hash;
#endif
    unsigned char fingerprint_digest[TPM2_SHA256_DIGEST_SIZE];

    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        LOG_ERROR("Failed to allocate BIO.");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }
    if (i2d_PUBKEY_bio(bio_mem, key) == 0) {
        LOG_ERROR("Failed to get public key.");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }
    BIO_get_mem_ptr(bio_mem, &bio_mem_data);
    der_key = (unsigned char *)bio_mem_data->data;
    size_der_pub = bio_mem_data->length;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (SHA256_Init(&sha256_context) == 0 ||
        SHA256_Update(&sha256_context, der_key, size_der_pub) == 0 ||
        SHA256_Final(&fingerprint_digest[0], &sha256_context) == 0) {
        LOG_ERROR("sha256 update failed.");
        goto error_cleanup;
    }
#else
    if (EVP_Q_digest(NULL, "sha256", NULL, der_key, size_der_pub,
                     &fingerprint_digest[0], &size_hash) == 0) {
        LOG_ERROR("sha256 update failed.");
        goto error_cleanup;
    }
#endif
    *fingerprint = calloc(1, TPM2_SHA256_DIGEST_SIZE * 2 + 1);
    if (!(*fingerprint)) {
        LOG_ERROR("Failed to allocate fingerprint.");
        goto error_cleanup;
    }
    char *pf = &(*fingerprint)[0];
    for (size_t i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++) {
        pf += sprintf(pf, "%.2x", fingerprint_digest[i]);
    }
    rc = TSS2_RC_SUCCESS;

 error_cleanup:
    if (bio_mem)
        BIO_free_all(bio_mem);
    return rc;
 }

TSS2_RC
get_ek_fingerprints(TSS2_SYS_CONTEXT *sys_ctx,
                    char **rsa_fingerprint, char **ecc_fingerprint)
{
    TSS2_RC rc;
    EVP_PKEY *ecc_ek_key_pub = NULL;
    EVP_PKEY *rsa_ek_key_pub = NULL;

    rc = get_ecc_ek_public(sys_ctx, &ecc_ek_key_pub);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get ECC EK: %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }
    rc = get_pubkey_fingerprint(ecc_ek_key_pub, ecc_fingerprint);
    if (rc != TSS2_RC_SUCCESS) {
        goto error_cleanup;
    }

    rc = get_rsa_ek_public(sys_ctx, &rsa_ek_key_pub);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get RSA EK: %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }

    rc = get_pubkey_fingerprint(rsa_ek_key_pub, rsa_fingerprint);
    if (rc != TSS2_RC_SUCCESS) {
        SAFE_FREE(*ecc_fingerprint);
        goto error_cleanup;
    }

 error_cleanup:
    if (ecc_ek_key_pub)
        EVP_PKEY_free(ecc_ek_key_pub);
    if (rsa_ek_key_pub)
        EVP_PKEY_free(rsa_ek_key_pub);
    return rc;
}

TSS2_RC
prepare_certificate(TSS2_SYS_CONTEXT *sys_ctx, X509 *ek_cert,
                    TPM2_NV_INDEX nv_index, char* env_var) {
    TSS2_RC rc;

#if defined(FAPI_TEST_CERTIFICATE) || defined(FAPI_TEST_CERTIFICATE_ECC)
    char *pem_filename;
    FILE *output_file;
    // (void)nv_idex;
    (void)sys_ctx;

    pem_filename = getenv(env_var);
    if (!pem_filename) {
        LOG_ERROR("Environment variable FAPI_TEST_CERTIFICATE_ECC not set.");
        rc = TSS2_FAPI_RC_GENERAL_FAILURE;
        goto error_cleanup;
    }
    output_file = fopen(pem_filename, "w");
    if (!output_file) {
        LOG_ERROR("Error opening output file: %s", pem_filename);
        rc = TSS2_FAPI_RC_GENERAL_FAILURE;
        goto error_cleanup;
    }
    if (PEM_write_X509(output_file, ek_cert) != 1) {
        perror("Error writing X.509 certificate to file");
        fclose(output_file);
        rc = TSS2_FAPI_RC_GENERAL_FAILURE;
        goto error_cleanup;
    }
    fclose(output_file);
#else
    // (void)env_var;

    rc = nv_write(sys_ctx, nv_index, ek_cert);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to write ECC EK cert.");
        goto error_cleanup;
    }
#endif
    rc = TSS2_RC_SUCCESS;

 error_cleanup:
    return rc;
}

TSS2_RC
init_ek_certificates(TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_RC rc;
    X509_REQ *req = NULL;
    EVP_PKEY *dmy_key = NULL;
    X509 *ecc_ek_cert = NULL;
    EVP_PKEY *ecc_ek_key_pub = NULL;
    X509 *rsa_ek_cert = NULL;
    EVP_PKEY *rsa_ek_key_pub = NULL;
    X509 *intermed_cert = NULL;
    EVP_PKEY *intermed_key = NULL;

    rc = get_ecc_ek_public(sys_ctx, &ecc_ek_key_pub);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get ECC EK: %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }

    rc = get_rsa_ek_public(sys_ctx, &rsa_ek_key_pub);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get RSA EK: %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }

#ifdef SELF_SIGNED_CERTIFICATE
    /* The self signed root cert will be used as intermediate certificate. */
    rc = load_intermed_cert_and_key("./ca/root-ca/private/root-ca.key.pem",
                                    &intermed_key,
                                    "./ca/root-ca/root-ca.cert.pem",
                                    &intermed_cert);
#else
    rc = load_intermed_cert_and_key("./ca/intermed-ca/private/intermed-ca.key.pem",
                                    &intermed_key,
                                    "./ca/intermed-ca/intermed-ca.cert.pem",
                                    &intermed_cert);
#endif

     if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to load intermediate key and cert %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }

    rc = get_dummy_csr(&dmy_key, &req);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get req: %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }

    rc = get_ek_certificate(intermed_key, intermed_cert, req,
                            ecc_ek_key_pub, &ecc_ek_cert);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get ECC EK cert.");
        goto error_cleanup;
    }

    rc = prepare_certificate(sys_ctx, ecc_ek_cert, 0x1c0000a,
                             "FAPI_TEST_CERTIFICATE_ECC");
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to prepare ECC EK cert.");
        goto error_cleanup;
    }

    EVP_PKEY_free(dmy_key);
    dmy_key = NULL;
    X509_REQ_free(req);
    req = NULL;

    rc = get_dummy_csr(&dmy_key, &req);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get req: %s\n", Tss2_RC_Decode(rc));
        goto error_cleanup;
    }

    rc = get_ek_certificate(intermed_key, intermed_cert, req,
                            rsa_ek_key_pub, &rsa_ek_cert);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get RSA EK cert.");
        goto error_cleanup;
    }

    rc = prepare_certificate(sys_ctx, rsa_ek_cert, 0x1c00002,
                             "FAPI_TEST_CERTIFICATE");
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to prepare RSA EK cert.");
        goto error_cleanup;
    }

    rc = TSS2_RC_SUCCESS;

 error_cleanup:
    if (req)
        X509_REQ_free(req);
    if (rsa_ek_cert)
        X509_free(rsa_ek_cert);
    if (ecc_ek_cert)
        X509_free(ecc_ek_cert);
    if (dmy_key)
        EVP_PKEY_free(dmy_key);
    if (ecc_ek_key_pub)
        EVP_PKEY_free(ecc_ek_key_pub);
    if (rsa_ek_key_pub)
        EVP_PKEY_free(rsa_ek_key_pub);
    if (intermed_cert)
        X509_free(intermed_cert);
    if (intermed_key)
        EVP_PKEY_free(intermed_key);

    return rc;
}

int
test_fapi_setup(TSS2_TEST_FAPI_CONTEXT **test_ctx)
{
    char template[] = "/tmp/fapi_tmpdir.XXXXXX";
    char *tmpdir = NULL;
    size_t size;
    int ret;

    size = sizeof(TSS2_TEST_FAPI_CONTEXT);
    *test_ctx = calloc(1, size);
    if (test_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for the test context", size);
        goto error;
    }

    tmpdir = strdup(template);
    if (!tmpdir) {
        LOG_ERROR("Failed to allocate name of temp dir.");
        goto error;
    }
    (*test_ctx)->tmpdir = mkdtemp(tmpdir);
    if (!(*test_ctx)->tmpdir) {
        LOG_ERROR("No temp dir created");
        goto error;
    }
    fapi_test_ctx = *test_ctx;

    ret = init_fapi(FAPI_PROFILE, &(*test_ctx)->fapi_ctx);
    if (ret != 0) {
        LOG_ERROR("init fapi failed.");
        goto error;
    }
    (*test_ctx)->test_esys_ctx.esys_ctx = (*test_ctx)->fapi_ctx->esys;
    (*test_ctx)->test_esys_ctx.tpm_state = malloc(sizeof(tpm_state));
    if (test_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for tpm_state.", size);
        goto error;
    }

    return ret;

 error:
    SAFE_FREE(tmpdir);
    SAFE_FREE(*test_ctx);
    return EXIT_ERROR;
}

void
test_fapi_teardown(TSS2_TEST_FAPI_CONTEXT *test_ctx)
{
    if (test_ctx) {
        if (test_ctx->fapi_ctx) {
            Fapi_Finalize(&test_ctx->fapi_ctx);
        }
        SAFE_FREE(test_ctx->tmpdir);
        SAFE_FREE(test_ctx->test_esys_ctx.tpm_state);
        SAFE_FREE(test_ctx);
    }
}

/**
 * This program is a template for integration tests (ones that use the TCTI,
 * the ESAPI, and FAPI contexts / API directly). It does nothing more than
 * parsing  command line options that allow the caller (likely a script)
 * to specifywhich TCTI to use for the test using getenv("TPM20TEST_TCTI").
 */
int
main(int argc, char *argv[])
{
    int ret, size;
    char *config = NULL;
    char *config_path = NULL;
    char *config_env = NULL;
    char *remove_cmd = NULL;
    TSS2_TEST_FAPI_CONTEXT *test_ctx = NULL;

    TSS2_TEST_ESYS_CONTEXT *test_esys_ctx;

    ret = test_esys_setup(&test_esys_ctx);
    if (ret != 0) {
        return ret;
    }
#if !defined(FAPI_NONTPM) && !defined(DLOPEN) && defined(SELF_GENERATED_CERTIFICATE) && \
    !defined(FAPI_TEST_FINGERPRINT) && !defined(FAPI_TEST_FINGERPRINT_ECC)
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_RC rc;

    rc = Esys_GetSysContext(test_esys_ctx->esys_ctx, &sys_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get SysContext: %s\n", Tss2_RC_Decode(rc));
        ret = 1;
        goto error;
    }
    rc = init_ek_certificates(sys_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to initialize EK certificates: %s\n",
                  Tss2_RC_Decode(rc));
        ret = 1;
        goto error;
    }
#else
    char *ecc_fingerprint = NULL;
    char *rsa_fingerprint = NULL;
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_RC rc;

    rc = Esys_GetSysContext(test_esys_ctx->esys_ctx, &sys_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to get SysContext: %s\n", Tss2_RC_Decode(rc));
        return EXIT_ERROR;
    }

    rc = get_ek_fingerprints(sys_ctx, &rsa_fingerprint, &ecc_fingerprint);
    if (rc != TSS2_RC_SUCCESS) {
        return EXIT_ERROR;
    }
    setenv("FAPI_TEST_FINGERPRINT", rsa_fingerprint, 1);
    setenv("FAPI_TEST_FINGERPRINT_ECC", ecc_fingerprint, 1);
    free(rsa_fingerprint);
    free(ecc_fingerprint);
#endif

    test_esys_teardown(test_esys_ctx);

    ret = test_fapi_setup(&test_ctx);
    if (ret != 0) {
        goto error;
    }

#if !defined(FAPI_NONTPM) && !defined(DLOPEN)
    ret = test_fapi_checks_pre(test_ctx);
    if (ret != 0) {
        goto error;
    }
#endif

    ret = test_invoke_fapi(test_ctx->fapi_ctx);
    LOG_INFO("Test returned %i", ret);
    if (ret) goto error;

#if !defined(FAPI_NONTPM) && !defined(DLOPEN)
    test_ctx->test_esys_ctx.esys_ctx = test_ctx->fapi_ctx->esys;
    ret = test_fapi_checks_post(test_ctx);
    if (ret != 0) {
        goto error;
    }

#endif

    size = asprintf(&remove_cmd, "rm -r -f %s", test_ctx->tmpdir);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    if (system(remove_cmd) != 0) {
        LOG_ERROR("Directory %s can't be deleted.", test_ctx->tmpdir);
        ret = EXIT_ERROR;
        goto error;
    }

error:
    test_fapi_teardown(test_ctx);
    if (config) free(config);
    if (config_path) free(config_path);
    if (config_env) free(config_env);
    if (remove_cmd) free(remove_cmd);

    return ret;
}
