/* SPDX-FileCopyrightText: 2023, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <curl/curl.h>             // for curl_easy_cleanup, curl_easy_init
#include <json.h>                  // for json_object_get_string, json_objec...
#include <openssl/bio.h>           // for BIO_new, BIO_free_all, BIO_push
#include <openssl/buffer.h>        // for buf_mem_st
#include <openssl/evp.h>           // for EVP_DigestUpdate, BIO_f_base64
#include <openssl/opensslv.h>      // for OPENSSL_VERSION_NUMBER
#include <openssl/sha.h>           // for SHA256_DIGEST_LENGTH
#include <stdbool.h>               // for bool, true
#include <stdint.h>                // for uint8_t
#include <stdio.h>                 // for NULL, size_t, snprintf, sprintf, FILE
#include <stdlib.h>                // for free, malloc, calloc
#include <string.h>                // for strdup, strlen

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/aes.h>
#endif

#include "fapi_int.h"              // for FAPI_CONTEXT, VENDOR_AMD, VENDOR_INTC
#include "ifapi_config.h"          // for IFAPI_CONFIG
#include "ifapi_curl.h"            // for ifapi_get_curl_buffer
#include "tpm_json_deserialize.h"  // for ifapi_parse_json
#include "tss2_common.h"           // for BYTE, TSS2_FAPI_RC_GENERAL_FAILURE
#include "tss2_fapi.h"             // for FAPI_CONTEXT
#include "tss2_tpm2_types.h"       // for TPM2B_PUBLIC, TPMT_PUBLIC, TPMU_PU...

#define LOGMODULE fapi
#include "util/log.h"              // for LOG_ERROR, goto_error, SAFE_FREE

struct tpm_getekcertificate_ctx;

#define AMD_EK_URI_LEN 16 /*<< AMD EK takes first 16 hex chars of hash */
#define NULL_TERM_LEN 1 // '\0'

typedef struct tpm_getekcertificate_ctx tpm_getekcertificate_ctx;
struct tpm_getekcertificate_ctx {
    char *ec_cert_path;
    FILE *ec_cert_file_handle;
    char *ek_server_addr;
    unsigned int SSL_NO_VERIFY;
    char *ek_path;
    bool verbose;
    bool is_tpm2_device_active;
    TPM2B_PUBLIC *out_public;
};

static tpm_getekcertificate_ctx ctx = {
    .is_tpm2_device_active = true,
};

/** Compute the SHA256 hash from the public key of an EK.
 *
 * @param[in]  ek_public The public information of the EK.
 * @retval unsigned_char* The hash value.
 * @retval NULL If the computation of the hash fails.
 */
static unsigned char *hash_ek_public(TPM2B_PUBLIC *ek_public, UINT32 vendor) {
    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    if (!hash) {
        LOG_ERROR("OOM");
        return NULL;
    }

    EVP_MD_CTX *sha256ctx = EVP_MD_CTX_new();
    if (!sha256ctx) {
        LOG_ERROR("EVP_MD_CTX_new failed");
        goto err;
    }

    int is_success = EVP_DigestInit(sha256ctx, EVP_sha256());
    if (!is_success) {
        LOG_ERROR("EVP_DigestInit failed");
        goto err;
    }

    if (vendor == VENDOR_AMD) {
        switch (ek_public->publicArea.type) {
        case TPM2_ALG_RSA: {
            /*
             * hash = sha256(00 00 22 22 || (uint32_t) exp || modulus)
             */
            BYTE buf[4] = { 0x00, 0x00, 0x22, 0x22 }; // Prefix
            is_success = EVP_DigestUpdate(sha256ctx, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }

            UINT32 exp = ek_public->publicArea.parameters.rsaDetail.exponent;
            if (exp == 0) {
                exp = 0x00010001; // 0 indicates default
            } else {
                LOG_WARNING("non-default exponent used");
            }
            buf[3] = (BYTE)exp;
            buf[2] = (BYTE)(exp>>=8);
            buf[1] = (BYTE)(exp>>=8);
            buf[0] = (BYTE)(exp>>8);
            is_success = EVP_DigestUpdate(sha256ctx, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256ctx,
                    ek_public->publicArea.unique.rsa.buffer,
                    ek_public->publicArea.unique.rsa.size);
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }
            break;
        }
        case TPM2_ALG_ECC: {
            /*
             * hash = sha256(00 00 44 44 || (UINT32) exp || modulus)
             */
            BYTE buf[4] = { 0x00, 0x00, 0x44, 0x44 }; // Prefix
            is_success = EVP_DigestUpdate(sha256ctx, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }
            is_success = EVP_DigestUpdate(sha256ctx,
                    ek_public->publicArea.unique.ecc.x.buffer,
                    ek_public->publicArea.unique.ecc.x.size);
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256ctx,
                    ek_public->publicArea.unique.ecc.y.buffer,
                    ek_public->publicArea.unique.ecc.y.size);
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }
            break;
        }
        default:
            LOG_ERROR("unsupported EK algorithm");
            goto err;
        }
    } else {
        switch (ek_public->publicArea.type) {
        case TPM2_ALG_RSA:
            /* Add public key to the hash. */
            is_success = EVP_DigestUpdate(sha256ctx,
                                          ek_public->publicArea.unique.rsa.buffer,
                                          ek_public->publicArea.unique.rsa.size);
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }

            /* Add exponent to the hash. */
            if (ek_public->publicArea.parameters.rsaDetail.exponent != 0) {
                LOG_ERROR("non-default exponents unsupported");
                goto err;
            }
            /* Exponent 65537 will be added. */
            BYTE buf[3] = { 0x1, 0x00, 0x01 };
            is_success = EVP_DigestUpdate(sha256ctx, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }
            break;

        case TPM2_ALG_ECC:
            is_success = EVP_DigestUpdate(sha256ctx,
                                          ek_public->publicArea.unique.ecc.x.buffer,
                                          ek_public->publicArea.unique.ecc.x.size);
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }

            /* Add public key to the hash. */
            is_success = EVP_DigestUpdate(sha256ctx,
                                          ek_public->publicArea.unique.ecc.y.buffer,
                                          ek_public->publicArea.unique.ecc.y.size);
            if (!is_success) {
                LOG_ERROR("EVP_DigestUpdate failed");
                goto err;
            }
            break;

        default:
            LOG_ERROR("unsupported EK algorithm");
            goto err;
        }
    }

    is_success = EVP_DigestFinal_ex(sha256ctx, hash, NULL);
    if (!is_success) {
        LOG_ERROR("SHA256_Final failed");
        goto err;
    }

    EVP_MD_CTX_free(sha256ctx);
    LOG_TRACE("public-key-hash:");
    LOG_TRACE("  sha256: ");
    LOGBLOB_TRACE(&hash[0], SHA256_DIGEST_LENGTH, "Hash");
    return hash;
err:
    EVP_MD_CTX_free(sha256ctx);
    free(hash);
    return NULL;
}

/** Calculate the base64 encoding of the hash of the Endorsement Public Key.
 *
 * @param[in] buffer The hash of the endorsement public key.
 * @retval char* The base64 encoded string.
 * @retval NULL if the encoding fails.
 */
static char *
base64_encode(const unsigned char* buffer)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_pointer;

    LOG_INFO("Calculating the base64_encode of the hash of the Endorsement"
             "Public Key:");

    if (buffer == NULL) {
        LOG_ERROR("hash_ek_public returned null");
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, SHA256_DIGEST_LENGTH);
    (void)(BIO_flush(bio));
    BIO_get_mem_ptr(bio, &buffer_pointer);

    /* these are not NULL terminated */
    char *b64text = buffer_pointer->data;
    size_t len = buffer_pointer->length;

    size_t i;
    for (i = 0; i < len; i++) {
        if (b64text[i] == '+') {
            b64text[i] = '-';
        }
        if (b64text[i] == '/') {
            b64text[i] = '_';
        }
    }

    char *final_string = NULL;

    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_escape(curl, b64text, (int) len);
        if (output) {
            final_string = strdup(output);
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    BIO_free_all(bio);

    /* format to a proper NULL terminated string */
    return final_string;
}

/** Decode a base64 encoded certificate into binary form.
 *
 * @param[in]  buffer The base64 encoded certificate.
 * @param[in]  len The length of the encoded certificate.
 * @param[out] new_len The lenght of the binary certificate.
 * @retval char* The binary data of the certificate.
 * @retval NULL if the decoding fails.
 */
static char *
base64_decode(unsigned char* buffer, size_t len, size_t *new_len)
{
    size_t i;
    int unescape_len = 0, r = 0;
    char *binary_data = NULL, *unescaped_string = NULL;

    LOG_INFO("Decoding the base64 encoded cert into binary form");

    if (buffer == NULL) {
        LOG_ERROR("Cert buffer is null");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (buffer[i] == '-') {
            buffer[i] = '+';
        }
        if (buffer[i] == '_') {
            buffer[i] = '/';
        }
    }

    CURL *curl = curl_easy_init();
    if (curl) {
        /* Convert URL encoded string to a "plain string" */
        char *output = curl_easy_unescape(curl, (char *)buffer,
                                          (int) len, &unescape_len);
        if (output) {
            unescaped_string = strdup(output);
            curl_free(output);
        } else {
            LOG_ERROR("curl_easy_unescape failed.");
        }
    } else {
        LOG_ERROR("curl_easy_init failed.");
        return NULL;
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    if (unescaped_string == NULL) {
        LOG_ERROR("Computation of unescaped string failed.");
        return NULL;
    }

    binary_data = calloc(1, unescape_len);
    if (binary_data == NULL) {
        free (unescaped_string);
        LOG_ERROR("Allocation of data for certificate failed.");
        return NULL;
    }

    BIO *bio, *b64;
    bio = BIO_new_mem_buf(unescaped_string, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    if ((r = BIO_read(bio, binary_data, unescape_len)) <= 0) {
        LOG_ERROR("BIO_read base64 encoded cert failed");
        free(binary_data);
        binary_data = NULL;
    }
    *new_len = (size_t)r;

    free (unescaped_string);
    BIO_free_all(bio);
    return binary_data;
}

/** Encode the hash to the path required by the vendor
 *
 * @param[in] hash The sha256 hash of the public ek.
 * @retval The encoded path.
 */
static char *encode_ek_public(unsigned char *hash, UINT32 vendor) {
    if (vendor == VENDOR_INTC) {
        return base64_encode(hash);
    } else {
        char *hash_str = malloc(AMD_EK_URI_LEN * 2 + NULL_TERM_LEN);
        for (size_t i = 0; i < AMD_EK_URI_LEN; i++)
            {
                sprintf((char*)(hash_str + (i*2)), "%02x", hash[i]);
            }
        hash_str[AMD_EK_URI_LEN * 2] = '\0';
        return hash_str;
    }
}

/** Get endorsement certificate from the WEB.
 *
 * The base64 encoded public endorsement key will be added to the INTEL
 * server address and used as URL to retrieve the certificate.
 * The certificate will be retrieved via curl.
 *
 * @param[in]  b64h The base64 encoded public key.
 * @param[out] buffer The json encoded certificate.
 * @param[out] cert_size The size of the certificate.
 */
int retrieve_endorsement_certificate(char *path, unsigned char ** buffer,
                                     size_t *cert_size) {
    int ret = -1;

    size_t len = 1 + strlen(path) + strlen(ctx.ek_server_addr);
    char *weblink = (char *) malloc(len);

    if (!weblink) {
        LOG_ERROR("oom");
        return ret;
    }

    snprintf(weblink, len, "%s%s", ctx.ek_server_addr, path);

    CURLcode rc =  ifapi_get_curl_buffer((unsigned char *)weblink,
                                         buffer, cert_size);
    free(weblink);
    return rc;
}

/** Get INTEL certificate for EK
 *
 * Using the base64 encoded public endorsement key the JSON encoded certificate
 * will be downloaded.
 * The JSON certificate will be parsed and the base64 encoded certificate
 * will be converted into binary format.
 *
 *
 * @param[in] context The FAPI context with the configuration data.
 * @param[in] ek_public The out public data of the EK.
 * @param[out] cert_buffer the der encoded certificate.
 * @param[out] cert_size The size of the certificate buffer.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_NO_CERT If an error did occur during certificate downloading.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occured.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_get_web_ek_certificate(FAPI_CONTEXT *context, TPM2B_PUBLIC *ek_public,
                              UINT32 vendor,
                              unsigned char ** cert_buffer, size_t *cert_size)
{
    int rc = 1;
    char *cert_ptr = NULL;
    char *cert_start = NULL, *cert_bin = NULL;
    char *path = NULL;
    unsigned char *hash = hash_ek_public(ek_public, vendor);
    struct json_object *jso_cert, *jso = NULL;

    if (hash == NULL) {
        goto_error(rc, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Compute EK hash failed.", out);
    }

    path = encode_ek_public(hash, vendor);
    *cert_buffer = NULL;

    if (!path) {
        LOG_ERROR("encode ek hash returned null");
        goto out;
    }
    if (context->config.web_cert_service) {
        ctx.ek_server_addr = context->config.web_cert_service;
    } else {
        if (vendor == VENDOR_AMD) {
            ctx.ek_server_addr = "https://ftpm.amd.com/pki/aia/";
        } else {
            ctx.ek_server_addr = "https://ekop.intel.com/ekcertservice/";
        }
    }

    LOG_INFO("%s", path);

    /* Download the JSON encoded certificate. */
    rc = retrieve_endorsement_certificate(path, cert_buffer, cert_size);
    free(path);
    goto_if_error(rc, "Retrieve endorsement certificate", out);
    cert_ptr = (char *)*cert_buffer;
    LOGBLOB_DEBUG((uint8_t *)cert_ptr, *cert_size, "%s", "Certificate");

    if (vendor == VENDOR_INTC ) {
        /* Parse certificate data out of the json structure */
        jso = ifapi_parse_json(cert_ptr);
        if (jso == NULL)
            goto_error(rc, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Failed to parse EK cert data", out_free_json);

        if (!json_object_object_get_ex(jso, "certificate", &jso_cert))
            goto_error(rc, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Could not find cert object", out_free_json);

        if (!json_object_is_type(jso_cert, json_type_string))
            goto_error(rc, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Invalid EK cert data", out_free_json);

        cert_start = strdup(json_object_get_string(jso_cert));
        if (!cert_start) {
            SAFE_FREE(cert_ptr);
            goto_error(rc, TSS2_FAPI_RC_MEMORY,
                       "Failed to duplicate cert", out_free_json);
        }

        *cert_size = strlen(cert_start);

        /* Base64 decode buffer into binary PEM format */
        cert_bin = base64_decode((unsigned char *)cert_start,
                                 *cert_size, cert_size);
        SAFE_FREE(cert_ptr);
        SAFE_FREE(cert_start);
    } else {
        cert_bin = cert_ptr;
    }
      if (cert_bin == NULL) {
        goto_error(rc, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Invalid EK cert data", out_free_json);
    }
    LOG_DEBUG("Binary cert size %zu", *cert_size);
    *cert_buffer = (unsigned char *)cert_bin;

out_free_json:
    if (jso)
        json_object_put(jso);

out:
    free(hash);
    if (rc == 0) {
        return TSS2_RC_SUCCESS;
    } else {
        SAFE_FREE(cert_bin);
        SAFE_FREE(cert_ptr);
        LOG_ERROR("Get INTEL EK certificate.");
        return TSS2_FAPI_RC_NO_CERT;
    }
}
