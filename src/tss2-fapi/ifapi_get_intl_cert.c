/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "fapi_crypto.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

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

static unsigned char *hash_ek_public(TPM2B_PUBLIC *ek_public) {

    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    if (!hash) {
        LOG_ERROR("OOM");
        return NULL;
    }

    SHA256_CTX sha256;
    int is_success = SHA256_Init(&sha256);
    if (!is_success) {
        LOG_ERROR("SHA256_Init failed");
        goto err;
    }

    switch (ek_public->publicArea.type) {
    case TPM2_ALG_RSA:
        is_success = SHA256_Update(&sha256,
                                   ek_public->publicArea.unique.rsa.buffer,
                                   ek_public->publicArea.unique.rsa.size);
        if (!is_success) {
            LOG_ERROR("SHA256_Update failed");
            goto err;
        }

        if (ek_public->publicArea.parameters.rsaDetail.exponent != 0) {
            LOG_ERROR("non-default exponents unsupported");
            goto err;
        }
        BYTE buf[3] = { 0x1, 0x00, 0x01 }; // Exponent
        is_success = SHA256_Update(&sha256, buf, sizeof(buf));
        if (!is_success) {
            LOG_ERROR("SHA256_Update failed");
            goto err;
        }
        break;

    case TPM2_ALG_ECC:
        is_success = SHA256_Update(&sha256,
                                   ek_public->publicArea.unique.ecc.x.buffer,
                                   ek_public->publicArea.unique.ecc.x.size);
        if (!is_success) {
            LOG_ERROR("SHA256_Update failed");
            goto err;
        }

        is_success = SHA256_Update(&sha256,
                                   ek_public->publicArea.unique.ecc.y.buffer,
                                   ek_public->publicArea.unique.ecc.y.size);
        if (!is_success) {
            LOG_ERROR("SHA256_Update failed");
            goto err;
        }
        break;

    default:
        LOG_ERROR("unsupported EK algorithm");
        goto err;
    }

    is_success = SHA256_Final(hash, &sha256);
    if (!is_success) {
        LOG_ERROR("SHA256_Final failed");
        goto err;
    }

    LOG_TRACE("public-key-hash:");
    LOG_TRACE("  sha256: ");
    LOGBLOB_TRACE(&hash[0], SHA256_DIGEST_LENGTH, "Hash");
    return hash;
err:
    free(hash);
    return NULL;
}

char *base64_encode(const unsigned char* buffer)
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
        char *output = curl_easy_escape(curl, b64text, len);
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

struct CertificateBuffer {
  unsigned char *buffer;
  size_t size;
};

static size_t
get_certificate_buffer_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct CertificateBuffer *cert = (struct CertificateBuffer *)userp;

    unsigned char *tmp_ptr = realloc(cert->buffer, cert->size + realsize + 1);
    if (tmp_ptr == NULL) {
        LOG_ERROR("Can't allocate memory in CURL callback.");
        return 0;
    }
    cert->buffer = tmp_ptr;
    memcpy(&(cert->buffer[cert->size]), contents, realsize);
    cert->size += realsize;
    cert->buffer[cert->size] = 0;

    return realsize;
}

int retrieve_endorsement_certificate(char *b64h, unsigned char ** buffer,
                                     size_t *cert_size) {
    int ret = -1;

    size_t len = 1 + strlen(b64h) + strlen(ctx.ek_server_addr);
    struct CertificateBuffer cert_buffer = { .size = 0, .buffer = NULL };
    char *weblink = (char *) malloc(len);

    if (!weblink) {
        LOG_ERROR("oom");
        return ret;
    }

    snprintf(weblink, len, "%s%s", ctx.ek_server_addr, b64h);

    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        LOG_ERROR("curl_global_init failed: %s", curl_easy_strerror(rc));
        goto out_memory;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR("curl_easy_init failed");
        goto out_global_cleanup;
    }

    /*
     * should not be used - Used only on platforms with older CA certificates.
     */
    if (ctx.SSL_NO_VERIFY) {
        rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        if (rc != CURLE_OK) {
            LOG_ERROR("curl_easy_setopt for CURLOPT_SSL_VERIFYPEER failed: %s",
                      curl_easy_strerror(rc));
            goto out_easy_cleanup;
        }
    }

    rc = curl_easy_setopt(curl, CURLOPT_URL, weblink);
    if (rc != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt for CURLOPT_URL failed: %s",
                curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                           get_certificate_buffer_cb);
    if (rc != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt for CURLOPT_URL failed: %s",
                curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA,
                          (void *)&cert_buffer);
    if (rc != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt for CURLOPT_URL failed: %s",
                curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    if (LOGMODULE_status == LOGLEVEL_TRACE) {
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L)) {
            LOG_WARNING("Curl easy setopt verbose failed");
        }
    }

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOG_ERROR("curl_easy_perform() failed: %s", curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    *buffer = cert_buffer.buffer;
    *cert_size = cert_buffer.size;

    ret = 0;

out_easy_cleanup:
    if (ret != 0)
        free(cert_buffer.buffer);
    curl_easy_cleanup(curl);
out_global_cleanup:
    curl_global_cleanup();
out_memory:
    free(weblink);

    return ret;
}

/**
 * Get INTEL certificate for EK
 *
 * @param[in] context The FAPI context with the configuration data.
 * @param[in] ek_public The out public data of the EK.
 * @param[out] cert_buffer the der encoded certificate.
 * @param[out] cert_size The size of the certificate buffer.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_NO_CERT If an error did occur during certificate downloading.
 */
TSS2_RC
ifapi_get_intl_ek_certificate(FAPI_CONTEXT *context, TPM2B_PUBLIC *ek_public,
                              unsigned char ** cert_buffer, size_t *cert_size)
{
    int rc = 1;
    unsigned char *hash = hash_ek_public(ek_public);
    char *b64 = base64_encode(hash);
    if (!b64) {
        LOG_ERROR("base64_encode returned null");
        goto out;
    }
    if (context->config.intel_cert_service)
        ctx.ek_server_addr = context->config.intel_cert_service;
    else
        ctx.ek_server_addr = "https://ekop.intel.com/ekcertservice/";

    LOG_INFO("%s", b64);

    rc = retrieve_endorsement_certificate(b64, cert_buffer, cert_size);
    free(b64);
out:
    /* In some case this call was necessary after curl usage */
    OpenSSL_add_all_algorithms();

    free(hash);
    if (rc == 0) {
        return TSS2_RC_SUCCESS;
    } else {
        LOG_ERROR("Get INTEL EK certificate.");
        return TSS2_FAPI_RC_NO_CERT;
    }
}
