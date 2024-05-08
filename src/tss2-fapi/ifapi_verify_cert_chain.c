/* SPDX-FileCopyrightText: 2024, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h"             // for HAVE_CURL_URL_STRERROR
#endif

#include <openssl/bio.h>        // for BIO_free, BIO_new_mem_buf
#include <openssl/evp.h>        // for X509, ASN1_IA5STRING, X509_CRL, DIST_...
#include <openssl/obj_mac.h>    // for NID_crl_distribution_points, NID_info...
#include <openssl/opensslv.h>   // for OPENSSL_VERSION_NUMBER
#include <openssl/pem.h>        // for PEM_read_bio_X509
#include <openssl/safestack.h>  // for STACK_OF
#include <openssl/x509.h>       // for X509_free, X509_STORE_add_cert, X509_...
#include <openssl/x509v3.h>     // for DIST_POINT_NAME, GENERAL_NAME, ACCESS...
#include <openssl/err.h>        // for ERR_error_string_n, ERR_get_error
#include <stdbool.h>            // for bool, false, true
#include <stdlib.h>             // for free, realloc
#include <string.h>             // for memcpy, strdup, strlen

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/aes.h>
#endif

#include "fapi_certificates.h"  // for root_cert_list
#include "fapi_int.h"           // for OSSL_FREE
#include "ifapi_curl.h"          // for ifapi_get_crl_from_cert
#include "ifapi_helpers.h"      // linked lists...
#include "ifapi_macros.h"       // for goto_if_null2

#define LOGMODULE fapi
#include "util/log.h"           // for LOG_ERROR, goto_error, SAFE_FREE, got...


/* Free linked list of X509 certificates */
void
free_cert_list(NODE_OBJECT_T *node)
{
    NODE_OBJECT_T *next;
    if (node == NULL)
        return;
    while (node != NULL) {
        OSSL_FREE(node->object, X509);
        next = node->next;
        free(node);
        node = next;
    }
}

/* Check whether certificate is self signed. */
static bool
is_self_signed_cert(X509 *cert) {
    X509_NAME *issuer = X509_get_issuer_name(cert);
    X509_NAME *subject = X509_get_subject_name(cert);

    /* Compare the issuer and subject names */
    if (X509_NAME_cmp(issuer, subject) == 0) {
        return true;
    } else {
        return false;
    }
}

/* Get the url of the issuer stored in the certificate */
char* get_issuer_url(X509 *cert) {
    AUTHORITY_INFO_ACCESS *info = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (!info) return NULL;

    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers && ad->location->type == GEN_URI) {
            ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;
            char *url = strndup((char *)uri->data, uri->length);
            AUTHORITY_INFO_ACCESS_free(info);
            return url;
        }
    }
    AUTHORITY_INFO_ACCESS_free(info);
    return NULL;
}

/* Function to download a certificate */
X509 *download_cert(char* url) {
    unsigned char *cert_buffer = NULL;
    size_t cert_buffer_size;
    X509 *cert = NULL;
    unsigned const char* tmp_ptr1;
    unsigned const char** tmp_ptr2;
    int curl_rc;

    curl_rc = ifapi_get_curl_buffer((unsigned char *)url, &cert_buffer, &cert_buffer_size);
    if (curl_rc != 0) {
        return NULL;
    }
    tmp_ptr1 = cert_buffer;
    tmp_ptr2 = &tmp_ptr1;

    if (!d2i_X509(&cert, tmp_ptr2, (long) cert_buffer_size)) {
        return NULL;
    }
    return cert;
}

void
log_x509_name(X509_NAME *name) {
    char* str = X509_NAME_oneline(name, NULL, 0);
    LOG_DEBUG("X509_name: %s", str);
    free(str);
}


/* Function to find the issuer cert for a certain cert. */
TSS2_RC
find_issuer_for_cert(NODE_OBJECT_T *head, X509 *cert, X509 **issuer_cert) {
    char *url = NULL;
    NODE_OBJECT_T *current = head;
    TSS2_RC r;

    *issuer_cert = NULL;
    while (current) {
        if (X509_NAME_cmp(X509_get_subject_name(current->object), X509_get_issuer_name(cert)) == 0) {
            LOG_DEBUG("Found issuer:");
            X509_get_subject_name(current->object);
            *issuer_cert = current->object;
            return TSS2_RC_SUCCESS;
        }
        current = current->next;
    }
    /* Check url stored in cert */
    url = get_issuer_url(cert);
    if (url) {
        *issuer_cert = download_cert(url);
        if (!*issuer_cert) {
            goto_error(r, TSS2_FAPI_RC_NO_CERT, "Get certificate from %s.", error, url);
        }
        LOG_DEBUG("Downloaded certificate:");
        log_x509_name(X509_get_subject_name(*issuer_cert));
    }
    SAFE_FREE(url);
    return TSS2_RC_SUCCESS;

 error:
    SAFE_FREE(url);
    return r;
}

/* Function to find a certificate node by subject from issuer. */
bool
find_cert_by_issuer(NODE_OBJECT_T *head, X509_NAME *issuer_name) {
    NODE_OBJECT_T *current = head;

    while (current) {
        if (X509_NAME_cmp(X509_get_subject_name(current->object), issuer_name) == 0) {
            LOG_DEBUG("Found Root Certificate:");
            log_x509_name(issuer_name);
            return true;
        }
        current = current->next;
    }
    LOG_DEBUG("No root certificate");
    log_x509_name(issuer_name);
    return false;
}

static TSS2_RC
construct_cert_chain(NODE_OBJECT_T *cert_list, X509 *ek_cert,
                     STACK_OF(X509) *chain, STACK_OF(X509_CRL) *crls,
                     X509_STORE *store, NODE_OBJECT_T *root_certs) {
    TSS2_RC r;
    X509 *current = NULL;
    X509 *next = NULL;
    X509_CRL *crl = NULL;

     /* Create chain of intermediate certificates from EK certificate. */
    current = ek_cert;
    while(current) {
        /* Add crl for intermediate certificate. */
        r = ifapi_get_crl_from_cert(current, &crl);
        return_if_error(r, "Get crl for certificate.");

        if (crl) {
            sk_X509_CRL_push(crls, crl);

            /* Set the flags of the store to use CRLs. */
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL |
                                 X509_V_FLAG_EXTENDED_CRL_SUPPORT);
            if (1 != X509_STORE_add_crl(store, crl)) {
                return_error(TSS2_FAPI_RC_GENERAL_FAILURE,
                           "Failed to add intermediate crl.");
            }
        }
        if (current != ek_cert) {
            /* Add only intermediate certificates. */
            LOG_DEBUG("Push cert to chain.");
            log_x509_name(X509_get_subject_name(current));
            sk_X509_push(chain, current);
        }

        if (find_cert_by_issuer(root_certs, X509_get_issuer_name(current))) {
            /* Trusted issuer certificate */
            break;
        }

        r  = find_issuer_for_cert(cert_list, current, &next);
        return_if_error(r, "Get intermediate certificate.");

        if (!next) {
            /* Root certificate downloaded has to be in store. */
            break;
        }
        if (is_self_signed_cert(next)) {
            return_error(TSS2_FAPI_RC_GENERAL_FAILURE,
                         "Found Self signed certificate not allowed by FAPI.");
        }

        current = next;
    }
    return TSS2_RC_SUCCESS;
}

static X509
*get_X509_from_pem(const char *pem_cert)
{
    if (!pem_cert) {
        return NULL;
    }
    BIO *bufio = NULL;
    X509 *cert = NULL;

    /* Use BIO buffer for conversion */
    size_t pem_length = strlen(pem_cert);
    bufio = BIO_new_mem_buf((void *)pem_cert, (int) pem_length);
    if (!bufio)
        return NULL;
    /* Convert the certificate */
    cert = PEM_read_bio_X509(bufio, NULL, NULL, NULL);
    BIO_free(bufio);
    return cert;
}

/**
 * Verify EK certificate read from TPM with cert list stored in NV ram.
 *
 * @param[in] ek_pem The ek certificate in pem format.
 * @param[in] cert_buff a list of intermediate der cerficicates stored in
 *                      NV ram.
 * @param[in] cert_bu_size The size of the certificate buffer..
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_verify_cert_chain(char* ek_pem, uint8_t *cert_buf, size_t cert_buf_size,
                        char* root_cert_pem,
                        char* intermed_cert_pem) {
    TSS2_RC r;
    const uint8_t *current_pos = cert_buf;
    size_t remaining_length = cert_buf_size;
    NODE_OBJECT_T *cert_list = NULL;
    NODE_OBJECT_T *root_certs = NULL;
    X509 *ek_cert = NULL;
    BIO *bio = NULL;
    STACK_OF(X509) *chain = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    X509 *root_cert = NULL;
    X509 *intermed_cert = NULL;

    /* Create linked list with all X509 intermediate certificates. */
    while (remaining_length > 0) {
        X509 *cert = d2i_X509(NULL, &current_pos, remaining_length);
        goto_if_null(cert, "Failed to convert DER certificate to X509 certificate.",
                     TSS2_FAPI_RC_MEMORY, error);

        r = append_object_to_list(cert, &cert_list);
        goto_if_error(r, "Failed to create certificate list.", error);

        /* Calculate the length of the current certificate in the buffer. */
        size_t cert_length = current_pos - (cert_buf + (cert_buf_size - remaining_length));
        remaining_length -= cert_length;

    }

    /* Convert EK certificate from PEM to X509. */
    bio = BIO_new_mem_buf(ek_pem, -1);
    if (!bio) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error);
    }
    ek_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    goto_if_null(ek_cert, "Failed do convert EK certificate", TSS2_FAPI_RC_GENERAL_FAILURE,
                 error);
    OSSL_FREE(bio, BIO);
    chain = sk_X509_new_null();
    goto_if_null(chain, "Out of memory", TSS2_FAPI_RC_MEMORY, error);

    crls = sk_X509_CRL_new_null();
    goto_if_null(chain, "Out of memory", TSS2_FAPI_RC_MEMORY, error);

    store = X509_STORE_new();
    goto_if_null(store, "Out of memory", TSS2_FAPI_RC_MEMORY, error);


    /* Add test  root cert if passed as parameter */
    if (root_cert_pem) {
        root_cert = get_X509_from_pem(root_cert_pem);
        goto_if_null2(root_cert, "Failed to convert PEM certificate to DER.",
                      r, TSS2_FAPI_RC_BAD_VALUE, error);

        if (1 != X509_STORE_add_cert(store, root_cert)) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Failed to add root certificate", error);
        }

        r = append_object_to_list(root_cert, &root_certs);
        goto_if_error(r, "Failed to create certificate list.", error);
    }

    /* Add intermediate test cert passed as parameter */
    if (intermed_cert_pem) {
        intermed_cert = get_X509_from_pem(intermed_cert_pem);
        goto_if_null2(intermed_cert, "Failed to convert PEM certificate to DER.",
                      r, TSS2_FAPI_RC_BAD_VALUE, error);

        r = append_object_to_list(intermed_cert, &cert_list);
        goto_if_error(r, "Failed to create certificate list.", error);
    }

    /* Add stored root certificates */
    for (uint i = 0; i < sizeof(root_cert_list) / sizeof(char *); i++) {
         root_cert = get_X509_from_pem(root_cert_list[i]);
         goto_if_null(root_cert, "Failed to convert PEM certificate to DER.",
                      TSS2_FAPI_RC_BAD_VALUE, error);

         r = append_object_to_list(root_cert, &root_certs);
         goto_if_error(r, "Failed to create certificate list.", error);

         if (1 != X509_STORE_add_cert(store, root_cert)) {
             goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                        "Failed to add root certificate", error);
        }
    }

    /* Add intermediate certificates to chain and crls to store. */
    r = construct_cert_chain(cert_list, ek_cert, chain, crls, store, root_certs);
    goto_if_error(r, "Failed to construct cert chain.", error);

    /* Verify the certificate chain. */
    store_ctx = X509_STORE_CTX_new();
    goto_if_null(store_ctx, "Out of memory", TSS2_FAPI_RC_MEMORY, error);

    if (X509_STORE_CTX_init(store_ctx, store, ek_cert, chain) != 1) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to init X509 store", error);
    }

    X509_STORE_CTX_set0_untrusted(store_ctx, chain);
    X509_STORE_CTX_set0_crls(store_ctx, crls);

    LOG_DEBUG("Verify EK certificate:\n%s", ek_pem);

    if (X509_verify_cert(store_ctx) == 1) {
        /* Verification of EK was successful. */
        OSSL_FREE(ek_cert, X509);
        OSSL_FREE(chain, sk_X509);
        OSSL_FREE(store_ctx, X509_STORE_CTX);
        OSSL_FREE(store, X509_STORE);
        free_cert_list(cert_list);
        free_cert_list(root_certs);
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        return TSS2_RC_SUCCESS;
    }
    int err = X509_STORE_CTX_get_error(store_ctx);
    if (X509_verify_cert_error_string(err)) {
        LOG_ERROR("EK verification failed: %s", X509_verify_cert_error_string(err));
    } else {
        LOG_ERROR("EK verification failed.");
    }

    r =  TSS2_FAPI_RC_GENERAL_FAILURE;

 error:
    OSSL_FREE(ek_cert, X509);
    OSSL_FREE(chain, sk_X509);
    OSSL_FREE(store_ctx, X509_STORE_CTX);
    OSSL_FREE(store, X509_STORE);
    OSSL_FREE(bio, BIO);
    free_cert_list(cert_list);
    free_cert_list(root_certs);
    if (crls) {
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
    }

    return r;
}
