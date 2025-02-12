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

/* Function to find a certificate node by subject from issuer. */
static NODE_OBJECT_T
*find_cert_by_issuer(NODE_OBJECT_T *head, X509_NAME *issuer) {
    NODE_OBJECT_T *current = head;
    while (current) {
        if (X509_NAME_cmp(X509_get_subject_name(current->object), issuer) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static TSS2_RC
construct_cert_chain(NODE_OBJECT_T *cert_list, X509 *ek_cert, STACK_OF(X509) *chain,
                     X509_STORE *store) {
    TSS2_RC r;
    NODE_OBJECT_T *current = NULL;
    X509_CRL *ek_crl = NULL;
    X509_CRL *crl = NULL;

    /* Add crl for EK to store */
    r = ifapi_get_crl_from_cert(ek_cert, &ek_crl);
    return_if_error(r, "Get crl for EK certificate.");

    if (ek_crl) {
        /* Set the flags of the store to use CRLs. */
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        if (1 != X509_STORE_add_crl(store, ek_crl)) {
            return_error(TSS2_FAPI_RC_GENERAL_FAILURE,
                         "Failed to add EK certificate crl.");
        }
    }

    /* Create chain of intermediate certificates from EK certificate. */
    current = find_cert_by_issuer(cert_list, X509_get_issuer_name(ek_cert));
    return_if_null(current, "No intermediate certificate found for EK",
                   TSS2_FAPI_RC_GENERAL_FAILURE);

    while(current) {
        /* Add crl for intermediate certificate. */
        r = ifapi_get_crl_from_cert(current->object, &crl);
        return_if_error(r, "Get crl for intermediate certificate.");

        if (crl) {
            /* Set the flags of the store to use CRLs. */
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            if (1 != X509_STORE_add_crl(store, crl)) {
                return_error(TSS2_FAPI_RC_GENERAL_FAILURE,
                           "Failed to add intermediate crl.");
            }
        }
        sk_X509_push(chain, current->object);
        current = find_cert_by_issuer(cert_list, X509_get_issuer_name(current->object));
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
ifapi_verify_cert_chain(char* ek_pem, uint8_t *cert_buf, size_t cert_buf_size) {
    TSS2_RC r;
    const uint8_t *current_pos = cert_buf;
    size_t remaining_length = cert_buf_size;
    NODE_OBJECT_T *cert_list = NULL;
    X509 *ek_cert = NULL;
    BIO *bio = NULL;
    STACK_OF(X509) *chain = NULL;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *store_ctx = NULL;
    X509 *root_cert = NULL;
    X509_STORE_CTX_new();

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
    BIO_free(bio);
    chain = sk_X509_new_null();
    goto_if_null(chain, "Out of memory", TSS2_FAPI_RC_MEMORY, error);

    store = X509_STORE_new();
    goto_if_null(store, "Out of memory", TSS2_FAPI_RC_MEMORY, error);

    /* Add intermediate certificates to chain and crls to store. */
    r = construct_cert_chain(cert_list, ek_cert, chain, store);
    goto_if_error(r, "Failed to construct cert chain.", error);

    /* Add stored root certificates */
    for (uint i = 0; i < sizeof(root_cert_list) / sizeof(char *); i++) {
         root_cert = get_X509_from_pem(root_cert_list[i]);
         goto_if_null(root_cert, "Failed to convert PEM certificate to DER.",
                      TSS2_FAPI_RC_BAD_VALUE, error);
         if (1 != X509_STORE_add_cert(store, root_cert)) {
             goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                        "Failed to add root certificate", error);
        }
        OSSL_FREE(root_cert, X509);
    }

    /* Verify the certificate chain. */
    store_ctx = X509_STORE_CTX_new();
    goto_if_null(store_ctx, "Out of memory", TSS2_FAPI_RC_MEMORY, error);

    if (X509_STORE_CTX_init(store_ctx, store, ek_cert, chain) != 1) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to init X509 store", error);
    } else if  (X509_verify_cert(store_ctx) == 1) {
        /* Verification of EK was successful. */
        OSSL_FREE(chain, sk_X509);
        OSSL_FREE(store_ctx, X509_STORE_CTX);
        OSSL_FREE(store, X509_STORE);
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("EK verification failed");
    r =  TSS2_FAPI_RC_GENERAL_FAILURE;

 error:
    OSSL_FREE(chain, sk_X509);
    OSSL_FREE(store_ctx, X509_STORE_CTX);
    OSSL_FREE(store, X509_STORE);
    OSSL_FREE(bio, BIO);
    ifapi_free_node_list(cert_list);
    return r;
}
