/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef ESYS_IUTIL_H
#define ESYS_IUTIL_H

#include <stdbool.h>
#include <inttypes.h>
#include <string.h>

#include "tss2_esys.h"

#include "esys_int.h"
#include "esys_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SAFE_FREE(S) if((S) != NULL) {free((void*) (S)); (S)=NULL;}

#define TPM2_ERROR_FORMAT "%s%s (0x%08x)"
#define TPM2_ERROR_TEXT(r) "Error", "Code", r

#define return_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }

#define return_state_if_error(r,s,msg)      \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        esysContext->state = s; \
        return r;  \
    }

#define return_error(r,msg) \
    { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }

#define goto_state_if_error(r,s,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        esysContext->state = s; \
        goto label;  \
    }

#define goto_if_null(p,msg,ec,label) \
    if ((p) == NULL) { \
        LOG_ERROR("%s ", (msg)); \
        r = (ec); \
        goto label;  \
    }

#define goto_if_error(r,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        goto label;  \
    }

#define goto_error(r,v,msg,label) \
    { r = v;  \
      LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
      goto label; \
    }

#define return_if_null(p,msg,ec) \
    if (p == NULL) { \
        LOG_ERROR("%s ", msg); \
        return ec; \
    }

#define return_if_notnull(p,msg,ec) \
    if (p != NULL) { \
        LOG_ERROR("%s ", msg); \
        return ec; \
    }

#define exit_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        exit(1);  \
    }

#define set_return_code(r_max, r, msg) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        r_max = r; \
    }

/** An entry in a cpHash or rpHash table. */
typedef struct {
    TPM2_ALG_ID alg;                 /**< The hash algorithm. */
    size_t size;                     /**< The digest size. */
    uint8_t digest[sizeof(TPMU_HA)]; /**< The digest. */
} HASH_TAB_ITEM;

bool cmp_UINT16 (const UINT16 *in1, const UINT16 *in2);
bool cmp_BYTE (const BYTE *in1, const BYTE *in2);
bool cmp_BYTE_array(const BYTE *in1, size_t count1, const BYTE *in2, size_t count2);
bool cmp_TPM2B_DIGEST (const TPM2B_DIGEST *in1, const TPM2B_DIGEST *in2);
bool cmp_TPM2B_NAME (const TPM2B_NAME *in1, const TPM2B_NAME *in2);
bool cmp_TPM2B_AUTH (const TPM2B_AUTH *in1, const TPM2B_AUTH *in2);

TSS2_RC init_session_tab(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3);

void iesys_DeleteAllResourceObjects(
    ESYS_CONTEXT *esys_context);

TSS2_RC iesys_compute_encrypt_nonce(
    ESYS_CONTEXT *esysContext,
    int *encryptNonceIdx,
    TPM2B_NONCE **encryptNonce);

TSS2_RC iesys_compute_cp_hashtab(
    ESYS_CONTEXT *esysContext,
    const TPM2B_NAME *name1,
    const TPM2B_NAME *name2,
    const TPM2B_NAME *name3,
    HASH_TAB_ITEM cp_hash_tab[3],
    uint8_t *cpHashNum);

TSS2_RC iesys_compute_rp_hashtab(
    ESYS_CONTEXT *esysContext,
    const uint8_t *rpBuffer,
    size_t rpBuffer_size,
    HASH_TAB_ITEM rp_hash_tab[3],
    uint8_t *rpHashNum);

TSS2_RC esys_CreateResourceObject(
    ESYS_CONTEXT *esys_context,
    ESYS_TR esys_handle,
    RSRC_NODE_T **node);

TSS2_RC iesys_handle_to_tpm_handle(
    ESYS_TR esys_handle,
    TPM2_HANDLE *tpm_handle);

TSS2_RC esys_GetResourceObject(
    ESYS_CONTEXT *esys_context,
    ESYS_TR rsrc_handle,
    RSRC_NODE_T **node);

TPM2_HT iesys_get_handle_type(
    TPM2_HANDLE handle);

TSS2_RC iesys_finalize(ESYS_CONTEXT *context);

bool iesys_compare_name(
    TPM2B_PUBLIC *publicInfo,
    TPM2B_NAME *name);

TSS2_RC iesys_compute_encrypted_salt(
    ESYS_CONTEXT *esysContext,
    RSRC_NODE_T *tpmKeyNode,
    TPM2B_ENCRYPTED_SECRET *encryptedSalt);

TSS2_RC iesys_gen_caller_nonces(
    ESYS_CONTEXT *esysContext);

TSS2_RC iesys_encrypt_param(
    ESYS_CONTEXT *esysContext,
    TPM2B_NONCE **decryptNonce,
    int *decryptNonceIdx);

TSS2_RC iesys_decrypt_param(
    ESYS_CONTEXT *esysContext,
    const uint8_t *rpBuffer,
    size_t rpBuffer_size);

TSS2_RC iesys_check_rp_hmacs(
    ESYS_CONTEXT *esysContext,
    TSS2L_SYS_AUTH_RESPONSE *rspAuths,
    HASH_TAB_ITEM rp_hash_tab[3],
    uint8_t rpHashNum);

void iesys_compute_bound_entity(
    const TPM2B_NAME *name,
    const TPM2B_AUTH *auth,
    TPM2B_NAME *bound_entity);

bool iesys_is_object_bound(
    const TPM2B_NAME * name,
    const TPM2B_AUTH * auth,
    RSRC_NODE_T * session);

TSS2_RC iesys_check_sequence_async(
    ESYS_CONTEXT *esysContext);

TSS2_RC check_session_feasibility(
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    int mandatory);

void iesys_compute_session_value(
    RSRC_NODE_T *session,
    const TPM2B_NAME *name,
    const TPM2B_AUTH *auth_value);

TSS2_RC iesys_compute_hmac(
    RSRC_NODE_T *session,
    HASH_TAB_ITEM cp_hash_tab[3],
    uint8_t cpHashNum,
    TPM2B_NONCE *decryptNonce,
    TPM2B_NONCE *encryptNonce,
    TPMS_AUTH_COMMAND *auth);

TSS2_RC iesys_gen_auths(
    ESYS_CONTEXT *esysContext,
    RSRC_NODE_T *h1,
    RSRC_NODE_T *h2,
    RSRC_NODE_T *h3,
    TSS2L_SYS_AUTH_COMMAND *auths);

TSS2_RC iesys_check_response(
    ESYS_CONTEXT * esys_context);

TSS2_RC iesys_nv_get_name(
    TPM2B_NV_PUBLIC *publicInfo,
    TPM2B_NAME *name);

TSS2_RC iesys_get_name(
    TPM2B_PUBLIC *publicInfo,
    TPM2B_NAME *name);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ESYS_IUTIL_H */
