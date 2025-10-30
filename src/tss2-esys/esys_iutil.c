/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>     // for uint8_t, PRIx32, PRIx8, PRIx16
#include <stdlib.h>       // for calloc

#include "esys_crypto.h"  // for iesys_crypto_hash_get_digest_size, iesys_cr...
#include "esys_int.h"     // for RSRC_NODE_T, ESYS_CONTEXT, _ESYS_STATE_INIT
#include "esys_iutil.h"
#include "esys_mu.h"      // for FALSE
#include "esys_types.h"   // for IESYS_SESSION, IESYS_RESOURCE, IESYS_RSRC_U...
#include "tss2_esys.h"    // for ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE, ESYS_C...
#include "tss2_mu.h"      // for Tss2_MU_TPMI_ALG_HASH_Marshal, Tss2_MU_TPM2...

#define LOGMODULE esys
#include "util/log.h"     // for return_if_error, LOG_ERROR, LOG_TRACE, goto...

/**
 * Compare variables of type UINT16.
 * @param[in] in1 Variable to be compared with:
 * @param[in] in2
 */
static bool
cmp_UINT16(const UINT16 * in1, const UINT16 * in2)
{
    LOG_TRACE("call");
    if (*in1 == *in2)
        return true;
    else {
        LOG_TRACE("cmp false");
        return false;
    }
}

/**
 * Compare two arrays of type BYTE.
 * @param[in] in1 array to be compared with:.
 * @param[in] in2
 */

static bool
cmp_BYTE_array(const BYTE * in1, size_t count1, const BYTE * in2, size_t count2)
{
    if (count1 != count2) {
        LOG_TRACE("cmp false");
        return false;
    }

    if (memcmp(in1, in2, count2) != 0) {
        LOG_TRACE("cmp false");
        return false;
    }

    return true;
}

/**
 * Compare two variables of type TPM2B_DIGEST.
 * @param[in] in1 variable to be compared with:
 * @param[in] in2
 */
static bool
cmp_TPM2B_DIGEST(const TPM2B_DIGEST * in1, const TPM2B_DIGEST * in2)
{
    LOG_TRACE("call");

    if (!cmp_UINT16(&in1->size, &in2->size)) {
        LOG_TRACE("cmp false");
        return false;
    }

    return cmp_BYTE_array((BYTE *) & in1->buffer, in1->size,
                          (BYTE *) & in2->buffer, in2->size);
}

/**
 * Compare two variables of type TPM2B_NAME.
 * @param[in] in1 variable to be compared with:
 * @param[in] in2
 */
static bool
cmp_TPM2B_NAME(const TPM2B_NAME * in1, const TPM2B_NAME * in2)
{
    LOG_TRACE("call");

    if (!cmp_UINT16(&in1->size, &in2->size)) {
        LOG_TRACE("cmp false");
        return false;
    }

    return cmp_BYTE_array((BYTE *) & in1->name, in1->size, (BYTE *) & in2->name,
                          in2->size);
}

/**
 * Compare two structures of type TPM2B_AUTH.
 * @param[in] in1 Structure to be compared with:
 * @param[in] in1
 */
static bool
cmp_TPM2B_AUTH(const TPM2B_AUTH * in1, const TPM2B_AUTH * in2)
{
    LOG_TRACE("call");
    return cmp_TPM2B_DIGEST(in1, in2);
}

TSS2_RC
init_session_tab(ESYS_CONTEXT *esys_context,
                 ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3)
{
    TSS2_RC r = TPM2_RC_SUCCESS;
    ESYS_TR handle_tab[3] = { shandle1, shandle2, shandle3 };
    for (int i = 0; i < 3; i++) {
        esys_context->session_type[i] = handle_tab[i];
        if (handle_tab[i] == ESYS_TR_NONE || handle_tab[i] == ESYS_TR_PASSWORD) {
            esys_context->session_tab[i] = NULL;
        } else {
            r = esys_GetResourceObject(esys_context, handle_tab[i],
                                       &esys_context->session_tab[i]);
            return_if_error(r, "Unknown resource.");

            if (esys_context->session_tab[i]->rsrc.rsrcType != IESYSC_SESSION_RSRC) {
                LOG_ERROR("Error: ESYS_TR is not a session resource.");
                return TSS2_ESYS_RC_BAD_TR;
            }
        }

    }
    return r;
}

/** Delete all resource objects stored in the esys context.
 *
 * All resource objects stored in a linked list of the esys context are deleted.
 * @param[in,out] esys_context The ESYS_CONTEXT
 */
void
iesys_DeleteAllResourceObjects(ESYS_CONTEXT * esys_context)
{
    RSRC_NODE_T *node_rsrc;
    RSRC_NODE_T *next_node_rsrc;
    for (node_rsrc = esys_context->rsrc_list; node_rsrc != NULL;
         node_rsrc = next_node_rsrc) {
        next_node_rsrc = node_rsrc->next;
        free(node_rsrc);
    }
    esys_context->rsrc_list = NULL;
}
/**  Compute the TPM nonce of the session used for parameter encryption.
 *
 * Since only encryption session can be used an error is signaled if
 * more encryption sessions are used.
 * @param[in] esys_context The ESYS_CONTEXT
 * @param[out] encryptNonceIndex The number of the session used for encryption.
 * @param[out] encryptNonce The nonce used for encryption by TPM.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS if more than one encrypt
 *         session is used.
 */
TSS2_RC
iesys_compute_encrypt_nonce(ESYS_CONTEXT * esys_context,
                            int *encryptNonceIdx, TPM2B_NONCE ** encryptNonce)
{
    for (int i = 0; i < 3; i++) {
        RSRC_NODE_T *session = esys_context->session_tab[i];
        if (session != NULL) {
            if (session->rsrc.misc.rsrc_session.
                sessionAttributes & TPMA_SESSION_ENCRYPT) {
                if (*encryptNonce != NULL) {
                    /* Encrypt nonce already found */
                    return_error(TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS,
                                 "More than one encrypt session");
                }
                *encryptNonceIdx = i;
                *encryptNonce = &session->rsrc.misc.rsrc_session.nonceTPM;
            }
        }
    }
    return TSS2_RC_SUCCESS;
}

/** Create an esys resource object corresponding to a TPM object.
 *
 * The esys object is appended to the resource list stored in the esys context
 * (rsrc_list).
 * @param[in] esys_context The ESYS_CONTEXT
 * @param[in] esys_handle The esys handle which will be used for this object.
 * @param[out] esys_object The new resource object.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY if the object can not be allocated.
 */
TSS2_RC
esys_CreateResourceObject(ESYS_CONTEXT * esys_context,
                          ESYS_TR esys_handle, RSRC_NODE_T ** esys_object)
{
    RSRC_NODE_T *new_esys_object = calloc(1, sizeof(RSRC_NODE_T));
    if (new_esys_object == NULL)
        return_error(TSS2_ESYS_RC_MEMORY, "Out of memory.");
    if (esys_context->rsrc_list == NULL) {
        /* The first object of the list will be added */
        esys_context->rsrc_list = new_esys_object;
        new_esys_object->next = NULL;
    } else {
        /* The new object will become the first element of the list */
        new_esys_object->next = esys_context->rsrc_list;
        esys_context->rsrc_list = new_esys_object;
    }
    *esys_object = new_esys_object;
    new_esys_object->esys_handle = esys_handle;
    return TSS2_RC_SUCCESS;
}

/** Compute tpm handle for standard esys handles.
 *
 * The tpm handle ist computed for esys handles representing pcr registers and
 * hierarchies.
 * @parm esys_handle [in] The esys handle.
 * @parm tpm_handle [out] The corresponding tpm handle.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE if no standard handle is passed.
 */
TSS2_RC
iesys_handle_to_tpm_handle(ESYS_TR esys_handle, TPM2_HANDLE * tpm_handle)
{
    /* Since ESYS_TR_PCR0 is equal zero only <= ESYS_TR_PCR31 has to be checked */
    if (esys_handle <= ESYS_TR_PCR31) {
        *tpm_handle = (TPM2_HANDLE) esys_handle;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_OWNER) {
        *tpm_handle = TPM2_RH_OWNER;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_NULL) {
        *tpm_handle = TPM2_RH_NULL;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_LOCKOUT) {
        *tpm_handle = TPM2_RH_LOCKOUT;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_ENDORSEMENT) {
        *tpm_handle = TPM2_RH_ENDORSEMENT;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_PLATFORM) {
        *tpm_handle = TPM2_RH_PLATFORM;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_PLATFORM_NV) {
        *tpm_handle = TPM2_RH_PLATFORM_NV;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_FW_OWNER) {
        *tpm_handle = TPM2_RH_FW_OWNER;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_FW_ENDORSEMENT) {
        *tpm_handle = TPM2_RH_FW_ENDORSEMENT;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_FW_PLATFORM) {
        *tpm_handle = TPM2_RH_FW_PLATFORM;
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle == ESYS_TR_RH_FW_NULL) {
        *tpm_handle = TPM2_RH_FW_NULL;
        return TPM2_RC_SUCCESS;
    }
    if ((esys_handle & 0xFFFF0000) == ESYS_TR_RH_SVN_OWNER_BASE) {
        *tpm_handle = TPM2_RH_SVN_OWNER_BASE + (esys_handle & 0x0000FFFF);
        return TPM2_RC_SUCCESS;
    }
    if ((esys_handle & 0xFFFF0000) == ESYS_TR_RH_SVN_ENDORSEMENT_BASE) {
        *tpm_handle = TPM2_RH_SVN_ENDORSEMENT_BASE + (esys_handle & 0x0000FFFF);
        return TPM2_RC_SUCCESS;
    }
    if ((esys_handle & 0xFFFF0000) == ESYS_TR_RH_SVN_PLATFORM_BASE) {
        *tpm_handle = TPM2_RH_SVN_PLATFORM_BASE + (esys_handle & 0x0000FFFF);
        return TPM2_RC_SUCCESS;
    }
    if ((esys_handle & 0xFFFF0000) == ESYS_TR_RH_SVN_NULL_BASE) {
        *tpm_handle = TPM2_RH_SVN_NULL_BASE + (esys_handle & 0x0000FFFF);
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle >= ESYS_TR_RH_ACT_FIRST &&
        esys_handle <= ESYS_TR_RH_ACT_LAST) {
        *tpm_handle = TPM2_RH_ACT_0 + (esys_handle - ESYS_TR_RH_ACT_FIRST);
        return TPM2_RC_SUCCESS;
    }
    if (esys_handle >= ESYS_TR_RH_AC_FIRST &&
        esys_handle <= ESYS_TR_RH_AC_LAST) {
        *tpm_handle = TPM2_NV_AC_FIRST + (esys_handle - ESYS_TR_RH_AC_FIRST);
        return TPM2_RC_SUCCESS;
    }
    LOG_ERROR("Error: Esys invalid ESAPI handle (%"PRIx32").", esys_handle);
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Determines if an ESYS_TR (UINT32) is assigned a raw TPM2_HANDLE (UINT32)
 * hierarchy type.
 *
 * @param handle [in] The handle to check if it's a hierarchy or not.
 * @return
 *  true if it is a hierarchy, false otherwise.
 */
bool
iesys_is_platform_handle(ESYS_TR handle) {

    switch(handle) {
    case TPM2_RH_OWNER:
    case TPM2_RH_PLATFORM:
    case TPM2_RH_PLATFORM_NV:
    case TPM2_RH_ENDORSEMENT:
    case TPM2_RH_NULL:
        LOG_WARNING("Convert handle from TPM2_RH to ESYS_TR, got: 0x%"PRIx32,
                handle);
        return true;
    default:
        return false;
    }
}

/** Get the type of a tpm handle.
 *
 * @parm handle[in] The tpm handle.
 * @retval The part of the handle which represents the handle type.
 */
TPM2_HT
iesys_get_handle_type(TPM2_HANDLE handle)
{
    /* upper bytes of input data */
    TPM2_HT ht = (TPM2_HT) ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT);
    return ht;
}

/** Compute name derived from public info with a tpm name.
 *
 * A tpm name is computed from a public info structure and compared with a
 * second tpm name.
 * @param[in]  publicInfo The public info for name computation.
 * @param[in] name The name used for comparison.
 * @retval bool indicates whether the names are equal.
 */
bool
iesys_compare_name(ESYS_CRYPTO_CALLBACKS *crypto_cb, TPM2B_PUBLIC * publicInfo, TPM2B_NAME * name)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    TPM2B_NAME public_info_name;
    if (publicInfo == NULL || name == NULL)
        return false;
    r = iesys_get_name(crypto_cb, publicInfo, &public_info_name);
    if (r != TSS2_RC_SUCCESS) {
        LOG_DEBUG("name could not be computed.");
        return false;
    }
    return cmp_TPM2B_NAME(&public_info_name, name);
}

/** Compute a random salt which will be used for parameter encryption.
 *
 * Depending in the type of TPM key used for key exchange a salt will be computed.
 * For an ECC key an ephemeral key will be computed. This key together with the
 * public point of the TPMs key will be used to compute a shared secret which will
 * be used for the key derivation of the key for parameter encryption.
 * For an RSA key a random number will be computed to derive this key. The random
 * number will be encrypted with the TPM key.
 * @param[in,out]  esys_context The ESYS_CONTEXT. The generated salt will be
 *                 stored in this context.
 * @param[in] tpmKeyNode The esys resource object of the TPM key which will be
 *            used for key exchange.
 * @param[out] encryptedSalt In the case of an ECC the public point of the
 *             ephemeral key will be marshaled into this buffer.
 *             In the case of a TPM key the encrypted salt will be stored.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_compute_encrypted_salt(ESYS_CONTEXT * esys_context,
                             RSRC_NODE_T * tpmKeyNode,
                             TPM2B_ENCRYPTED_SECRET * encryptedSalt)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t keyHash_size = 0;
    size_t cSize = 0;
    TPM2B_ECC_PARAMETER Z; /* X coordinate of privKey*publicKey */
    TPMS_ECC_POINT Q; /* Public point of ephemeral key */

    if (tpmKeyNode == 0) {
        encryptedSalt->size = 0;
        return TSS2_RC_SUCCESS;
    }

    TPM2B_PUBLIC pub = tpmKeyNode->rsrc.misc.rsrc_key_pub;
    if (tpmKeyNode->rsrc.rsrcType != IESYSC_KEY_RSRC) {
        LOG_TRACE("Public info needed.");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    r = iesys_crypto_hash_get_digest_size(tpmKeyNode->rsrc.misc.
                                          rsrc_key_pub.publicArea.nameAlg,
                                          &keyHash_size);
    return_if_error(r, "Hash algorithm not supported.");

    switch (pub.publicArea.type) {
    case TPM2_ALG_RSA:

        r = iesys_crypto_get_random2b(&esys_context->crypto_backend,
                (TPM2B_NONCE *) & esys_context->salt,
                keyHash_size);
        return_if_error(r, "During getrandom.");

        /* When encrypting salts, the encryption scheme of a key is ignored and
           TPM2_ALG_OAEP is always used. */
        pub.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_OAEP;
        r = iesys_crypto_rsa_pk_encrypt(&esys_context->crypto_backend, &pub,
                                    keyHash_size, &esys_context->salt.buffer[0],
                                    sizeof(TPMU_ENCRYPTED_SECRET),
                                    (BYTE *) &encryptedSalt->secret[0], &cSize,
                                    "SECRET");
        return_if_error(r, "During encryption.");
        LOGBLOB_DEBUG(&encryptedSalt->secret[0], cSize, "IESYS encrypted salt");
        encryptedSalt->size = cSize;
        break;
    case TPM2_ALG_ECC:
        r = iesys_crypto_get_ecdh_point(&esys_context->crypto_backend,
                &pub, sizeof(TPMU_ENCRYPTED_SECRET),
                &Z, &Q,
                (BYTE *) &encryptedSalt->secret[0],
                &cSize);
        return_if_error(r, "During computation of ECC public key.");
        encryptedSalt->size = cSize;

        /* Compute salt from Z with KDFe */
        r = iesys_crypto_KDFe(&esys_context->crypto_backend, tpmKeyNode->rsrc.misc.
                              rsrc_key_pub.publicArea.nameAlg,
                              &Z, "SECRET", &Q.x,
                              &pub.publicArea.unique.ecc.x,
                              keyHash_size*8,
                              &esys_context->salt.buffer[0]);
        return_if_error(r, "During KDFe computation.");
        esys_context->salt.size = keyHash_size;
        break;
    default:
        LOG_ERROR("Not implemented");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
        break;
    }
    return r;
}

/** Generate caller nonces for all sessions.
 *
 * For every uses session stored in context random nonce is computed.
 * @param[in,out]  esys_context The ESYS_CONTEXT. The generated nonces will be
 *                 stored in this context.
 * @retval TPM2_RC_SUCCESS on success. An possible error is:
 * @retval TSS2_ESYS_RC_BAD_VALUE if an illegal hash algorithm value is stored
 *         in a session.
 */
TSS2_RC
iesys_gen_caller_nonces(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    for (int i = 0; i < 3; i++) {
        RSRC_NODE_T *session = esys_context->session_tab[i];
        if (session == NULL)
            continue;

        r = iesys_crypto_get_random2b(&esys_context->crypto_backend,
                &session->rsrc.misc.rsrc_session.nonceCaller,
                session->rsrc.misc.rsrc_session.nonceCaller.size);
        return_if_error(r, "Error: computing caller nonce.");
    }
    return TSS2_RC_SUCCESS;
}

/** Update session attributes.
 *
 * In case where command does not support param encryption/decryption
 * store the original session attributes and update them accordingly.
 *
 * @retval void
 */
static void
iesys_update_session_flags(ESYS_CONTEXT * esys_context,
                           IESYS_SESSION *rsrc_session)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t param_size;
    const uint8_t *param_buffer;

    LOG_DEBUG("Checking if command supports enc/dec");

    rsrc_session->origSessionAttributes = rsrc_session->sessionAttributes;

    r = Tss2_Sys_GetDecryptParam(esys_context->sys,
                                 &param_size, &param_buffer);
    if (r == TSS2_SYS_RC_NO_DECRYPT_PARAM) {
        LOG_DEBUG("clear TPMA_SESSION_DECRYPT flag");
        rsrc_session->sessionAttributes &= ~(TPMA_SESSION_DECRYPT);
    }

    r = Tss2_Sys_GetEncryptParam(esys_context->sys,
                                 &param_size, &param_buffer);
    if (r == TSS2_SYS_RC_NO_ENCRYPT_PARAM) {
        LOG_DEBUG("clear TPMA_SESSION_ENCRYPT flag");
        rsrc_session->sessionAttributes &= ~(TPMA_SESSION_ENCRYPT);
    }

    LOG_DEBUG("Session Attrs 0x%"PRIx32" orig 0x%"PRIx32,
	      rsrc_session->sessionAttributes,
	      rsrc_session->origSessionAttributes);
}

/** Restore session attributes.
 *
 * Restore original session attributes altered by iesys_update_session_flags()
 *
 * @retval void
 */
static void
iesys_restore_session_flags(ESYS_CONTEXT *esys_context)
{
    LOG_DEBUG("Restoring session attribs");

    for (int i = 0; i < 3; i++) {
        RSRC_NODE_T *session = esys_context->session_tab[i];
        if (session == NULL)
            continue;
        IESYS_SESSION *rsrc_session = &session->rsrc.misc.rsrc_session;
        LOG_DEBUG("Orig Session %i Attrs 0x%"PRIx8", altered Attrs x%"PRIx8, i,
                  rsrc_session->origSessionAttributes,
                  rsrc_session->sessionAttributes);

        rsrc_session->sessionAttributes = rsrc_session->origSessionAttributes;
    }
}

/** Parameter encryption with AES or XOR obfuscation.
 *
 * One parameter of a TPM command will be encrypted with the selected method.
 * The buffer to encrypted is determined with the SAPI function:
 * Tss2_Sys_GetCpBuffer. If more than one encryption session es used an error
 * will be returned. The decryption nonce of the session used for encryption
 * will be returned and used for HMAC computation. The encryption key is
 * derived with KDFa.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_encrypt_param(ESYS_CONTEXT * esys_context,
                    TPM2B_NONCE ** decryptNonce, int *decryptNonceIdx)
{
    TPM2B_NONCE *encryptNonce = NULL;
    *decryptNonceIdx = 0;
    *decryptNonce = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;
    esys_context->enc_session = NULL;

    for (int i = 0; i < 3; i++) {
        RSRC_NODE_T *session = esys_context->session_tab[i];
        if (session == NULL)
            continue;
        IESYS_SESSION *rsrc_session = &session->rsrc.misc.rsrc_session;
        if (rsrc_session->sessionAttributes & TPMA_SESSION_ENCRYPT)
            return_if_notnull(encryptNonce, "More than one encrypt session",
                               TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS);
        if (rsrc_session->sessionAttributes & TPMA_SESSION_DECRYPT)
            return_if_notnull(*decryptNonce, "More than one decrypt session",
                               TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS);

        iesys_update_session_flags(esys_context, rsrc_session);
    }

    for (int i = 0; i < 3; i++) {
        RSRC_NODE_T *session = esys_context->session_tab[i];
        if (session == NULL)
            continue;
        IESYS_SESSION *rsrc_session = &session->rsrc.misc.rsrc_session;
        TPMT_SYM_DEF *symDef = &rsrc_session->symmetric;

        if (rsrc_session->sessionAttributes & TPMA_SESSION_ENCRYPT) {
            esys_context->encryptNonceIdx = i;
            encryptNonce = &rsrc_session->nonceTPM;
            esys_context->encryptNonce = encryptNonce;
            esys_context->enc_session = rsrc_session;
        }

        /* Session for encryption found */
        if (rsrc_session->sessionAttributes & TPMA_SESSION_DECRYPT) {
            *decryptNonceIdx = i;
            *decryptNonce = &rsrc_session->nonceTPM;
            size_t hlen;
            r = iesys_crypto_hash_get_digest_size(rsrc_session->authHash, &hlen);
            return_if_error(r, "get digest size");
            size_t key_len = TPM2_MAX_SYM_KEY_BYTES + TPM2_MAX_SYM_BLOCK_SIZE;
            if (key_len % hlen > 0)
                key_len = key_len + hlen - (key_len % hlen);
            uint8_t symKey[key_len];
            size_t paramSize = 0;
            const uint8_t *paramBuffer;

            r = Tss2_Sys_GetDecryptParam(esys_context->sys, &paramSize,
                                         &paramBuffer);
            return_if_error(r, "Encryption not possible");

            if (paramSize == 0)
                continue;

            BYTE encrypt_buffer[paramSize];
            memcpy(&encrypt_buffer[0], paramBuffer, paramSize);
            LOGBLOB_DEBUG(paramBuffer, paramSize, "param to encrypt");

            /* AES encryption with key derived with KDFa */
            if (symDef->algorithm == TPM2_ALG_AES) {
                if (symDef->mode.aes != TPM2_ALG_CFB) {
                    return_error(TSS2_ESYS_RC_BAD_VALUE,
                                 "Invalid symmetric mode (must be CFB)");
                }
                r = iesys_crypto_KDFa(&esys_context->crypto_backend, rsrc_session->authHash,
                                      &rsrc_session->sessionValue[0],
                                      rsrc_session->sizeSessionValue, "CFB",
                                      &rsrc_session->nonceCaller,
                                      &rsrc_session->nonceTPM,
                                      symDef->keyBits.aes + AES_BLOCK_SIZE_IN_BYTES * 8,
                                      NULL, &symKey[0], FALSE);
                return_if_error(r, "while computing KDFa");

                size_t aes_off = ( symDef->keyBits.aes + 7) / 8;
                r = iesys_crypto_aes_encrypt(
                        &esys_context->crypto_backend,
                        &symKey[0],
                        symDef->algorithm,
                        symDef->keyBits.aes,
                        symDef->mode.aes,
                        &encrypt_buffer[0], paramSize,
                        &symKey[aes_off]);
                return_if_error(r, "AES encryption not possible");
            } else if (symDef->algorithm == TPM2_ALG_SM4) {
                /* SM4 encryption with key derived with KDFa */
                if (symDef->mode.sm4 != TPM2_ALG_CFB) {
                    return_error(TSS2_ESYS_RC_BAD_VALUE,
                                 "Invalid symmetric mode (must be CFB)");
                }
                r = iesys_crypto_KDFa(&esys_context->crypto_backend, rsrc_session->authHash,
                                      &rsrc_session->sessionValue[0],
                                      rsrc_session->sizeSessionValue, "CFB",
                                      &rsrc_session->nonceCaller,
                                      &rsrc_session->nonceTPM,
                                      symDef->keyBits.sm4 + SM4_BLOCK_SIZE_IN_BYTES * 8,
                                      NULL, &symKey[0], FALSE);
                return_if_error(r, "while computing KDFa");

                size_t sm4_off = ( symDef->keyBits.sm4 + 7) / 8;
                r = iesys_crypto_sm4_encrypt(
                        &esys_context->crypto_backend,
                        &symKey[0],
                        symDef->algorithm,
                        symDef->keyBits.sm4,
                        symDef->mode.sm4,
                        &encrypt_buffer[0], paramSize,
                        &symKey[sm4_off]);
                return_if_error(r, "SM4 encryption not possible");
            }
            /* XOR obfuscation of parameter */
            else if (symDef->algorithm == TPM2_ALG_XOR) {
                r = iesys_xor_parameter_obfuscation(&esys_context->crypto_backend,
                                                    rsrc_session->authHash,
                                                    &rsrc_session->sessionValue[0],
                                                    rsrc_session->sizeSessionValue,
                                                    &rsrc_session->nonceCaller,
                                                    &rsrc_session->nonceTPM,
                                                    &encrypt_buffer[0],
                                                    paramSize);
                return_if_error(r, "XOR obfuscation not possible.");

            } else {
                return_error(TSS2_ESYS_RC_BAD_VALUE,
                             "Invalid symmetric algorithm (should be XOR, AES, or SM4)");
            }
            r = Tss2_Sys_SetDecryptParam(esys_context->sys, paramSize,
                                         &encrypt_buffer[0]);
            return_if_error(r, "Set encrypt parameter not possible");

        }
    }
    return r;
}

/** Parameter decryption with AES or XOR obfuscation.
 *
 * One parameter of a TPM response will be decrypted with the selected method.
 * @param[in]  esys_context The ESYS_CONTEXT.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED if hash algorithm is not implemented.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_decrypt_param(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    const uint8_t *ciphertext;
    size_t p2BSize;
    size_t hlen;
    RSRC_NODE_T *session;
    IESYS_SESSION *rsrc_session;
    TPMT_SYM_DEF *symDef;
    size_t key_len = TPM2_MAX_SYM_KEY_BYTES + TPM2_MAX_SYM_BLOCK_SIZE;

    session = esys_context->session_tab[esys_context->encryptNonceIdx];
    rsrc_session = &session->rsrc.misc.rsrc_session;
    symDef = &rsrc_session->symmetric;

    r = iesys_crypto_hash_get_digest_size(rsrc_session->authHash, &hlen);
    return_if_error(r, "Error");
    if (key_len % hlen > 0)
        key_len = key_len + hlen - (key_len % hlen);

    uint8_t symKey[key_len];

    r = Tss2_Sys_GetEncryptParam(esys_context->sys, &p2BSize, &ciphertext);
    return_if_error(r, "Getting encrypt param");

    UINT8 plaintext[p2BSize];
    memcpy(&plaintext[0], ciphertext, p2BSize);

    if (symDef->algorithm == TPM2_ALG_AES) {
        /* Parameter decryption with a symmetric AES key derived by KDFa */
        if (symDef->mode.aes != TPM2_ALG_CFB) {
            return_error(TSS2_ESYS_RC_BAD_VALUE,
                         "Invalid symmetric mode (must be CFB)");
        }
        LOGBLOB_DEBUG(&rsrc_session->sessionKey.buffer[0],
                      rsrc_session->sessionKey.size,
                      "IESYS encrypt session key");

        r = iesys_crypto_KDFa(&esys_context->crypto_backend, rsrc_session->authHash,
                              &rsrc_session->sessionValue[0],
                              rsrc_session->sizeSessionValue,
                              "CFB", &rsrc_session->nonceTPM,
                              &rsrc_session->nonceCaller,
                              symDef->keyBits.aes
                              + AES_BLOCK_SIZE_IN_BYTES * 8, NULL,
                              &symKey[0], FALSE);
        return_if_error(r, "KDFa error");
        LOGBLOB_DEBUG(&symKey[0],
                      ((symDef->keyBits.aes +
                        AES_BLOCK_SIZE_IN_BYTES * 8) + 7) / 8,
                      "IESYS encrypt KDFa key");

        size_t aes_off = ( symDef->keyBits.aes + 7) / 8;
        r = iesys_crypto_aes_decrypt(
            &esys_context->crypto_backend,
            &symKey[0],
            symDef->algorithm,
            symDef->keyBits.aes,
            symDef->mode.aes,
            &plaintext[0], p2BSize,
            &symKey[aes_off]);
        return_if_error(r, "Decryption error");

        r = Tss2_Sys_SetEncryptParam(esys_context->sys, p2BSize, &plaintext[0]);
        return_if_error(r, "Setting plaintext");
    } else if (symDef->algorithm == TPM2_ALG_SM4) {
        /* Parameter decryption with a symmetric SM4 key derived by KDFa */
        if (symDef->mode.sm4 != TPM2_ALG_CFB) {
            return_error(TSS2_ESYS_RC_BAD_VALUE,
                         "Invalid symmetric mode (must be CFB)");
        }
        LOGBLOB_DEBUG(&rsrc_session->sessionKey.buffer[0],
                      rsrc_session->sessionKey.size,
                      "IESYS encrypt session key");

        r = iesys_crypto_KDFa(&esys_context->crypto_backend, rsrc_session->authHash,
                              &rsrc_session->sessionValue[0],
                              rsrc_session->sizeSessionValue,
                              "CFB", &rsrc_session->nonceTPM,
                              &rsrc_session->nonceCaller,
                              symDef->keyBits.sm4
                              + SM4_BLOCK_SIZE_IN_BYTES * 8, NULL,
                              &symKey[0], FALSE);
        return_if_error(r, "KDFa error");
        LOGBLOB_DEBUG(&symKey[0],
                      ((symDef->keyBits.sm4 +
                        SM4_BLOCK_SIZE_IN_BYTES * 8) + 7) / 8,
                      "IESYS encrypt KDFa key");

        size_t sm4_off = ( symDef->keyBits.sm4 + 7) / 8;
        r = iesys_crypto_sm4_decrypt(
            &esys_context->crypto_backend,
            &symKey[0],
            symDef->algorithm,
            symDef->keyBits.sm4,
            symDef->mode.sm4,
            &plaintext[0], p2BSize,
            &symKey[sm4_off]);
        return_if_error(r, "Decryption error");

        r = Tss2_Sys_SetEncryptParam(esys_context->sys, p2BSize, &plaintext[0]);
        return_if_error(r, "Setting plaintext");
    } else if (symDef->algorithm == TPM2_ALG_XOR) {
        /* Parameter decryption with XOR obfuscation */
        r = iesys_xor_parameter_obfuscation(&esys_context->crypto_backend,
                                            rsrc_session->authHash,
                                            &rsrc_session->sessionValue[0],
                                            rsrc_session->sizeSessionValue,
                                            &rsrc_session->nonceTPM,
                                            &rsrc_session->nonceCaller,
                                            &plaintext[0],
                                            p2BSize);
        return_if_error(r, "XOR obfuscation not possible.");

        r = Tss2_Sys_SetEncryptParam(esys_context->sys, p2BSize, &plaintext[0]);
        return_if_error(r, "Setting plaintext");
    } else {
        return_error(TSS2_ESYS_RC_BAD_VALUE,
                     "Invalid symmetric algorithm (should be XOR, AES, or SM4)");
    }
    return TSS2_RC_SUCCESS;
}

/** Computation of the command response(cp) hash.
 *
 * The command response(rp) hash of the command is computed for every
 * session.  If the sessions use different hash algorithms then different cp
 * hashes must be calculated.
 * @param[in] esys_context The ESYS_CONTEXT
 * @param[in] hash_alg The hash alg used to compute the cp hash
 * @param[3] [out] rp_hash The rp hash.
 * @param[out] rp_hash_size The size of the computed rp hash.
 * @retval TSS2_RC_SUCCESS on success,
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_compute_rp_hash(ESYS_CONTEXT *esys_context,
                      TPMI_ALG_HASH hash_alg,
                      uint8_t *rp_hash,
                      size_t *rp_hash_size) {
     TSS2_RC r;
     uint8_t rcBuffer[4] = { 0 };
     uint8_t ccBuffer[4];
     const uint8_t *rpBuffer;
     size_t rpBuffer_size;

     r = Tss2_Sys_GetCommandCode(esys_context->sys, &ccBuffer[0]);
     return_if_error(r, "Error: get command code");

     r = Tss2_Sys_GetRpBuffer(esys_context->sys, &rpBuffer_size, &rpBuffer);
     return_if_error(r, "Error: get rp buffer");

     *rp_hash_size =  sizeof(TPMU_HA);
     r = iesys_crypto_rpHash(&esys_context->crypto_backend, hash_alg,
                             rcBuffer, ccBuffer, rpBuffer, rpBuffer_size,
                             &rp_hash[0],
                             rp_hash_size);
     return_if_error(r, "crypto rpHash");

     return TSS2_RC_SUCCESS;
}

/** Check the HMAC values of the response for all sessions.
 *
 * The HMAC values are computed based on the session secrets, the used nonces,
 * the session attributes, the response hash.
 * @param[in] esys_context The ESYS_CONTEXT.
 * @param[in] rspAuths The list of the session auth values.
 * @param[in] rp_hashtab  The list of response hashes.
 * @param[in] rpHashNum The number of response hashes.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED if hash algorithm is not implemented.
 */
TSS2_RC
iesys_check_rp_hmacs(ESYS_CONTEXT * esys_context,
                     TSS2L_SYS_AUTH_RESPONSE * rspAuths)
{
    TSS2_RC r;
    size_t rp_digest_size;
    uint8_t rp_digest[sizeof(TPMU_HA)];

    for (int i = 0; i < rspAuths->count; i++) {
        RSRC_NODE_T *session = esys_context->session_tab[i];
        if (session == NULL)
            continue;

        IESYS_SESSION *rsrc_session = &session->rsrc.misc.rsrc_session;
        if (rsrc_session->type_policy_session == POLICY_PASSWORD) {
            /* A policy password session has no auth value */
            if (rspAuths->auths[i].hmac.size != 0) {
                LOG_ERROR("PolicyPassword session's HMAC must be 0-length.");
                return TSS2_ESYS_RC_RSP_AUTH_FAILED;
            }
            continue;
        }

        rp_digest_size = sizeof(TPMU_HA);
        r = iesys_compute_rp_hash(esys_context,
                                  session->rsrc.misc.rsrc_session.authHash,
                                  &rp_digest[0],
                                  &rp_digest_size);
        return_if_error(r, "crypto rpHash");

        TPM2B_AUTH rp_hmac;
        rp_hmac.size = sizeof(TPMU_HA);
        rsrc_session->nonceTPM = rspAuths->auths[i].nonce;
        rsrc_session->sessionAttributes =
            rspAuths->auths[i].sessionAttributes;
        r = iesys_crypto_authHmac(&esys_context->crypto_backend, rsrc_session->authHash,
                                  &rsrc_session->sessionValue[0],
                                  rsrc_session->sizeHmacValue,
                                  &rp_digest[0],
                                  rp_digest_size,
                                  &rsrc_session->nonceTPM,
                                  &rsrc_session->nonceCaller, NULL, NULL,
                                  rspAuths->auths[i].sessionAttributes,
                                  &rp_hmac);
        return_if_error(r, "HMAC error");

        if (!cmp_TPM2B_AUTH(&rspAuths->auths[i].hmac, &rp_hmac)) {
            LOG_ERROR("TPM's response auth is invalid for session %i", i);
            return TSS2_ESYS_RC_RSP_AUTH_FAILED;
        }
    }
    return TSS2_RC_SUCCESS;
}
/** Compute the value for check of bind authorization.
 *
 * This value has to be computed from the bind object in the StartAuthSession
 * command and later checked in for corresponding object authorizations.
 * @param[in] name The name of the bind object.
 * @param[in] auth The authorization of the bind object.
 * @param[out] bound_entity The value used for checking the bind authorization.
 */
void
iesys_compute_bound_entity(const TPM2B_NAME * name,
                           const TPM2B_AUTH * auth, TPM2B_NAME * bound_entity)
{
    size_t i;
    UINT16 j = 0;
    *bound_entity = *name;
    memset(&bound_entity->name[bound_entity->size], 0,
           sizeof(bound_entity->name) - bound_entity->size);
    for (i = sizeof(bound_entity->name) - auth->size;
         i < sizeof(bound_entity->name); i++)
        bound_entity->name[i] ^= auth->buffer[j++];
    bound_entity->size = sizeof(bound_entity->name);
}

/** Predicate whether the authorization is for the object bound to the session.
 *
 * @param[in] name The name of the object.
 * @param[in] auth The auth value of the object.
 * @param[in] sesssion The session to be checked.
 * @retval true if object is bind object of session.
 * @retval false if not.
 */
bool
iesys_is_object_bound(const TPM2B_NAME * name,
                      const TPM2B_AUTH * auth, RSRC_NODE_T * session)
{
    TPM2B_NAME tmp;
    if (session->rsrc.misc.rsrc_session.bound_entity.size == 0)
        /* No bind session */
        return false;
    iesys_compute_bound_entity(name, auth, &tmp);
    return cmp_TPM2B_NAME(&session->rsrc.misc.rsrc_session.bound_entity, &tmp);
}

/**
 * Compute the session value
 *
 * This function derives the session value from the session key
 * and the auth value. The auth value is appended to the session key.
 * The session value is used for key derivation for parameter encryption and
 * HMAC computation. There is one exception for HMAC key derivation: If the
 * session is bound to an object only the session key is used. The auth value
 * is appended only for the key used for parameter encryption.
 * The auth value is only used if an authorization is necessary and the name
 * of the object is not equal to the name of an used bound entity
 * @param[in,out] session for which the session value will be computed.
 *       The value will be stored in sessionValue of the session object.
 *       The length of the object will be stored in sizeHmacValue and
 *       sizeSessionValue respectively to the purpose of usage (HMAC computation
 *       or parameter encryption).
 * @param[in] name name of the object to be authorized (NULL if no authorization)
 * @param[in] auth_value auth value of the object to be authorized
 *             (NULL if no authorization)
 */
void
iesys_compute_session_value(RSRC_NODE_T * session,
                            const TPM2B_NAME * name,
                            const TPM2B_AUTH * auth_value)
{
    if (session == NULL)
        return;

    /* First the session Key is copied into the sessionValue */
    session->rsrc.misc.rsrc_session.sizeSessionValue
        = session->rsrc.misc.rsrc_session.sessionKey.size;
    memcpy(&session->rsrc.misc.rsrc_session.sessionValue[0],
           &session->rsrc.misc.rsrc_session.sessionKey.buffer[0],
           session->rsrc.misc.rsrc_session.sessionKey.size);

     /* This requires an HMAC Session and not a password session */
    if (session->rsrc.misc.rsrc_session.sessionType != TPM2_SE_HMAC &&
        session->rsrc.misc.rsrc_session.sessionType != TPM2_SE_POLICY)
        return;

    session->rsrc.misc.rsrc_session.sizeHmacValue = session->rsrc.misc.rsrc_session.sizeSessionValue;

    if (name == NULL || auth_value == NULL)
        return;

    /* The auth value is appended to the session key */
    memcpy(&session->rsrc.misc.rsrc_session.
           sessionValue[session->rsrc.misc.rsrc_session.sessionKey.size],
           &auth_value->buffer[0], auth_value->size);
    session->rsrc.misc.rsrc_session.sizeSessionValue += auth_value->size;

    /* Then if we are a bound session, the auth value is not appended to the end
       of the session value for HMAC computation. The size of the key will not be
       increased.*/
    if (iesys_is_object_bound(name, auth_value, session))
        return;

    /* type_policy_session set to POLICY_AUTH by command PolicyAuthValue */
    if (session->rsrc.misc.rsrc_session.sessionType == TPM2_SE_POLICY &&
        session->rsrc.misc.rsrc_session.type_policy_session != POLICY_AUTH)
        return;

    session->rsrc.misc.rsrc_session.sizeHmacValue += auth_value->size;
}

/**
 * Lookup the object to a handle from inside the context.
 *
 * This function searches the esapi context for an object that corresponds to a
 * provided esys_handle. These objects contain information such as the
 * appropriate tpm handle, the public name or the stored auth values.
 * These esys handles refer either to an object previously initialized on the
 * same context, in which case this will be returned. Or they refer to a
 * "global", in which case the corresponding object will be created if it does
 * not exist yet.
 * @param[in,out] esys_context The esys context to issue the command on.
 * @param[in] esys_handle The handle to find the corresponding object for.
 * @param[out] esys_object The object containing the name, tpm handle and auth value
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_TR if the handle is invalid.
 * @retval TSS2_ESYS_RC_BAD_VALUE if an unknown handle < ESYS_TR_MIN_OBJECT is
 *         passed.
 */
TSS2_RC
esys_GetResourceObject(ESYS_CONTEXT * esys_context,
                       ESYS_TR esys_handle, RSRC_NODE_T ** esys_object)
{
    RSRC_NODE_T *esys_object_aux;
    TPM2_HANDLE tpm_handle;
    size_t offset = 0;
    TSS2_RC r;

    /* Sometimes the TPM API allows for optional objects. In those cases we map
       the object node to NULL. This will be handled accordingly by following
       code */
    if (esys_handle == ESYS_TR_NONE) {
        *esys_object = NULL;
        return TSS2_RC_SUCCESS;
    }

    /* The typical case is that we have a resource object already within the
       esys context's linked list. We iterate through the list and search
       for the corresponding object and return it if found.
       If no object is found, this can be an erroneous handle number or it
       can be because of a reference "global" object that does not require
       previous initialization. */
    for (esys_object_aux = esys_context->rsrc_list; esys_object_aux != NULL;
         esys_object_aux = esys_object_aux->next) {
        if (esys_object_aux->esys_handle == esys_handle) {
            *esys_object = esys_object_aux;
            return TPM2_RC_SUCCESS;
        }
    }

    /* All objects with a TR-handle larger than ESYS_TR_MIN_OBJECT must have
       been initialized previously. Therefore the TR handle was erroneous. */
    if (esys_handle >= ESYS_TR_MIN_OBJECT) {
        LOG_ERROR("Error: Esys handle does not exist (0x%08"PRIx32").",
                  TSS2_ESYS_RC_BAD_TR);
        return TSS2_ESYS_RC_BAD_TR;
    }

    /* There are special "global" object for the TPM, such as PCRs or
       hierarchies. If they do not exist yet inside the Esys context we create
       them here and return the newly created object. */
    r = iesys_handle_to_tpm_handle(esys_handle, &tpm_handle);
    return_if_error(r, "Unknown ESYS handle.");

    r = esys_CreateResourceObject(esys_context, esys_handle, &esys_object_aux);
    return_if_error(r, "Creating Resource Object.");

    esys_object_aux->rsrc.handle = tpm_handle;
    esys_object_aux->rsrc.rsrcType = IESYSC_WITHOUT_MISC_RSRC;

    r = Tss2_MU_TPM2_HANDLE_Marshal(tpm_handle,
                                &esys_object_aux->rsrc.name.name[0],
                                sizeof(esys_object_aux->rsrc.name.name),
                                &offset);
    return_if_error(r, "Marshaling TPM handle.");

    esys_object_aux->rsrc.name.size = offset;
    *esys_object = esys_object_aux;
    return TSS2_RC_SUCCESS;
}

/**
 * Check that the esys context is ready for an _async call.
 *
 * This function will check that the sequence of invocations to the esys context
 * was such that an _async function can be called. This means that the internal
 * @state field is either @ESYS_STATE_INIT, @_ESYS_STATE_ERRORRESPONSE,
 * @_ESYS_STATE_FINISHED.
 * @param[in,out] esys_context The esys context to issue the command on.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 */
TSS2_RC
iesys_check_sequence_async(ESYS_CONTEXT * esys_context)
{
    if (esys_context == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    if (esys_context->state != ESYS_STATE_INIT &&
        esys_context->state != ESYS_STATE_RESUBMISSION) {
        LOG_ERROR("Esys called in bad sequence.");
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    }
    esys_context->submissionCount = 1;
    return TSS2_RC_SUCCESS;
}

/** Check whether session without authorization occurs before one with.
 *
 * @param[in] session1-3 The three sessions.
 * @retval TPM2_RC_SUCCESS if the order is ok.
 * @retval TSS2_ESYS_RC_BAD_VALUE if not.
 */
TSS2_RC
check_session_feasibility(ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
                          int mandatory)
{
    ESYS_TR handle_tab[3] = { shandle1, shandle2, shandle3 };
    bool check_none = false;
    for (int i = 2; i >= 0; i--) {
        if (handle_tab[i] != ESYS_TR_NONE)
            mandatory--;
        if (handle_tab[i] != ESYS_TR_NONE && handle_tab[i] != ESYS_TR_PASSWORD)
            check_none = true;
        else {
            if (check_none) {
                if (handle_tab[i] == ESYS_TR_NONE) {
                    LOG_ERROR("Error: ESYS_TR_NONE used before other handle.");
                    return TSS2_ESYS_RC_BAD_VALUE;
                }
            }
        }
    }
    if (mandatory > 0) {
        LOG_ERROR("Not enough sessions provided for the command.");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    return TPM2_RC_SUCCESS;
}

/** Computation of the command parameter(cp) hash.
 *
 * The command parameter(cp) hash of the command is computed for every
 * session.  If the sessions use different hash algorithms then different cp
 * hashes must be calculated.
 * The names of objects with an auth index and the command buffer are used
 * to compute the cp hash with the hash algorithm of the corresponding session.
 * The result is stored in table together with the used hash algorithm.
 * @param[in] esys_context The ESYS_CONTEXT
 * @param[in] hash_alg The hash alg used to compute the cp hash
 * @param[3] [out] cp_hash The cp hash.
 * @param[out] cp_hash_size The size of the computed cp hash.
 * @retval TSS2_RC_SUCCESS on success,
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_compute_cp_hash(ESYS_CONTEXT *esys_context,
                      TPMI_ALG_HASH hash_alg,
                      uint8_t *cp_hash,
                      size_t *cp_hash_size) {
     TSS2_RC r;
     uint8_t ccBuffer[4];
     const uint8_t *cpBuffer;
     size_t cpBuffer_size;
     const TPM2B_NAME *name1, *name2, *name3;

     r = Tss2_Sys_GetCommandCode(esys_context->sys, &ccBuffer[0]);
     return_if_error(r, "Error: get command code");

     r = Tss2_Sys_GetCpBuffer(esys_context->sys, &cpBuffer_size, &cpBuffer);
     return_if_error(r, "Error: get cp buffer");

     name1 = (esys_context->auth_objects[0] != NULL) ?
         &esys_context->auth_objects[0]->rsrc.name : NULL;
     name2 = (esys_context->auth_objects[1] != NULL) ?
         &esys_context->auth_objects[1]->rsrc.name : NULL;
     name3 = (esys_context->auth_objects[2] != NULL) ?
         &esys_context->auth_objects[2]->rsrc.name : NULL;

     *cp_hash_size = sizeof(TPMU_HA);

     r = iesys_crypto_cpHash(&esys_context->crypto_backend,
                             hash_alg,
                             ccBuffer,
                             name1, name2, name3,
                             cpBuffer, cpBuffer_size,
                             &cp_hash[0],
                             cp_hash_size);
     return_if_error(r, "crypto cpHash");

     return TSS2_RC_SUCCESS;
}

/** Compute HMAC for a session.
 *
 * The HMAC is computed from the appropriate cp hash, the caller nonce, the TPM
 * nonce and the session attributes. If an encrypt session is not the first
 * session also the encrypt and the decrypt nonce have to be included.
 * @param[in] session The session for which the HMAC has to be computed.
 * @param[in] encryptNonce The encrypt Nonce of an encryption session. Has to
 *            be NULL if encryption session is first session.
 * @param[in] decryptNonce The decrypt Nonce of an encryption session. Has to
 *            be NULL if encryption session is first session.
 * @param[out] auth The computed HMAC value.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED if hash algorithm is not implemented.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_compute_hmac(ESYS_CONTEXT *esys_context, RSRC_NODE_T * session,
                   TPM2B_NONCE * decryptNonce,
                   TPM2B_NONCE * encryptNonce,
                   TPMS_AUTH_COMMAND * auth)
{
    TSS2_RC r;
    size_t authHash_size = 0;
    uint8_t cp_hash[sizeof(TPMU_HA)];
    size_t cp_hash_size;

    if (session != NULL) {
        IESYS_SESSION *rsrc_session = &session->rsrc.misc.rsrc_session;
        r = iesys_crypto_hash_get_digest_size(rsrc_session->
                                              authHash, &authHash_size);
        return_if_error(r, "Initializing auth session");

        r = iesys_compute_cp_hash(esys_context, rsrc_session->authHash, cp_hash, &cp_hash_size);
        return_if_error(r, "crypto cpHash");

        auth->hmac.size = sizeof(TPMU_HA);
        /* if other than first session is used for for parameter encryption
           the corresponding nonces have to be included into the hmac
           computation of the first session */
        r = iesys_crypto_authHmac(&esys_context->crypto_backend, rsrc_session->authHash,
                                  &rsrc_session->sessionValue[0],
                                  rsrc_session->sizeHmacValue,
                                  &cp_hash[0],
                                  cp_hash_size,
                                  &rsrc_session->nonceCaller,
                                  &rsrc_session->nonceTPM,
                                  decryptNonce, encryptNonce,
                                  rsrc_session->sessionAttributes, &auth->hmac);
        return_if_error(r, "HMAC error");
        auth->sessionHandle = session->rsrc.handle;
        auth->nonce = rsrc_session->nonceCaller;
        auth->sessionAttributes =
            rsrc_session->sessionAttributes;
    }
    return TSS2_RC_SUCCESS;
}

/** Compute the auth values (HMACs) for all sessions.
 *
 * The caller nonce, the encrypt nonces, the cp hashes, and the HMAC values for
 * the command authorization are computed.
 * @param[in] esys_context The esys context to issue the command on.
 * @param[in] h1-3 The esys session resource objects.
 * @param[out] The list if the authorizations with the computed HMACs.
 * @param[out] auth The computed HMAC value.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED if hash algorithm is not implemented.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_gen_auths(ESYS_CONTEXT * esys_context,
                RSRC_NODE_T * h1,
                RSRC_NODE_T * h2,
                RSRC_NODE_T * h3,
                TSS2L_SYS_AUTH_COMMAND * auths)
{
    TSS2_RC r;
    TPM2B_NONCE *decryptNonce = NULL;
    int decryptNonceIdx = 0;
    int encryptNonceIdx = 0;
    TPM2B_NONCE *encryptNonce = NULL;

    esys_context->auth_objects[0] = h1;
    esys_context->auth_objects[1] = h2;
    esys_context->auth_objects[2] = h3;

    auths->count = 0;
    r = iesys_gen_caller_nonces(esys_context);
    return_if_error(r, "Error nonce generation caller");
    r = iesys_encrypt_param(esys_context, &decryptNonce, &decryptNonceIdx);
    return_if_error(r, "Error parameter encryption");
    r = iesys_compute_encrypt_nonce(esys_context, &encryptNonceIdx,
                                    &encryptNonce);
    return_if_error(r, "More than one crypt session");

    /*
     * TPM2.0 Architecture 19.6.5 Note 7
     *
     * If the same session (not the first session) is used for decrypt and
     * encrypt, its nonceTPM is only used once. If different sessions are used
     * for decrypt and encrypt, both nonceTPMs are included
     */
    if (decryptNonceIdx && (decryptNonceIdx == encryptNonceIdx)) {
        decryptNonceIdx = 0;
    }

    for (int session_idx = 0; session_idx < 3; session_idx++) {
        auths->auths[auths->count].nonce.size = 0;
        auths->auths[auths->count].sessionAttributes = 0;
        if (esys_context->session_type[session_idx] == ESYS_TR_PASSWORD) {
            if (esys_context->auth_objects[session_idx] == NULL) {
                auths->auths[auths->count].hmac.size = 0;
                auths->count += 1;
            } else {
                auths->auths[auths->count].sessionHandle = TPM2_RH_PW;
                auths->auths[auths->count].hmac =
                    esys_context->auth_objects[session_idx]->auth;
                auths->count += 1;
            }
            continue;
        }
        RSRC_NODE_T *session = esys_context->session_tab[session_idx];
        if (session != NULL) {
            IESYS_SESSION *rsrc_session = &session->rsrc.misc.rsrc_session;
            if (rsrc_session->type_policy_session == POLICY_PASSWORD) {
                auths->auths[auths->count].sessionHandle = session->rsrc.handle;
                if (esys_context->auth_objects[session_idx] == NULL) {
                    auths->auths[auths->count].hmac.size = 0;
                } else {
                    auths->auths[auths->count].hmac =
                        esys_context->auth_objects[session_idx]->auth;
                }
                auths->auths[auths->count].sessionAttributes =
                    session->rsrc.misc.rsrc_session.sessionAttributes;
                auths->count += 1;
                continue;
            }
        }
        r = iesys_compute_hmac(esys_context, esys_context->session_tab[session_idx],
                               (session_idx == 0
                                && decryptNonceIdx > 0) ? decryptNonce : NULL,
                               (session_idx == 0
                                && encryptNonceIdx > 0) ? encryptNonce : NULL,
                               &auths->auths[session_idx]);
        return_if_error(r, "Error while computing hmacs");
        if (esys_context->session_tab[session_idx] != NULL && session != NULL) {
            auths->auths[auths->count].sessionHandle = session->rsrc.handle;
            auths->count++;
        }
    }

    esys_context->encryptNonceIdx = encryptNonceIdx;
    esys_context->encryptNonce = encryptNonce;

    return TSS2_RC_SUCCESS;
}

/** Check the response HMACs for all sessions.
 *
 * The response HMAC values are computed. Based on these values the HMACs for
 * all sessions are computed and compared with the HMACs stored in the response
 * auth list which is determined with the SAPI function Tss2_Sys_GetRspAuths.
 * @param[in] esys_context The esys context which is used to get the response
 * auth values and the sessions.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED if hash algorithm is not implemented.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_check_response(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    const uint8_t *rpBuffer;
    size_t rpBuffer_size;
    TSS2L_SYS_AUTH_RESPONSE rspAuths;

    if (esys_context->authsCount == 0) {
        LOG_TRACE("No auths to verify");
        return TSS2_RC_SUCCESS;
    }

    r = Tss2_Sys_GetRspAuths(esys_context->sys, &rspAuths);
    return_if_error(r, "Error: GetRspAuths");

    if (rspAuths.count != esys_context->authsCount) {
        LOG_ERROR("Number of response auths differs: %i (expected %i)",
                  rspAuths.count, esys_context->authsCount);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    /*
     * At least one session object is defined so the rp hashes must be computed
     * and the HMACs of the responses have to be checked.
     * Encrypted response parameters will be decrypted.
     */
    if (esys_context->session_type[0] >= ESYS_TR_MIN_OBJECT ||
        esys_context->session_type[1] >= ESYS_TR_MIN_OBJECT ||
        esys_context->session_type[2] >= ESYS_TR_MIN_OBJECT) {
        r = Tss2_Sys_GetRpBuffer(esys_context->sys, &rpBuffer_size, &rpBuffer);
        return_if_error(r, "Error: get rp buffer");

        r = iesys_check_rp_hmacs(esys_context, &rspAuths);
        return_if_error(r, "Error: response hmac check");

        if (esys_context->encryptNonce == NULL) {
            iesys_restore_session_flags(esys_context);
            return TSS2_RC_SUCCESS;
        }

        r = iesys_decrypt_param(esys_context);
        return_if_error(r, "Error: while decrypting parameter.");
        iesys_restore_session_flags(esys_context);

    }
    return TSS2_RC_SUCCESS;
}

/** Compute the name from the public data of a NV index.
 *
 * The name of a NV index is computed as follows:
 *   name =  nameAlg||Hash(nameAlg,marshal(publicArea))
 * @param[in] publicInfo The public information of the NV index.
 * @param[out] name The computed name.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_ESYS_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED if hash algorithm is not implemented.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
iesys_nv_get_name(ESYS_CRYPTO_CALLBACKS *crypto_cb, TPM2B_NV_PUBLIC * publicInfo, TPM2B_NAME * name)
{
    BYTE buffer[sizeof(TPMS_NV_PUBLIC)];
    size_t offset = 0;
    size_t size = sizeof(TPMU_NAME) - sizeof(TPMI_ALG_HASH);
    size_t len_alg_id = sizeof(TPMI_ALG_HASH);
    ESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;

    if (publicInfo->nvPublic.nameAlg == TPM2_ALG_NULL) {
        name->size = 0;
        return TSS2_RC_SUCCESS;
    }
    TSS2_RC r;
    r = iesys_crypto_hash_start(
        crypto_cb,
        &cryptoContext, publicInfo->nvPublic.nameAlg);
    return_if_error(r, "Crypto hash start");

    r = Tss2_MU_TPMS_NV_PUBLIC_Marshal(&publicInfo->nvPublic,
                                       &buffer[0], sizeof(TPMS_NV_PUBLIC),
                                       &offset);
    goto_if_error(r, "Marshaling TPMS_NV_PUBLIC", error_cleanup);

    r = iesys_crypto_hash_update(crypto_cb,
            cryptoContext, &buffer[0], offset);
    goto_if_error(r, "crypto hash update", error_cleanup);

    r = iesys_crypto_hash_finish(crypto_cb,
            &cryptoContext, &name->name[len_alg_id],
            &size);
    goto_if_error(r, "crypto hash finish", error_cleanup);

    offset = 0;
    r = Tss2_MU_TPMI_ALG_HASH_Marshal(publicInfo->nvPublic.nameAlg,
                                  &name->name[0], sizeof(TPMI_ALG_HASH),
                                  &offset);
    goto_if_error(r, "Marshaling TPMI_ALG_HASH", error_cleanup);

    name->size = size + len_alg_id;
    return TSS2_RC_SUCCESS;

error_cleanup:
    if (cryptoContext) {
        TSS2_RC tmp_rc = iesys_crypto_hash_abort(crypto_cb,
                &cryptoContext);
        if (tmp_rc != TSS2_RC_SUCCESS) {
            r = tmp_rc;
        }
    }
    return r;
}

/** Compute the name of a TPM transient or persistent object.
 *
 * The name of a NV index is computed as follows:
 *   name = Hash(nameAlg,marshal(publicArea))
 * @param[in] publicInfo The public information of the TPM object.
 * @param[out] name The computed name.
 * @retval TPM2_RC_SUCCESS  or one of the possible errors TSS2_ESYS_RC_BAD_VALUE,
 * TSS2_ESYS_RC_MEMORY, TSS2_ESYS_RC_GENERAL_FAILURE, TSS2_ESYS_RC_NOT_IMPLEMENTED,
 * or return codes of SAPI errors.
 */
TSS2_RC
iesys_get_name(ESYS_CRYPTO_CALLBACKS *crypto_cb, TPM2B_PUBLIC * publicInfo, TPM2B_NAME * name)
{
    BYTE buffer[sizeof(TPMT_PUBLIC)];
    size_t offset = 0;
    size_t len_alg_id = sizeof(TPMI_ALG_HASH);
    size_t size = sizeof(TPMU_NAME) - sizeof(TPMI_ALG_HASH);
    ESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;

    if (publicInfo->publicArea.nameAlg == TPM2_ALG_NULL) {
        name->size = 0;
        return TSS2_RC_SUCCESS;
    }
    TSS2_RC r;
    r = iesys_crypto_hash_start(crypto_cb,
        &cryptoContext, publicInfo->publicArea.nameAlg);
    return_if_error(r, "crypto hash start");

    r = Tss2_MU_TPMT_PUBLIC_Marshal(&publicInfo->publicArea,
                                    &buffer[0], sizeof(TPMT_PUBLIC), &offset);
    goto_if_error(r, "Marshaling TPMT_PUBLIC", error_cleanup);

    r = iesys_crypto_hash_update(crypto_cb,
        cryptoContext, &buffer[0], offset);
    goto_if_error(r, "crypto hash update", error_cleanup);

    r = iesys_crypto_hash_finish(crypto_cb,
            &cryptoContext, &name->name[len_alg_id],
                                     &size);
    goto_if_error(r, "crypto hash finish", error_cleanup);

    offset = 0;
    r = Tss2_MU_TPMI_ALG_HASH_Marshal(publicInfo->publicArea.nameAlg,
                                  &name->name[0], sizeof(TPMI_ALG_HASH),
                                  &offset);
    goto_if_error(r, "Marshaling TPMI_ALG_HASH", error_cleanup);

    name->size = size + len_alg_id;
    return TSS2_RC_SUCCESS;

error_cleanup:
    if (cryptoContext) {
        TSS2_RC tmp_rc = iesys_crypto_hash_abort(crypto_cb,
                &cryptoContext);
        if (tmp_rc != TSS2_RC_SUCCESS) {
            r = tmp_rc;
        }
    }
    return r;
}

/** Check whether the return code corresponds to an TPM error.
 *
 * if no layer is part of the return code or a layer from the resource manager
 * is given the function will return true.
 * @param[in] r The return code to be checked.
 * @retval true if r corresponds to an TPM error.
 * @retval false in other cases.
 */
bool
iesys_tpm_error(TSS2_RC r)
{
    return (r != TSS2_RC_SUCCESS &&
            ((r & TSS2_RC_LAYER_MASK) == 0 ||
             (r & TSS2_RC_LAYER_MASK) == TSS2_RESMGR_TPM_RC_LAYER ||
             (r & TSS2_RC_LAYER_MASK) == TSS2_RESMGR_RC_LAYER));
}

/** Remove trailing spaces includes auth value.
 *
 * Trailing zeros will be removed.
 *
 * @param[in,out] auth_value The auth value to be adapted.
 */
void iesys_strip_trailing_zeros(TPM2B_DIGEST *digest)
{
    /* Remove trailing zeroes */
    if (digest) {
        while (digest->size > 0 &&
               digest->buffer[digest->size - 1] == 0) {
            digest->size--;
        }
    }
}

/** Adapt auth value.
 *
 * if the size of auth value exceeds hash_size the auth value
 * will be replaced with the hash of the auth value.
 * Trailing zeros will be removed.
 *
 * @param[in,out] auth_value The auth value to be adapted.
 * @param[in] hash_alg The hash alg used for adaption.
 * @retval TSS2_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_VALUE if an invalid hash is passed.
 * @retval TSS2_ESYS_RC_MEMORY if the ESAPI cannot allocate enough memory.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for a failure during digest
 *         computation.
 */
TSS2_RC
iesys_adapt_auth_value(
    ESYS_CRYPTO_CALLBACKS *crypto_cb,
    TPM2B_AUTH *auth_value,
    TPMI_ALG_HASH hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    ESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;
    TPM2B_AUTH hash2b;
    size_t hash_size;

    /* Remove trailing zeroes */
    iesys_strip_trailing_zeros(auth_value);

    if (hash_alg) {
        r = iesys_crypto_hash_get_digest_size(hash_alg, &hash_size);
        return_if_error(r, "Get digest size.");

        if (auth_value && auth_value->size > hash_size) {
            /* The auth value has to be adapted. */
            r = iesys_crypto_hash_start(crypto_cb,
                     &cryptoContext, hash_alg);
            return_if_error(r, "crypto hash start");

            r = iesys_crypto_hash_update(crypto_cb,
                    cryptoContext, &auth_value->buffer[0],
                    auth_value->size);
            goto_if_error(r, "crypto hash update", error_cleanup);

            r = iesys_crypto_hash_finish(crypto_cb,
                    &cryptoContext, &hash2b.buffer[0], &hash_size);
            goto_if_error(r, "crypto hash finish", error_cleanup);

            memcpy(&auth_value->buffer[0], &hash2b.buffer[0], hash_size);
            auth_value->size = hash_size;

            /* Remove trailing zeroes */
            iesys_strip_trailing_zeros(auth_value);
        }
    }

    return r;

 error_cleanup:
    if (cryptoContext) {
        TSS2_RC tmp_rc = iesys_crypto_hash_abort(crypto_cb,
                &cryptoContext);
        if (tmp_rc != TSS2_RC_SUCCESS) {
            r = tmp_rc;
        }
    }
    return r;
}
