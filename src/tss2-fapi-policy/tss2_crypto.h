/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef TSS2_CRYPTO_H
#define TSS2_CRYPTO_H

#include <openssl/evp.h> // for EVP_MD
#include <stddef.h>      // for size_t
#include <stdint.h>      // for uint8_t, uint16_t

#include "ifapi_keystore.h"  // for IFAPI_OBJECT
#include "ifapi_profiles.h"  // for IFAPI_PROFILE
#include "tss2_common.h"     // for TSS2_RC
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPM2_ALG_ID, TPMI_ALG_HASH

typedef struct IFAPI_CRYPTO_CONTEXT IFAPI_CRYPTO_CONTEXT_BLOB;

#define HASH_UPDATE(CONTEXT, TYPE, OBJECT, R, LABEL)                                               \
    {                                                                                              \
        uint8_t buffer[sizeof(TYPE)];                                                              \
        size_t  offset = 0;                                                                        \
        (R) = Tss2_MU_##TYPE##_Marshal(OBJECT, &buffer[0], sizeof(TYPE), &offset);                 \
        goto_if_error(R, "Marshal for hash update", LABEL);                                        \
        (R) = ifapi_crypto_hash_update(CONTEXT, (const uint8_t *)&buffer[0], offset);              \
        goto_if_error(R, "crypto hash update", LABEL);                                             \
    }

#define HASH_UPDATE_BUFFER(CONTEXT, BUFFER, SIZE, R, LABEL)                                        \
    R = ifapi_crypto_hash_update(CONTEXT, (const uint8_t *)(BUFFER), SIZE);                        \
    goto_if_error(R, "crypto hash update", LABEL);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
const EVP_MD *ifapi_get_ossl_hash_md(TPM2_ALG_ID hashAlgorithm);
#else
const char *ifapi_get_hash_md(TPM2_ALG_ID hashAlgorithm);
#endif

size_t ifapi_hash_get_digest_size(TPM2_ALG_ID hashAlgorithm);

TSS2_RC
ifapi_crypto_hash_start(IFAPI_CRYPTO_CONTEXT_BLOB **context, TPM2_ALG_ID hashAlgorithm);

TSS2_RC
ifapi_crypto_hash_update(IFAPI_CRYPTO_CONTEXT_BLOB *context, const uint8_t *buffer, size_t size);

TSS2_RC
ifapi_crypto_hash_finish(IFAPI_CRYPTO_CONTEXT_BLOB **context, uint8_t *digest, size_t *digestSize);

void ifapi_crypto_hash_abort(IFAPI_CRYPTO_CONTEXT_BLOB **context);

#endif /* TSS2_CRYPTO_H */
