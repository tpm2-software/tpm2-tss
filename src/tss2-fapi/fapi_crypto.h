/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef FAPI_CRYPTO_H
#define FAPI_CRYPTO_H

#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t, uint16_t

#include "ifapi_keystore.h"  // for IFAPI_OBJECT
#include "ifapi_profiles.h"  // for IFAPI_PROFILE
#include "tss2_common.h"     // for TSS2_RC
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPM2_ALG_ID, TPMI_ALG_HASH

TSS2_RC
ifapi_get_profile_sig_scheme(const IFAPI_PROFILE *profile,
                             const TPMT_PUBLIC   *tpmPublic,
                             TPMT_SIG_SCHEME     *signatureScheme);

TSS2_RC
ifapi_tpm_ecc_sig_to_der(const TPMT_SIGNATURE *tpmSignature,
                         uint8_t             **signature,
                         size_t               *signatureSize);

TSS2_RC
ifapi_verify_signature(const IFAPI_OBJECT *keyObject,
                       const uint8_t      *signature,
                       size_t              signatureSize,
                       const uint8_t      *digest,
                       size_t              digestSize);

TSS2_RC
ifapi_verify_signature_quote(const IFAPI_OBJECT    *keyObject,
                             const uint8_t         *signature,
                             size_t                 signatureSize,
                             const uint8_t         *digest,
                             size_t                 digestSize,
                             const TPMT_SIG_SCHEME *signatureScheme);

TSS2_RC
ifapi_rsa_encrypt(const char             *pem_key,
                  const TPMT_RSA_DECRYPT *rsa_decrypt_scheme,
                  const uint8_t          *plainText,
                  size_t                  plainTextSize,
                  uint8_t               **cipherText,
                  size_t                 *cipherTextSize);

#endif /* FAPI_CRYPTO_H */
