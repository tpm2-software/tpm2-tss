/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifndef EYSS_TYPEPCHECK_H
#define EYSS_TYPEPCHECK_H

#include <inttypes.h>

#include "tss2_tpm2_types.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC iesys_TPM2_ALGORITHM_ID_check(const TPM2_ALGORITHM_ID in);

TSS2_RC iesys_TPM2_MODIFIER_INDICATOR_check(const TPM2_MODIFIER_INDICATOR in);

TSS2_RC iesys_TPM2_AUTHORIZATION_SIZE_check(const TPM2_AUTHORIZATION_SIZE in);

TSS2_RC iesys_TPM2_PARAMETER_SIZE_check(const TPM2_PARAMETER_SIZE in);

TSS2_RC iesys_TPM2_KEY_SIZE_check(const TPM2_KEY_SIZE in);

TSS2_RC iesys_TPM2_KEY_BITS_check(const TPM2_KEY_BITS in);

TSS2_RC iesys_TPM2_ALG_ID_check(const TPM2_ALG_ID in);

TSS2_RC iesys_TPM2_ECC_CURVE_check(const TPM2_ECC_CURVE in);

TSS2_RC iesys_TPM2_CC_check(const TPM2_CC in);

TSS2_RC iesys_TPM2_CLOCK_ADJUST_check(const TPM2_CLOCK_ADJUST in);

TSS2_RC iesys_TPM2_EO_check(const TPM2_EO in);

TSS2_RC iesys_TPM2_ST_check(const TPM2_ST in);

TSS2_RC iesys_TPM2_SE_check(const TPM2_SE in);

TSS2_RC iesys_TPM2_CAP_check(const TPM2_CAP in);

TSS2_RC iesys_TPM2_HANDLE_check(const TPM2_HANDLE in);

TSS2_RC iesys_TPM2_RH_check(const TPM2_RH in);

TSS2_RC iesys_TPMA_CC_check(const TPMA_CC in);

TSS2_RC iesys_TPMA_MODES_check(const TPMA_MODES in);

TSS2_RC iesys_TPMI_YES_NO_check(const TPMI_YES_NO in);

TSS2_RC iesys_TPMI_DH_OBJECT_check(const TPMI_DH_OBJECT in);

TSS2_RC iesys_TPMI_DH_PERSISTENT_check(const TPMI_DH_PERSISTENT in);

TSS2_RC iesys_TPMI_DH_ENTITY_check(const TPMI_DH_ENTITY in);

TSS2_RC iesys_TPMI_DH_PCR_check(const TPMI_DH_PCR in);

TSS2_RC iesys_TPMI_SH_AUTH_SESSION_check(const TPMI_SH_AUTH_SESSION in);

TSS2_RC iesys_TPMI_SH_HMAC_check(const TPMI_SH_HMAC in);

TSS2_RC iesys_TPMI_SH_POLICY_check(const TPMI_SH_POLICY in);

TSS2_RC iesys_TPMI_DH_CONTEXT_check(const TPMI_DH_CONTEXT in);

TSS2_RC iesys_TPMI_RH_HIERARCHY_check(const TPMI_RH_HIERARCHY in);

TSS2_RC iesys_TPMI_RH_ENABLES_check(const TPMI_RH_ENABLES in);

TSS2_RC iesys_TPMI_RH_HIERARCHY_AUTH_check(const TPMI_RH_HIERARCHY_AUTH in);

TSS2_RC iesys_TPMI_RH_PLATFORM_check(const TPMI_RH_PLATFORM in);

TSS2_RC iesys_TPMI_RH_OWNER_check(const TPMI_RH_OWNER in);

TSS2_RC iesys_TPMI_RH_ENDORSEMENT_check(const TPMI_RH_ENDORSEMENT in);

TSS2_RC iesys_TPMI_RH_PROVISION_check(const TPMI_RH_PROVISION in);

TSS2_RC iesys_TPMI_RH_CLEAR_check(const TPMI_RH_CLEAR in);

TSS2_RC iesys_TPMI_RH_NV_AUTH_check(const TPMI_RH_NV_AUTH in);

TSS2_RC iesys_TPMI_RH_LOCKOUT_check(const TPMI_RH_LOCKOUT in);

TSS2_RC iesys_TPMI_ALG_HASH_check(const TPMI_ALG_HASH in);

TSS2_RC iesys_TPMI_ALG_ASYM_check(const TPMI_ALG_ASYM in);

TSS2_RC iesys_TPMI_ALG_SYM_check(const TPMI_ALG_SYM in);

TSS2_RC iesys_TPMI_ALG_SYM_OBJECT_check(const TPMI_ALG_SYM_OBJECT in);

TSS2_RC iesys_TPMI_ALG_SYM_MODE_check(const TPMI_ALG_SYM_MODE in);

TSS2_RC iesys_TPMI_ALG_KDF_check(const TPMI_ALG_KDF in);

TSS2_RC iesys_TPMI_ALG_SIG_SCHEME_check(const TPMI_ALG_SIG_SCHEME in);

TSS2_RC iesys_TPMI_ECC_KEY_EXCHANGE_check(const TPMI_ECC_KEY_EXCHANGE in);

TSS2_RC iesys_TPMI_ST_COMMAND_TAG_check(const TPMI_ST_COMMAND_TAG in);

TSS2_RC iesys_TPMS_EMPTY_check(const TPMS_EMPTY *in);

TSS2_RC iesys_TPMS_ALGORITHM_DESCRIPTION_check(const TPMS_ALGORITHM_DESCRIPTION *in);

TSS2_RC iesys_TPMU_HA_check(const TPMU_HA *in, UINT32 selector);

TSS2_RC iesys_TPMT_HA_check(const TPMT_HA *in);

TSS2_RC iesys_TPM2B_DIGEST_check(const TPM2B_DIGEST *in);

TSS2_RC iesys_TPM2B_DATA_check(const TPM2B_DATA *in);

TSS2_RC iesys_TPM2B_NONCE_check(const TPM2B_NONCE *in);

TSS2_RC iesys_TPM2B_AUTH_check(const TPM2B_AUTH *in);

TSS2_RC iesys_TPM2B_OPERAND_check(const TPM2B_OPERAND *in);

TSS2_RC iesys_TPM2B_EVENT_check(const TPM2B_EVENT *in);

TSS2_RC iesys_TPM2B_MAX_BUFFER_check(const TPM2B_MAX_BUFFER *in);

TSS2_RC iesys_TPM2B_MAX_NV_BUFFER_check(const TPM2B_MAX_NV_BUFFER *in);

TSS2_RC iesys_TPM2B_TIMEOUT_check(const TPM2B_TIMEOUT *in);

TSS2_RC iesys_TPM2B_IV_check(const TPM2B_IV *in);

TSS2_RC iesys_TPMU_NAME_check(const TPMU_NAME *in, UINT32 selector);

TSS2_RC iesys_TPM2B_NAME_check(const TPM2B_NAME *in);

TSS2_RC iesys_TPMS_PCR_SELECT_check(const TPMS_PCR_SELECT *in);

TSS2_RC iesys_TPMS_PCR_SELECTION_check(const TPMS_PCR_SELECTION *in);

TSS2_RC iesys_TPMT_TK_CREATION_check(const TPMT_TK_CREATION *in);

TSS2_RC iesys_TPMT_TK_VERIFIED_check(const TPMT_TK_VERIFIED *in);

TSS2_RC iesys_TPMT_TK_AUTH_check(const TPMT_TK_AUTH *in);

TSS2_RC iesys_TPMT_TK_HASHCHECK_check(const TPMT_TK_HASHCHECK *in);

TSS2_RC iesys_TPMS_ALG_PROPERTY_check(const TPMS_ALG_PROPERTY *in);

TSS2_RC iesys_TPML_CC_check(const TPML_CC *in);

TSS2_RC iesys_TPML_CCA_check(const TPML_CCA *in);

TSS2_RC iesys_TPML_ALG_check(const TPML_ALG *in);

TSS2_RC iesys_TPML_HANDLE_check(const TPML_HANDLE *in);

TSS2_RC iesys_TPML_DIGEST_check(const TPML_DIGEST *in);

TSS2_RC iesys_TPML_DIGEST_VALUES_check(const TPML_DIGEST_VALUES *in);

TSS2_RC iesys_TPML_PCR_SELECTION_check(const TPML_PCR_SELECTION *in);

TSS2_RC iesys_TPML_ALG_PROPERTY_check(const TPML_ALG_PROPERTY *in);

TSS2_RC iesys_TPML_TAGGED_TPM_PROPERTY_check(const TPML_TAGGED_TPM_PROPERTY *in);

TSS2_RC iesys_TPML_TAGGED_PCR_PROPERTY_check(const TPML_TAGGED_PCR_PROPERTY *in);

TSS2_RC iesys_TPML_ECC_CURVE_check(const TPML_ECC_CURVE *in);

TSS2_RC iesys_TPMS_CLOCK_INFO_check(const TPMS_CLOCK_INFO *in);

TSS2_RC iesys_TPMS_TIME_INFO_check(const TPMS_TIME_INFO *in);

TSS2_RC iesys_TPMS_TIME_ATTEST_INFO_check(const TPMS_TIME_ATTEST_INFO *in);

TSS2_RC iesys_TPMS_CERTIFY_INFO_check(const TPMS_CERTIFY_INFO *in);

TSS2_RC iesys_TPMS_QUOTE_INFO_check(const TPMS_QUOTE_INFO *in);

TSS2_RC iesys_TPMS_COMMAND_AUDIT_INFO_check(const TPMS_COMMAND_AUDIT_INFO *in);

TSS2_RC iesys_TPMS_SESSION_AUDIT_INFO_check(const TPMS_SESSION_AUDIT_INFO *in);

TSS2_RC iesys_TPMS_CREATION_INFO_check(const TPMS_CREATION_INFO *in);

TSS2_RC iesys_TPMS_NV_CERTIFY_INFO_check(const TPMS_NV_CERTIFY_INFO *in);

TSS2_RC iesys_TPMI_ST_ATTEST_check(const TPMI_ST_ATTEST in);

TSS2_RC iesys_TPMU_ATTEST_check(const TPMU_ATTEST *in, UINT32 selector);

TSS2_RC iesys_TPMS_ATTEST_check(const TPMS_ATTEST *in);

TSS2_RC iesys_TPM2B_ATTEST_check(const TPM2B_ATTEST *in);

TSS2_RC iesys_TPMS_AUTH_COMMAND_check(const TPMS_AUTH_COMMAND *in);

TSS2_RC iesys_TPMS_AUTH_RESPONSE_check(const TPMS_AUTH_RESPONSE *in);

TSS2_RC iesys_TPMI_AES_KEY_BITS_check(const TPMI_AES_KEY_BITS in);

TSS2_RC iesys_TPMU_SYM_KEY_BITS_check(const TPMU_SYM_KEY_BITS *in, UINT32 selector);

TSS2_RC iesys_TPMU_SYM_MODE_check(const TPMU_SYM_MODE *in, UINT32 selector);

TSS2_RC iesys_TPMT_SYM_DEF_check(const TPMT_SYM_DEF *in);

TSS2_RC iesys_TPMT_SYM_DEF_OBJECT_check(const TPMT_SYM_DEF_OBJECT *in);

TSS2_RC iesys_TPM2B_SYM_KEY_check(const TPM2B_SYM_KEY *in);

TSS2_RC iesys_TPMS_SYMCIPHER_PARMS_check(const TPMS_SYMCIPHER_PARMS *in);

TSS2_RC iesys_TPM2B_SENSITIVE_DATA_check(const TPM2B_SENSITIVE_DATA *in);

TSS2_RC iesys_TPMS_SENSITIVE_CREATE_check(const TPMS_SENSITIVE_CREATE *in);

TSS2_RC iesys_TPM2B_SENSITIVE_CREATE_check(const TPM2B_SENSITIVE_CREATE *in);

TSS2_RC iesys_TPMS_SCHEME_HASH_check(const TPMS_SCHEME_HASH *in);

TSS2_RC iesys_TPMS_SCHEME_ECDAA_check(const TPMS_SCHEME_ECDAA *in);

TSS2_RC iesys_TPMI_ALG_KEYEDHASH_SCHEME_check(const TPMI_ALG_KEYEDHASH_SCHEME in);

TSS2_RC iesys_TPMS_SCHEME_HMAC_check(const TPMS_SCHEME_HMAC *in);

TSS2_RC iesys_TPMS_SCHEME_XOR_check(const TPMS_SCHEME_XOR *in);

TSS2_RC iesys_TPMU_SCHEME_KEYEDHASH_check(const TPMU_SCHEME_KEYEDHASH *in, UINT32 selector);

TSS2_RC iesys_TPMT_KEYEDHASH_SCHEME_check(const TPMT_KEYEDHASH_SCHEME *in);

TSS2_RC iesys_TPMS_SIG_SCHEME_RSASSA_check(const TPMS_SIG_SCHEME_RSASSA *in);

TSS2_RC iesys_TPMS_SIG_SCHEME_RSAPSS_check(const TPMS_SIG_SCHEME_RSAPSS *in);

TSS2_RC iesys_TPMS_SIG_SCHEME_ECDSA_check(const TPMS_SIG_SCHEME_ECDSA *in);

TSS2_RC iesys_TPMS_SIG_SCHEME_SM2_check(const TPMS_SIG_SCHEME_SM2 *in);

TSS2_RC iesys_TPMS_SIG_SCHEME_ECSCHNORR_check(const TPMS_SIG_SCHEME_ECSCHNORR *in);

TSS2_RC iesys_TPMS_SIG_SCHEME_ECDAA_check(const TPMS_SIG_SCHEME_ECDAA *in);

TSS2_RC iesys_TPMU_SIG_SCHEME_check(const TPMU_SIG_SCHEME *in, UINT32 selector);

TSS2_RC iesys_TPMT_SIG_SCHEME_check(const TPMT_SIG_SCHEME *in);

TSS2_RC iesys_TPMS_ENC_SCHEME_OAEP_check(const TPMS_ENC_SCHEME_OAEP *in);

TSS2_RC iesys_TPMS_ENC_SCHEME_RSAES_check(const TPMS_ENC_SCHEME_RSAES *in);

TSS2_RC iesys_TPMS_KEY_SCHEME_ECDH_check(const TPMS_KEY_SCHEME_ECDH *in);

TSS2_RC iesys_TPMS_SCHEME_MGF1_check(const TPMS_SCHEME_MGF1 *in);

TSS2_RC iesys_TPMS_SCHEME_KDF1_SP800_56A_check(const TPMS_SCHEME_KDF1_SP800_56A *in);

TSS2_RC iesys_TPMS_SCHEME_KDF1_SP800_108_check(const TPMS_SCHEME_KDF1_SP800_108 *in);

TSS2_RC iesys_TPMU_KDF_SCHEME_check(const TPMU_KDF_SCHEME *in, UINT32 selector);

TSS2_RC iesys_TPMT_KDF_SCHEME_check(const TPMT_KDF_SCHEME *in);

TSS2_RC iesys_TPMI_ALG_ASYM_SCHEME_check(const TPMI_ALG_ASYM_SCHEME in);

TSS2_RC iesys_TPMU_ASYM_SCHEME_check(const TPMU_ASYM_SCHEME *in, UINT32 selector);

TSS2_RC iesys_TPMT_ASYM_SCHEME_check(const TPMT_ASYM_SCHEME *in);

TSS2_RC iesys_TPMI_ALG_RSA_SCHEME_check(const TPMI_ALG_RSA_SCHEME in);

TSS2_RC iesys_TPMT_RSA_SCHEME_check(const TPMT_RSA_SCHEME *in);

TSS2_RC iesys_TPMI_ALG_RSA_DECRYPT_check(const TPMI_ALG_RSA_DECRYPT in);

TSS2_RC iesys_TPMT_RSA_DECRYPT_check(const TPMT_RSA_DECRYPT *in);

TSS2_RC iesys_TPM2B_PUBLIC_KEY_RSA_check(const TPM2B_PUBLIC_KEY_RSA *in);

TSS2_RC iesys_TPMI_RSA_KEY_BITS_check(const TPMI_RSA_KEY_BITS in);

TSS2_RC iesys_TPM2B_PRIVATE_KEY_RSA_check(const TPM2B_PRIVATE_KEY_RSA *in);

TSS2_RC iesys_TPM2B_ECC_PARAMETER_check(const TPM2B_ECC_PARAMETER *in);

TSS2_RC iesys_TPMS_ECC_POINT_check(const TPMS_ECC_POINT *in);

TSS2_RC iesys_TPM2B_ECC_POINT_check(const TPM2B_ECC_POINT *in);

TSS2_RC iesys_TPMI_ALG_ECC_SCHEME_check(const TPMI_ALG_ECC_SCHEME in);

TSS2_RC iesys_TPMI_ECC_CURVE_check(const TPMI_ECC_CURVE in);

TSS2_RC iesys_TPMT_ECC_SCHEME_check(const TPMT_ECC_SCHEME *in);

TSS2_RC iesys_TPMS_ALGORITHM_DETAIL_ECC_check(const TPMS_ALGORITHM_DETAIL_ECC *in);

TSS2_RC iesys_TPMS_SIGNATURE_RSA_check(const TPMS_SIGNATURE_RSA *in);

TSS2_RC iesys_TPMS_SIGNATURE_RSASSA_check(const TPMS_SIGNATURE_RSASSA *in);

TSS2_RC iesys_TPMS_SIGNATURE_RSAPSS_check(const TPMS_SIGNATURE_RSAPSS *in);

TSS2_RC iesys_TPMS_SIGNATURE_ECC_check(const TPMS_SIGNATURE_ECC *in);

TSS2_RC iesys_TPMS_SIGNATURE_ECDSA_check(const TPMS_SIGNATURE_ECDSA *in);

TSS2_RC iesys_TPMS_SIGNATURE_ECDAA_check(const TPMS_SIGNATURE_ECDAA *in);

TSS2_RC iesys_TPMS_SIGNATURE_SM2_check(const TPMS_SIGNATURE_SM2 *in);

TSS2_RC iesys_TPMS_SIGNATURE_ECSCHNORR_check(const TPMS_SIGNATURE_ECSCHNORR *in);

TSS2_RC iesys_TPMU_SIGNATURE_check(const TPMU_SIGNATURE *in, UINT32 selector);

TSS2_RC iesys_TPMT_SIGNATURE_check(const TPMT_SIGNATURE *in);

TSS2_RC iesys_TPMU_ENCRYPTED_SECRET_check(const TPMU_ENCRYPTED_SECRET *in, UINT32 selector);

TSS2_RC iesys_TPM2B_ENCRYPTED_SECRET_check(const TPM2B_ENCRYPTED_SECRET *in);

TSS2_RC iesys_TPMI_ALG_PUBLIC_check(const TPMI_ALG_PUBLIC in);

TSS2_RC iesys_TPMU_PUBLIC_ID_check(const TPMU_PUBLIC_ID *in, UINT32 selector);

TSS2_RC iesys_TPMS_KEYEDHASH_PARMS_check(const TPMS_KEYEDHASH_PARMS *in);

TSS2_RC iesys_TPMS_ASYM_PARMS_check(const TPMS_ASYM_PARMS *in);

TSS2_RC iesys_TPMS_RSA_PARMS_check(const TPMS_RSA_PARMS *in);

TSS2_RC iesys_TPMS_ECC_PARMS_check(const TPMS_ECC_PARMS *in);

TSS2_RC iesys_TPMU_PUBLIC_PARMS_check(const TPMU_PUBLIC_PARMS *in, UINT32 selector);

TSS2_RC iesys_TPMT_PUBLIC_PARMS_check(const TPMT_PUBLIC_PARMS *in);

TSS2_RC iesys_TPMT_PUBLIC_check(const TPMT_PUBLIC *in);

TSS2_RC iesys_TPM2B_PUBLIC_check(const TPM2B_PUBLIC *in);

TSS2_RC iesys_TPM2B_TEMPLATE_check(const TPM2B_TEMPLATE *in);

TSS2_RC iesys_TPM2B_PRIVATE_VENDOR_SPECIFIC_check(const TPM2B_PRIVATE_VENDOR_SPECIFIC *in);

TSS2_RC iesys_TPMU_SENSITIVE_COMPOSITE_check(const TPMU_SENSITIVE_COMPOSITE *in, UINT32 selector);

TSS2_RC iesys_TPMT_SENSITIVE_check(const TPMT_SENSITIVE *in);

TSS2_RC iesys_TPM2B_SENSITIVE_check(const TPM2B_SENSITIVE *in);

TSS2_RC iesys__PRIVATE_check(const _PRIVATE *in);

TSS2_RC iesys_TPM2B_PRIVATE_check(const TPM2B_PRIVATE *in);

TSS2_RC iesys_TPM2B_ID_OBJECT_check(const TPM2B_ID_OBJECT *in);

TSS2_RC iesys_TPM2_NV_INDEX_check(const TPM2_NV_INDEX in);

TSS2_RC iesys_TPMS_NV_PIN_COUNTER_PARAMETERS_check(const TPMS_NV_PIN_COUNTER_PARAMETERS *in);

TSS2_RC iesys_TPMA_NV_check(const TPMA_NV in);

TSS2_RC iesys_TPMS_NV_PUBLIC_check(const TPMS_NV_PUBLIC *in);

TSS2_RC iesys_TPM2B_NV_PUBLIC_check(const TPM2B_NV_PUBLIC *in);

TSS2_RC iesys_TPM2B_CONTEXT_SENSITIVE_check(const TPM2B_CONTEXT_SENSITIVE *in);

TSS2_RC iesys_TPMS_CONTEXT_DATA_check(const TPMS_CONTEXT_DATA *in);

TSS2_RC iesys_TPM2B_CONTEXT_DATA_check(const TPM2B_CONTEXT_DATA *in);

TSS2_RC iesys_TPMS_CONTEXT_check(const TPMS_CONTEXT *in);

TSS2_RC iesys_TPMS_CREATION_DATA_check(const TPMS_CREATION_DATA *in);

TSS2_RC iesys_TPM2B_CREATION_DATA_check(const TPM2B_CREATION_DATA *in);

TSS2_RC iesys_INT32_check(const INT32 in);

TSS2_RC iesys_UINT16_check(const UINT16 in);

TSS2_RC iesys_UINT32_check(const UINT32 in);

TSS2_RC iesys_UINT64_check(const UINT64 in);

TSS2_RC iesys_TPM2_SU_check(const TPM2_SU in);

#ifdef __cplusplus
}
#endif

#endif /* EYSS_TYPEPCHECK_H */
