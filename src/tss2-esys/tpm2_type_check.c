/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#include <inttypes.h>

#include "tss2_esys.h"
#include "tpm2_type_check.h"
#include "esys_iutil.h"
#define LOGMODULE esys
#include "util/log.h"

/*** Table 5 - Definition of Types for Documentation ClarityTable 5 - Definition of Types for Documentation Clarity ***/

/**
 * Check, if a variable is actually of type TPM2_ALG_ID.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_ALG_ID_check(
    const TPM2_ALG_ID in)
{
    if ((in == TPM2_ALG_ERROR) ||
        (in == TPM2_ALG_RSA) ||
        (in == TPM2_ALG_SHA) ||
        (in == TPM2_ALG_SHA1) ||
        (in == TPM2_ALG_HMAC) ||
        (in == TPM2_ALG_AES) ||
        (in == TPM2_ALG_MGF1) ||
        (in == TPM2_ALG_KEYEDHASH) ||
        (in == TPM2_ALG_XOR) ||
        (in == TPM2_ALG_SHA256) ||
        (in == TPM2_ALG_SHA384) ||
        (in == TPM2_ALG_SHA512) ||
        (in == TPM2_ALG_NULL) ||
        (in == TPM2_ALG_SM3_256) ||
        (in == TPM2_ALG_SM4) ||
        (in == TPM2_ALG_RSASSA) ||
        (in == TPM2_ALG_RSAES) ||
        (in == TPM2_ALG_RSAPSS) ||
        (in == TPM2_ALG_OAEP) ||
        (in == TPM2_ALG_ECDSA) ||
        (in == TPM2_ALG_ECDH) ||
        (in == TPM2_ALG_ECDAA) ||
        (in == TPM2_ALG_SM2) ||
        (in == TPM2_ALG_ECSCHNORR) ||
        (in == TPM2_ALG_ECMQV) ||
        (in == TPM2_ALG_KDF1_SP800_56A) ||
        (in == TPM2_ALG_KDF2) ||
        (in == TPM2_ALG_KDF1_SP800_108) ||
        (in == TPM2_ALG_ECC) ||
        (in == TPM2_ALG_SYMCIPHER) ||
        (in == TPM2_ALG_CAMELLIA) ||
        (in == TPM2_ALG_CTR) ||
        (in == TPM2_ALG_OFB) ||
        (in == TPM2_ALG_CBC) ||
        (in == TPM2_ALG_CFB) ||
        (in == TPM2_ALG_ECB))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_ALG_ID");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_ECC_CURVE.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_ECC_CURVE_check(
    const TPM2_ECC_CURVE in)
{
    if ((in == TPM2_ECC_NONE) ||
        (in == TPM2_ECC_NIST_P192) ||
        (in == TPM2_ECC_NIST_P224) ||
        (in == TPM2_ECC_NIST_P256) ||
        (in == TPM2_ECC_NIST_P384) ||
        (in == TPM2_ECC_NIST_P521) ||
        (in == TPM2_ECC_BN_P256) ||
        (in == TPM2_ECC_BN_P638) ||
        (in == TPM2_ECC_SM2_P256))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_ECC_CURVE");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_CC.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_CC_check(
    const TPM2_CC in)
{
    if ((in == TPM2_CC_NV_UndefineSpaceSpecial) ||
        (in == TPM2_CC_EvictControl) ||
        (in == TPM2_CC_HierarchyControl) ||
        (in == TPM2_CC_NV_UndefineSpace) ||
        (in == TPM2_CC_ChangeEPS) ||
        (in == TPM2_CC_ChangePPS) ||
        (in == TPM2_CC_Clear) ||
        (in == TPM2_CC_ClearControl) ||
        (in == TPM2_CC_ClockSet) ||
        (in == TPM2_CC_HierarchyChangeAuth) ||
        (in == TPM2_CC_NV_DefineSpace) ||
        (in == TPM2_CC_PCR_Allocate) ||
        (in == TPM2_CC_PCR_SetAuthPolicy) ||
        (in == TPM2_CC_PP_Commands) ||
        (in == TPM2_CC_SetPrimaryPolicy) ||
        (in == TPM2_CC_FieldUpgradeStart) ||
        (in == TPM2_CC_ClockRateAdjust) ||
        (in == TPM2_CC_CreatePrimary) ||
        (in == TPM2_CC_NV_GlobalWriteLock) ||
        (in == TPM2_CC_GetCommandAuditDigest) ||
        (in == TPM2_CC_NV_Increment) ||
        (in == TPM2_CC_NV_SetBits) ||
        (in == TPM2_CC_NV_Extend) ||
        (in == TPM2_CC_NV_Write) ||
        (in == TPM2_CC_NV_WriteLock) ||
        (in == TPM2_CC_DictionaryAttackLockReset) ||
        (in == TPM2_CC_DictionaryAttackParameters) ||
        (in == TPM2_CC_NV_ChangeAuth) ||
        (in == TPM2_CC_PCR_Event) ||
        (in == TPM2_CC_PCR_Reset) ||
        (in == TPM2_CC_SequenceComplete) ||
        (in == TPM2_CC_SetAlgorithmSet) ||
        (in == TPM2_CC_SetCommandCodeAuditStatus) ||
        (in == TPM2_CC_FieldUpgradeData) ||
        (in == TPM2_CC_IncrementalSelfTest) ||
        (in == TPM2_CC_SelfTest) ||
        (in == TPM2_CC_Startup) ||
        (in == TPM2_CC_Shutdown) ||
        (in == TPM2_CC_StirRandom) ||
        (in == TPM2_CC_ActivateCredential) ||
        (in == TPM2_CC_Certify) ||
        (in == TPM2_CC_PolicyNV) ||
        (in == TPM2_CC_CertifyCreation) ||
        (in == TPM2_CC_Duplicate) ||
        (in == TPM2_CC_GetTime) ||
        (in == TPM2_CC_GetSessionAuditDigest) ||
        (in == TPM2_CC_NV_Read) ||
        (in == TPM2_CC_NV_ReadLock) ||
        (in == TPM2_CC_ObjectChangeAuth) ||
        (in == TPM2_CC_PolicySecret) ||
        (in == TPM2_CC_Rewrap) ||
        (in == TPM2_CC_Create) ||
        (in == TPM2_CC_ECDH_ZGen) ||
        (in == TPM2_CC_HMAC) ||
        (in == TPM2_CC_Import) ||
        (in == TPM2_CC_Load) ||
        (in == TPM2_CC_Quote) ||
        (in == TPM2_CC_RSA_Decrypt) ||
        (in == TPM2_CC_HMAC_Start) ||
        (in == TPM2_CC_SequenceUpdate) ||
        (in == TPM2_CC_Sign) ||
        (in == TPM2_CC_Unseal) ||
        (in == TPM2_CC_PolicySigned) ||
        (in == TPM2_CC_ContextLoad) ||
        (in == TPM2_CC_ContextSave) ||
        (in == TPM2_CC_ECDH_KeyGen) ||
        (in == TPM2_CC_EncryptDecrypt) ||
        (in == TPM2_CC_FlushContext) ||
        (in == TPM2_CC_LoadExternal) ||
        (in == TPM2_CC_MakeCredential) ||
        (in == TPM2_CC_NV_ReadPublic) ||
        (in == TPM2_CC_PolicyAuthorize) ||
        (in == TPM2_CC_PolicyAuthValue) ||
        (in == TPM2_CC_PolicyCommandCode) ||
        (in == TPM2_CC_PolicyCounterTimer) ||
        (in == TPM2_CC_PolicyCpHash) ||
        (in == TPM2_CC_PolicyLocality) ||
        (in == TPM2_CC_PolicyNameHash) ||
        (in == TPM2_CC_PolicyOR) ||
        (in == TPM2_CC_PolicyTicket) ||
        (in == TPM2_CC_ReadPublic) ||
        (in == TPM2_CC_RSA_Encrypt) ||
        (in == TPM2_CC_StartAuthSession) ||
        (in == TPM2_CC_VerifySignature) ||
        (in == TPM2_CC_ECC_Parameters) ||
        (in == TPM2_CC_FirmwareRead) ||
        (in == TPM2_CC_GetCapability) ||
        (in == TPM2_CC_GetRandom) ||
        (in == TPM2_CC_GetTestResult) ||
        (in == TPM2_CC_Hash) ||
        (in == TPM2_CC_PCR_Read) ||
        (in == TPM2_CC_PolicyPCR) ||
        (in == TPM2_CC_PolicyRestart) ||
        (in == TPM2_CC_ReadClock) ||
        (in == TPM2_CC_PCR_Extend) ||
        (in == TPM2_CC_PCR_SetAuthValue) ||
        (in == TPM2_CC_NV_Certify) ||
        (in == TPM2_CC_EventSequenceComplete) ||
        (in == TPM2_CC_HashSequenceStart) ||
        (in == TPM2_CC_PolicyPhysicalPresence) ||
        (in == TPM2_CC_PolicyDuplicationSelect) ||
        (in == TPM2_CC_PolicyGetDigest) ||
        (in == TPM2_CC_TestParms) ||
        (in == TPM2_CC_Commit) ||
        (in == TPM2_CC_PolicyPassword) ||
        (in == TPM2_CC_ZGen_2Phase) ||
        (in == TPM2_CC_EC_Ephemeral) ||
        (in == TPM2_CC_PolicyNvWritten) ||
        (in == TPM2_CC_PolicyTemplate) ||
        (in == TPM2_CC_CreateLoaded) ||
        (in == TPM2_CC_PolicyAuthorizeNV) ||
        (in == TPM2_CC_EncryptDecrypt2) ||
        (in == TPM2_CC_Vendor_TCG_Test))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_CC");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_CLOCK_ADJUST.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_CLOCK_ADJUST_check(
    const TPM2_CLOCK_ADJUST in)
{
    if ((in == TPM2_CLOCK_COARSE_SLOWER) ||
        (in == TPM2_CLOCK_MEDIUM_SLOWER) ||
        (in == TPM2_CLOCK_FINE_SLOWER) ||
        (in == TPM2_CLOCK_NO_CHANGE) ||
        (in == TPM2_CLOCK_FINE_FASTER) ||
        (in == TPM2_CLOCK_MEDIUM_FASTER) ||
        (in == TPM2_CLOCK_COARSE_FASTER))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_CLOCK_ADJUST");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_EO.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_EO_check(
    const TPM2_EO in)
{
    if ((in == TPM2_EO_EQ) ||
        (in == TPM2_EO_NEQ) ||
        (in == TPM2_EO_SIGNED_GT) ||
        (in == TPM2_EO_UNSIGNED_GT) ||
        (in == TPM2_EO_SIGNED_LT) ||
        (in == TPM2_EO_UNSIGNED_LT) ||
        (in == TPM2_EO_SIGNED_GE) ||
        (in == TPM2_EO_UNSIGNED_GE) ||
        (in == TPM2_EO_SIGNED_LE) ||
        (in == TPM2_EO_UNSIGNED_LE) ||
        (in == TPM2_EO_BITSET) ||
        (in == TPM2_EO_BITCLEAR))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_EO");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_ST.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_ST_check(
    const TPM2_ST in)
{
    if ((in == TPM2_ST_RSP_COMMAND) ||
        (in == TPM2_ST_NULL) ||
        (in == TPM2_ST_NO_SESSIONS) ||
        (in == TPM2_ST_SESSIONS) ||
        (in == TPM2_ST_ATTEST_NV) ||
        (in == TPM2_ST_ATTEST_COMMAND_AUDIT) ||
        (in == TPM2_ST_ATTEST_SESSION_AUDIT) ||
        (in == TPM2_ST_ATTEST_CERTIFY) ||
        (in == TPM2_ST_ATTEST_QUOTE) ||
        (in == TPM2_ST_ATTEST_TIME) ||
        (in == TPM2_ST_ATTEST_CREATION) ||
        (in == TPM2_ST_CREATION) ||
        (in == TPM2_ST_VERIFIED) ||
        (in == TPM2_ST_AUTH_SECRET) ||
        (in == TPM2_ST_HASHCHECK) ||
        (in == TPM2_ST_AUTH_SIGNED) ||
        (in == TPM2_ST_FU_MANIFEST))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_ST");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_SE.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_SE_check(
    const TPM2_SE in)
{
    if ((in == TPM2_SE_HMAC) ||
        (in == TPM2_SE_POLICY) ||
        (in == TPM2_SE_TRIAL))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_SE");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPM2_CAP.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_CAP_check(
    const TPM2_CAP in)
{
    if ((in == TPM2_CAP_ALGS) ||
        (in == TPM2_CAP_HANDLES) ||
        (in == TPM2_CAP_COMMANDS) ||
        (in == TPM2_CAP_PP_COMMANDS) ||
        (in == TPM2_CAP_AUDIT_COMMANDS) ||
        (in == TPM2_CAP_PCRS) ||
        (in == TPM2_CAP_TPM_PROPERTIES) ||
        (in == TPM2_CAP_PCR_PROPERTIES) ||
        (in == TPM2_CAP_ECC_CURVES) ||
        (in == TPM2_CAP_VENDOR_PROPERTY))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_CAP");
    return TSS2_ESYS_RC_BAD_VALUE;
}
/*** Table 26 - Definition of Types for HandlesTable 26 - Definition of Types for Handles ***/

/**
 * Check, if a variable is actually of type TPM2_RH.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_RH_check(
    const TPM2_RH in)
{
    if ((in == TPM2_RH_SRK) ||
        (in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_REVOKE) ||
        (in == TPM2_RH_TRANSPORT) ||
        (in == TPM2_RH_OPERATOR) ||
        (in == TPM2_RH_ADMIN) ||
        (in == TPM2_RH_EK) ||
        (in == TPM2_RH_NULL) ||
        (in == TPM2_RH_UNASSIGNED) ||
        (in == TPM2_RS_PW) ||
        (in == TPM2_RH_LOCKOUT) ||
        (in == TPM2_RH_ENDORSEMENT) ||
        (in == TPM2_RH_PLATFORM) ||
        (in == TPM2_RH_PLATFORM_NV) ||
        (in == TPM2_RH_AUTH_00) ||
        (in == TPM2_RH_AUTH_FF))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_RH");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_YES_NO.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_YES_NO_check(const TPMI_YES_NO in)
{
    if ((in == TPM2_NO) ||
        (in == TPM2_YES)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_YES_NO");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_DH_OBJECT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_DH_OBJECT_check(const TPMI_DH_OBJECT in)
{
    if ((in >= (UINT32)TPM2_TRANSIENT_FIRST && in <= (UINT32)TPM2_TRANSIENT_LAST) ||
        (in >= (UINT32)TPM2_PERSISTENT_FIRST && in <= (UINT32)TPM2_PERSISTENT_LAST) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_DH_OBJECT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_DH_PERSISTENT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_DH_PERSISTENT_check(const TPMI_DH_PERSISTENT in)
{
    if ((in >= (UINT32)TPM2_PERSISTENT_FIRST && in <= (UINT32)TPM2_PERSISTENT_LAST)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_DH_PERSISTENT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_DH_ENTITY.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_DH_ENTITY_check(const TPMI_DH_ENTITY in)
{
    if ((in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_ENDORSEMENT) ||
        (in == TPM2_RH_PLATFORM) ||
        (in == TPM2_RH_LOCKOUT) ||
        (in >= (UINT32)TPM2_TRANSIENT_FIRST && in <= (UINT32)TPM2_TRANSIENT_LAST) ||
        (in >= (UINT32)TPM2_PERSISTENT_FIRST && in <= (UINT32)TPM2_PERSISTENT_LAST) ||
        (in >= TPM2_NV_INDEX_FIRST && in <= TPM2_NV_INDEX_LAST) ||
        (in <= TPM2_PCR_LAST) ||
        (in >= TPM2_RH_AUTH_00 && in <= TPM2_RH_AUTH_FF) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_DH_ENTITY");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_DH_PCR.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_DH_PCR_check(const TPMI_DH_PCR in)
{
    if ((in <= TPM2_PCR_LAST) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_DH_PCR");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_SH_AUTH_SESSION.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_SH_AUTH_SESSION_check(const TPMI_SH_AUTH_SESSION in)
{
    if ((in >= TPM2_HMAC_SESSION_FIRST && in <= TPM2_HMAC_SESSION_LAST) ||
        (in >= TPM2_POLICY_SESSION_FIRST && in <= TPM2_POLICY_SESSION_LAST) ||
        (in == TPM2_RS_PW)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_SH_AUTH_SESSION");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_SH_HMAC.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_SH_HMAC_check(const TPMI_SH_HMAC in)
{
    if ((in >= TPM2_HMAC_SESSION_FIRST && in <= TPM2_HMAC_SESSION_LAST)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_SH_HMAC");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_SH_POLICY.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_SH_POLICY_check(const TPMI_SH_POLICY in)
{
    if ((in >= TPM2_POLICY_SESSION_FIRST && in <= TPM2_POLICY_SESSION_LAST)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_SH_POLICY");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_DH_CONTEXT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_DH_CONTEXT_check(const TPMI_DH_CONTEXT in)
{
    if ((in >= TPM2_HMAC_SESSION_FIRST && in <= TPM2_HMAC_SESSION_LAST) ||
        (in >= TPM2_POLICY_SESSION_FIRST && in <= TPM2_POLICY_SESSION_LAST) ||
        (in >= (UINT32)TPM2_TRANSIENT_FIRST && in <= (UINT32)TPM2_TRANSIENT_LAST)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_DH_CONTEXT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_HIERARCHY.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_HIERARCHY_check(const TPMI_RH_HIERARCHY in)
{
    if ((in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_PLATFORM) ||
        (in == TPM2_RH_ENDORSEMENT) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_HIERARCHY");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_ENABLES.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_ENABLES_check(const TPMI_RH_ENABLES in)
{
    if ((in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_PLATFORM) ||
        (in == TPM2_RH_ENDORSEMENT) ||
        (in == TPM2_RH_PLATFORM_NV) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_ENABLES");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_HIERARCHY_AUTH.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_HIERARCHY_AUTH_check(const TPMI_RH_HIERARCHY_AUTH in)
{
    if ((in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_PLATFORM) ||
        (in == TPM2_RH_ENDORSEMENT) ||
        (in == TPM2_RH_LOCKOUT)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_HIERARCHY_AUTH");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_PLATFORM.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_PLATFORM_check(const TPMI_RH_PLATFORM in)
{
    if ((in == TPM2_RH_PLATFORM)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_PLATFORM");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_OWNER.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_OWNER_check(const TPMI_RH_OWNER in)
{
    if ((in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_OWNER");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_ENDORSEMENT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_ENDORSEMENT_check(const TPMI_RH_ENDORSEMENT in)
{
    if ((in == TPM2_RH_ENDORSEMENT) ||
        (in == TPM2_RH_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_ENDORSEMENT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_PROVISION.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_PROVISION_check(const TPMI_RH_PROVISION in)
{
    if ((in == TPM2_RH_OWNER) ||
        (in == TPM2_RH_PLATFORM)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_PROVISION");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_CLEAR.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_CLEAR_check(const TPMI_RH_CLEAR in)
{
    if ((in == TPM2_RH_LOCKOUT) ||
        (in == TPM2_RH_PLATFORM)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_CLEAR");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_NV_AUTH.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_NV_AUTH_check(const TPMI_RH_NV_AUTH in)
{
    if ((in == TPM2_RH_PLATFORM) ||
        (in == TPM2_RH_OWNER) ||
        (in >= TPM2_NV_INDEX_FIRST && in <= TPM2_NV_INDEX_LAST)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_NV_AUTH");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_LOCKOUT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_LOCKOUT_check(const TPMI_RH_LOCKOUT in)
{
    if ((in == TPM2_RH_LOCKOUT)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_LOCKOUT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_RH_NV_INDEX.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RH_NV_INDEX_check(const TPMI_RH_NV_INDEX in)
{
    if ((in >= TPM2_NV_INDEX_FIRST && in <= TPM2_NV_INDEX_LAST)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RH_NV_INDEX");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_HASH.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_HASH_check(const TPMI_ALG_HASH in)
{
    if ((in == TPM2_ALG_SHA1) ||
        (in == TPM2_ALG_SHA256) ||
        (in == TPM2_ALG_SHA384) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_HASH");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_ASYM.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_ASYM_check(const TPMI_ALG_ASYM in)
{
    if ((in == TPM2_ALG_RSA) ||
        (in == TPM2_ALG_ECC) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_ASYM");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_SYM.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_SYM_check(const TPMI_ALG_SYM in)
{
    if ((in == TPM2_ALG_AES) ||
        (in == TPM2_ALG_XOR) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_SYM");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_SYM_OBJECT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_SYM_OBJECT_check(const TPMI_ALG_SYM_OBJECT in)
{
    if ((in == TPM2_ALG_AES) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_SYM_OBJECT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_SYM_MODE.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_SYM_MODE_check(const TPMI_ALG_SYM_MODE in)
{
    if ((in == TPM2_ALG_CTR) ||
        (in == TPM2_ALG_OFB) ||
        (in == TPM2_ALG_CBC) ||
        (in == TPM2_ALG_CFB) ||
        (in == TPM2_ALG_ECB) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_SYM_MODE");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_KDF.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_KDF_check(const TPMI_ALG_KDF in)
{
    if ((in == TPM2_ALG_MGF1) ||
        (in == TPM2_ALG_KDF1_SP800_56A) ||
        (in == TPM2_ALG_KDF1_SP800_108) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_KDF");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_SIG_SCHEME.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_SIG_SCHEME_check(const TPMI_ALG_SIG_SCHEME in)
{
    if ((in == TPM2_ALG_RSASSA) ||
        (in == TPM2_ALG_RSAPSS) ||
        (in == TPM2_ALG_ECDSA) ||
        (in == TPM2_ALG_ECDAA) ||
        (in == TPM2_ALG_SM2) ||
        (in == TPM2_ALG_ECSCHNORR) ||
        (in == TPM2_ALG_HMAC) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_SIG_SCHEME");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ECC_KEY_EXCHANGE.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ECC_KEY_EXCHANGE_check(const TPMI_ECC_KEY_EXCHANGE in)
{
    if ((in == TPM2_ALG_ECDH) ||
        (in == TPM2_ALG_SM2) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ECC_KEY_EXCHANGE");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ST_COMMAND_TAG.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ST_COMMAND_TAG_check(const TPMI_ST_COMMAND_TAG in)
{
    if ((in == TPM2_ST_NO_SESSIONS) ||
        (in == TPM2_ST_SESSIONS)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ST_COMMAND_TAG");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMS_ALGORITHM_DESCRIPTION.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ALGORITHM_DESCRIPTION_check(const TPMS_ALGORITHM_DESCRIPTION *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2_ALG_ID_check ((in == NULL)? 0 : in->alg);
    return_if_error(ret, "Bad Value for TPM2_ALG_ID");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMU_HA.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_HA_check(const TPMU_HA *in, UINT32 selector)
{
    (void)in;
    switch (selector) {
        case TPM2_ALG_SHA1:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_SHA256:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_SHA384:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_HA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_HA_check(const TPMT_HA *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hashAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    ret = iesys_TPMU_HA_check (&in->digest, in->hashAlg);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_DIGEST.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_DIGEST_check(const TPM2B_DIGEST *in)
{
    if (in != NULL && in->size > sizeof(TPMU_HA)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMU_HA));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_DATA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_DATA_check(const TPM2B_DATA *in)
{
    if (in != NULL && in->size > sizeof(TPMT_HA)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMT_HA));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}
/*** Table 75 - Definition of Types for TPM2B_NONCETable 75 - Definition of Types for TPM2B_NONCE ***/

/**
 * Check, if a variable is actually TPM2B_NONCE.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_NONCE_check(const TPM2B_NONCE *in)
{
    return iesys_TPM2B_DIGEST_check(in);
}
/*** Table 76 - Definition of Types for TPM2B_AUTHTable 76 - Definition of Types for TPM2B_AUTH ***/

/**
 * Check, if a variable is actually TPM2B_AUTH.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_AUTH_check(const TPM2B_AUTH *in)
{
    return iesys_TPM2B_DIGEST_check(in);
}
/*** Table 77 - Definition of Types for TPM2B_OPERANDTable 77 - Definition of Types for TPM2B_OPERAND ***/

/**
 * Check, if a variable is actually TPM2B_OPERAND.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_OPERAND_check(const TPM2B_OPERAND *in)
{
    return iesys_TPM2B_DIGEST_check(in);
}

/**
 * Check, if a variable is actually TPM2B_EVENT.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_EVENT_check(const TPM2B_EVENT *in)
{
    if (in != NULL && in->size > 1024) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)1024);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_MAX_BUFFER.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_MAX_BUFFER_check(const TPM2B_MAX_BUFFER *in)
{
    if (in != NULL && in->size > TPM2_MAX_DIGEST_BUFFER) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_DIGEST_BUFFER);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_MAX_NV_BUFFER.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_MAX_NV_BUFFER_check(const TPM2B_MAX_NV_BUFFER *in)
{
    if (in != NULL && in->size > TPM2_MAX_NV_BUFFER_SIZE) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_NV_BUFFER_SIZE);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}
/*** Table 81 - Definition of Types for TPM2B_TIMEOUTTable 81 - Definition of Types for TPM2B_TIMEOUT ***/

/**
 * Check, if a variable is actually TPM2B_TIMEOUT.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_TIMEOUT_check(const TPM2B_TIMEOUT *in)
{
    return iesys_TPM2B_DIGEST_check(in);
}

/**
 * Check, if a variable is actually TPM2B_IV.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_IV_check(const TPM2B_IV *in)
{
    if (in != NULL && in->size > TPM2_MAX_SYM_BLOCK_SIZE) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_SYM_BLOCK_SIZE);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMU_NAME variable.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_NAME_check(const TPMU_NAME *in,
    UINT32 selector)
{
    switch (selector) {
        case 4:
            return TSS2_RC_SUCCESS;
        default:
            return iesys_TPMT_HA_check (&in->digest);
    };
}

/**
 * Check, if a variable is actually TPM2B_NAME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_NAME_check(const TPM2B_NAME *in)
{
    if (in != NULL && in->size > sizeof(TPMU_NAME)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMU_NAME));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_PCR_SELECTION.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_PCR_SELECTION_check(const TPMS_PCR_SELECTION *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hash);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    if (in != NULL && in->sizeofSelect > TPM2_PCR_SELECT_MAX) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->sizeofSelect,(size_t)TPM2_PCR_SELECT_MAX);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMT_TK_CREATION.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_TK_CREATION_check(const TPMT_TK_CREATION *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    if (in != NULL && in->tag != TPM2_ST_CREATION) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->tag,(size_t)TPM2_ST_CREATION);
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    ret = iesys_TPM2_ST_check ((in == NULL)? 0 : in->tag);
    return_if_error(ret, "Bad Value for TPM2_ST");

    ret = iesys_TPMI_RH_HIERARCHY_check ((in == NULL)? 0 : in->hierarchy);
    return_if_error(ret, "Bad Value for TPMI_RH_HIERARCHY");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->digest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMT_TK_VERIFIED.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_TK_VERIFIED_check(const TPMT_TK_VERIFIED *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    if (in != NULL && in->tag != TPM2_ST_VERIFIED) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->tag,(size_t)TPM2_ST_VERIFIED);
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    ret = iesys_TPM2_ST_check ((in == NULL)? 0 : in->tag);
    return_if_error(ret, "Bad Value for TPM2_ST");

    ret = iesys_TPMI_RH_HIERARCHY_check ((in == NULL)? 0 : in->hierarchy);
    return_if_error(ret, "Bad Value for TPMI_RH_HIERARCHY");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->digest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMT_TK_AUTH.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_TK_AUTH_check(const TPMT_TK_AUTH *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2_ST_check ((in == NULL)? 0 : in->tag);
    return_if_error(ret, "Bad Value for TPM2_ST");

    ret = iesys_TPMI_RH_HIERARCHY_check ((in == NULL)? 0 : in->hierarchy);
    return_if_error(ret, "Bad Value for TPMI_RH_HIERARCHY");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->digest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMT_TK_HASHCHECK.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_TK_HASHCHECK_check(const TPMT_TK_HASHCHECK *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    if (in != NULL && in->tag != TPM2_ST_HASHCHECK) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->tag,(size_t)TPM2_ST_HASHCHECK);
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    ret = iesys_TPM2_ST_check ((in == NULL)? 0 : in->tag);
    return_if_error(ret, "Bad Value for TPM2_ST");

    ret = iesys_TPMI_RH_HIERARCHY_check ((in == NULL)? 0 : in->hierarchy);
    return_if_error(ret, "Bad Value for TPMI_RH_HIERARCHY");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->digest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_ALG_PROPERTY.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ALG_PROPERTY_check(const TPMS_ALG_PROPERTY *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2_ALG_ID_check ((in == NULL)? 0 : in->alg);
    return_if_error(ret, "Bad Value for TPM2_ALG_ID");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_CC.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_CC_check(const TPML_CC *in)
{
    if (in != NULL && in->count > TPM2_MAX_CAP_CC) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_MAX_CAP_CC);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_CCA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_CCA_check(const TPML_CCA *in)
{
    if (in != NULL && in->count > TPM2_MAX_CAP_CC) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_MAX_CAP_CC);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_ALG.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_ALG_check(const TPML_ALG *in)
{
    if (in != NULL && in->count > TPM2_MAX_ALG_LIST_SIZE) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_MAX_ALG_LIST_SIZE);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_HANDLE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_HANDLE_check(const TPML_HANDLE *in)
{
    if (in != NULL && in->count > TPM2_MAX_CAP_HANDLES) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_MAX_CAP_HANDLES);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_DIGEST.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_DIGEST_check(const TPML_DIGEST *in)
{
    if (in != NULL && in->count > 8) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)8);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_DIGEST_VALUES.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_DIGEST_VALUES_check(const TPML_DIGEST_VALUES *in)
{
    if (in != NULL && in->count > TPM2_NUM_PCR_BANKS) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_NUM_PCR_BANKS);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_PCR_SELECTION.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_PCR_SELECTION_check(const TPML_PCR_SELECTION *in)
{
    if (in != NULL && in->count > TPM2_NUM_PCR_BANKS) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_NUM_PCR_BANKS);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_ALG_PROPERTY.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_ALG_PROPERTY_check(const TPML_ALG_PROPERTY *in)
{
    if (in != NULL && in->count > TPM2_MAX_CAP_ALGS) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_MAX_CAP_ALGS);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPML_ECC_CURVE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPML_ECC_CURVE_check(const TPML_ECC_CURVE *in)
{
    if (in != NULL && in->count > TPM2_MAX_ECC_CURVES) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->count,(size_t)TPM2_MAX_ECC_CURVES);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_CLOCK_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_CLOCK_INFO_check(const TPMS_CLOCK_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_YES_NO_check ((in == NULL)? 0 : in->safe);
    return_if_error(ret, "Bad Value for TPMI_YES_NO");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_TIME_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_TIME_INFO_check(const TPMS_TIME_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMS_CLOCK_INFO_check ((in == NULL)? NULL : &in->clockInfo);
    return_if_error(ret, "Bad Value for TPMS_CLOCK_INFO");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_TIME_ATTEST_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_TIME_ATTEST_INFO_check(const TPMS_TIME_ATTEST_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMS_TIME_INFO_check ((in == NULL)? NULL : &in->time);
    return_if_error(ret, "Bad Value for TPMS_TIME_INFO");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_CERTIFY_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_CERTIFY_INFO_check(const TPMS_CERTIFY_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->name);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->qualifiedName);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_QUOTE_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_QUOTE_INFO_check(const TPMS_QUOTE_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPML_PCR_SELECTION_check ((in == NULL)? NULL : &in->pcrSelect);
    return_if_error(ret, "Bad Value for TPML_PCR_SELECTION");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->pcrDigest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_COMMAND_AUDIT_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_COMMAND_AUDIT_INFO_check(const TPMS_COMMAND_AUDIT_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2_ALG_ID_check ((in == NULL)? 0 : in->digestAlg);
    return_if_error(ret, "Bad Value for TPM2_ALG_ID");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->auditDigest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->commandDigest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_SESSION_AUDIT_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SESSION_AUDIT_INFO_check(const TPMS_SESSION_AUDIT_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_YES_NO_check ((in == NULL)? 0 : in->exclusiveSession);
    return_if_error(ret, "Bad Value for TPMI_YES_NO");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->sessionDigest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_CREATION_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_CREATION_INFO_check(const TPMS_CREATION_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->objectName);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->creationHash);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_NV_CERTIFY_INFO.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_NV_CERTIFY_INFO_check(const TPMS_NV_CERTIFY_INFO *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->indexName);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    ret = iesys_TPM2B_MAX_NV_BUFFER_check ((in == NULL)? NULL : &in->nvContents);
    return_if_error(ret, "Bad Value for TPM2B_MAX_NV_BUFFER");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ST_ATTEST.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ST_ATTEST_check(const TPMI_ST_ATTEST in)
{
    if ((in == TPM2_ST_ATTEST_CERTIFY) ||
        (in == TPM2_ST_ATTEST_QUOTE) ||
        (in == TPM2_ST_ATTEST_SESSION_AUDIT) ||
        (in == TPM2_ST_ATTEST_COMMAND_AUDIT) ||
        (in == TPM2_ST_ATTEST_TIME) ||
        (in == TPM2_ST_ATTEST_CREATION) ||
        (in == TPM2_ST_ATTEST_NV)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ST_ATTEST");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMU_ATTEST.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_ATTEST_check(const TPMU_ATTEST *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ST_ATTEST_CERTIFY:
            return iesys_TPMS_CERTIFY_INFO_check (&in->certify);
        case TPM2_ST_ATTEST_CREATION:
            return iesys_TPMS_CREATION_INFO_check (&in->creation);
        case TPM2_ST_ATTEST_QUOTE:
            return iesys_TPMS_QUOTE_INFO_check (&in->quote);
        case TPM2_ST_ATTEST_COMMAND_AUDIT:
            return iesys_TPMS_COMMAND_AUDIT_INFO_check (&in->commandAudit);
        case TPM2_ST_ATTEST_SESSION_AUDIT:
            return iesys_TPMS_SESSION_AUDIT_INFO_check (&in->sessionAudit);
        case TPM2_ST_ATTEST_TIME:
            return iesys_TPMS_TIME_ATTEST_INFO_check (&in->time);
        case TPM2_ST_ATTEST_NV:
            return iesys_TPMS_NV_CERTIFY_INFO_check (&in->nv);
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMS_ATTEST.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ATTEST_check(const TPMS_ATTEST *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ST_ATTEST_check ((in == NULL)? 0 : in->type);
    return_if_error(ret, "Bad Value for TPMI_ST_ATTEST");

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->qualifiedSigner);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    ret = iesys_TPM2B_DATA_check ((in == NULL)? NULL : &in->extraData);
    return_if_error(ret, "Bad Value for TPM2B_DATA");

    ret = iesys_TPMS_CLOCK_INFO_check ((in == NULL)? NULL : &in->clockInfo);
    return_if_error(ret, "Bad Value for TPMS_CLOCK_INFO");

    ret = iesys_TPMU_ATTEST_check (&in->attested, in->type);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_ATTEST.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_ATTEST_check(const TPM2B_ATTEST *in)
{
    if (in != NULL && in->size > sizeof(TPMS_ATTEST)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMS_ATTEST));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_AUTH_COMMAND.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_AUTH_COMMAND_check(const TPMS_AUTH_COMMAND *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_SH_AUTH_SESSION_check ((in == NULL)? 0 : in->sessionHandle);
    return_if_error(ret, "Bad Value for TPMI_SH_AUTH_SESSION");

    ret = iesys_TPM2B_NONCE_check ((in == NULL)? NULL : &in->nonce);
    return_if_error(ret, "Bad Value for TPM2B_NONCE");

    ret = iesys_TPM2B_AUTH_check ((in == NULL)? NULL : &in->hmac);
    return_if_error(ret, "Bad Value for TPM2B_AUTH");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_AUTH_RESPONSE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_AUTH_RESPONSE_check(const TPMS_AUTH_RESPONSE *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_NONCE_check ((in == NULL)? NULL : &in->nonce);
    return_if_error(ret, "Bad Value for TPM2B_NONCE");

    ret = iesys_TPM2B_AUTH_check ((in == NULL)? NULL : &in->hmac);
    return_if_error(ret, "Bad Value for TPM2B_AUTH");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_AES_KEY_BITS.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_AES_KEY_BITS_check(const TPMI_AES_KEY_BITS in)
{
    if ((in == 128) ||
        (in == 192) ||
        (in == 256)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_AES_KEY_BITS");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMU_SYM_KEY_BITS.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_SYM_KEY_BITS_check(const TPMU_SYM_KEY_BITS *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_AES:
            return iesys_TPMI_AES_KEY_BITS_check (in->aes);
        case TPM2_ALG_XOR:
            return iesys_TPMI_ALG_HASH_check (in->exclusiveOr);
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMU_SYM_MODE.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_SYM_MODE_check(const TPMU_SYM_MODE *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_AES:
            return iesys_TPMI_ALG_SYM_MODE_check (in->aes);
        case TPM2_ALG_XOR:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_SYM_DEF.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_SYM_DEF_check(const TPMT_SYM_DEF *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_SYM_check ((in == NULL)? 0 : in->algorithm);
    return_if_error(ret, "Bad Value for TPMI_ALG_SYM");

    ret = iesys_TPMU_SYM_KEY_BITS_check (&in->keyBits, in->algorithm);
    return_if_error(ret, "Bad value");

    ret = iesys_TPMU_SYM_MODE_check (&in->mode, in->algorithm);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMT_SYM_DEF_OBJECT.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_SYM_DEF_OBJECT_check(const TPMT_SYM_DEF_OBJECT *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_SYM_OBJECT_check ((in == NULL)? 0 : in->algorithm);
    return_if_error(ret, "Bad Value for TPMI_ALG_SYM_OBJECT");

    ret = iesys_TPMU_SYM_KEY_BITS_check (&in->keyBits, in->algorithm);
    return_if_error(ret, "Bad value");

    ret = iesys_TPMU_SYM_MODE_check (&in->mode, in->algorithm);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_SYM_KEY.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_SYM_KEY_check(const TPM2B_SYM_KEY *in)
{
    if (in != NULL && in->size > TPM2_MAX_SYM_KEY_BYTES) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_SYM_KEY_BYTES);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_SYMCIPHER_PARMS.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SYMCIPHER_PARMS_check(const TPMS_SYMCIPHER_PARMS *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_SYM_DEF_OBJECT_check ((in == NULL)? NULL : &in->sym);
    return_if_error(ret, "Bad Value for TPMT_SYM_DEF_OBJECT");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_SENSITIVE_DATA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_SENSITIVE_DATA_check(const TPM2B_SENSITIVE_DATA *in)
{
    if (in != NULL && in->size > TPM2_MAX_SYM_DATA) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_SYM_DATA);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_SENSITIVE_CREATE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SENSITIVE_CREATE_check(const TPMS_SENSITIVE_CREATE *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_AUTH_check ((in == NULL)? NULL : &in->userAuth);
    return_if_error(ret, "Bad Value for TPM2B_AUTH");

    ret = iesys_TPM2B_SENSITIVE_DATA_check ((in == NULL)? NULL : &in->data);
    return_if_error(ret, "Bad Value for TPM2B_SENSITIVE_DATA");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_SENSITIVE_CREATE.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_SENSITIVE_CREATE_check(const TPM2B_SENSITIVE_CREATE *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMS_SENSITIVE_CREATE_check ((in == NULL)? NULL : &in->sensitive);
    return_if_error(ret, "Bad Value for TPMS_SENSITIVE_CREATE");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_SCHEME_HASH.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_HASH_check(const TPMS_SCHEME_HASH *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hashAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_SCHEME_ECDAA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_ECDAA_check(const TPMS_SCHEME_ECDAA *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hashAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_KEYEDHASH_SCHEME.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_KEYEDHASH_SCHEME_check(const TPMI_ALG_KEYEDHASH_SCHEME in)
{
    if ((in == TPM2_ALG_HMAC) ||
        (in == TPM2_ALG_XOR) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_KEYEDHASH_SCHEME");
    return TSS2_ESYS_RC_BAD_VALUE;
}
/*** Table 144 - Definition of Types for HMAC_SIG_SCHEMETable 144 - Definition of Types for HMAC_SIG_SCHEME ***/

/**
 * Check, if a variable is actually TPMS_SCHEME_HMAC.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_HMAC_check(const TPMS_SCHEME_HMAC *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SCHEME_XOR.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_XOR_check(const TPMS_SCHEME_XOR *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hashAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    ret = iesys_TPMI_ALG_KDF_check ((in == NULL)? 0 : in->kdf);
    return_if_error(ret, "Bad Value for TPMI_ALG_KDF");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMU_SCHEME_KEYEDHASH.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_SCHEME_KEYEDHASH_check(const TPMU_SCHEME_KEYEDHASH *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_HMAC:
            return iesys_TPMS_SCHEME_HMAC_check (&in->hmac);
        case TPM2_ALG_XOR:
            return iesys_TPMS_SCHEME_XOR_check (&in->exclusiveOr);
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_KEYEDHASH_SCHEME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_KEYEDHASH_SCHEME_check(const TPMT_KEYEDHASH_SCHEME *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_KEYEDHASH_SCHEME_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_KEYEDHASH_SCHEME");

    ret = iesys_TPMU_SCHEME_KEYEDHASH_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}
/*** Table 148 - Definition of Table 148 - Definition of  Types for RSA Signature Schemes ***/

/**
 * Check, if a variable is actually TPMS_SIG_SCHEME_RSASSA.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIG_SCHEME_RSASSA_check(const TPMS_SIG_SCHEME_RSASSA *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIG_SCHEME_RSAPSS.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIG_SCHEME_RSAPSS_check(const TPMS_SIG_SCHEME_RSAPSS *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}
/*** Table 149 - Definition of Table 149 - Definition of  Types for ECC Signature Schemes ***/

/**
 * Check, if a variable is actually TPMS_SIG_SCHEME_ECDSA.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIG_SCHEME_ECDSA_check(const TPMS_SIG_SCHEME_ECDSA *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIG_SCHEME_SM2.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIG_SCHEME_SM2_check(const TPMS_SIG_SCHEME_SM2 *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIG_SCHEME_ECSCHNORR.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIG_SCHEME_ECSCHNORR_check(const TPMS_SIG_SCHEME_ECSCHNORR *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIG_SCHEME_ECDAA.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIG_SCHEME_ECDAA_check(const TPMS_SIG_SCHEME_ECDAA *in)
{
    return iesys_TPMS_SCHEME_ECDAA_check(in);
}

/**
 * Check, if a variable is actually TPMU_SIG_SCHEME.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_SIG_SCHEME_check(const TPMU_SIG_SCHEME *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_RSASSA:
            return iesys_TPMS_SIG_SCHEME_RSASSA_check (&in->rsassa);
        case TPM2_ALG_RSAPSS:
            return iesys_TPMS_SIG_SCHEME_RSAPSS_check (&in->rsapss);
        case TPM2_ALG_ECDSA:
            return iesys_TPMS_SIG_SCHEME_ECDSA_check (&in->ecdsa);
        case TPM2_ALG_ECDAA:
            return iesys_TPMS_SIG_SCHEME_ECDAA_check (&in->ecdaa);
        case TPM2_ALG_SM2:
            return iesys_TPMS_SIG_SCHEME_SM2_check (&in->sm2);
        case TPM2_ALG_ECSCHNORR:
            return iesys_TPMS_SIG_SCHEME_ECSCHNORR_check (&in->ecschnorr);
        case TPM2_ALG_HMAC:
            return iesys_TPMS_SCHEME_HMAC_check (&in->hmac);
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_SIG_SCHEME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_SIG_SCHEME_check(const TPMT_SIG_SCHEME *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_SIG_SCHEME_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_SIG_SCHEME");

    ret = iesys_TPMU_SIG_SCHEME_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}
/*** Table 152 - Definition of Types for Table 152 - Definition of Types for  Encryption Schemes ***/

/**
 * Check, if a variable is actually TPMS_ENC_SCHEME_OAEP.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ENC_SCHEME_OAEP_check(const TPMS_ENC_SCHEME_OAEP *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_ENC_SCHEME_RSAES.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ENC_SCHEME_RSAES_check(const TPMS_ENC_SCHEME_RSAES *in)
{
    (void)in;
    return TSS2_RC_SUCCESS;
}
/*** Table 153 - Definition of Types for Table 153 - Definition of Types for  ECC Key Exchange ***/

/**
 * Check, if a variable is actually TPMS_KEY_SCHEME_ECDH.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_KEY_SCHEME_ECDH_check(const TPMS_KEY_SCHEME_ECDH *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}
/*** Table 154 - Definition of Types for KDF SchemesTable 154 - Definition of Types for KDF Schemes ***/

/**
 * Check, if a variable is actually TPMS_SCHEME_MGF1.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_MGF1_check(const TPMS_SCHEME_MGF1 *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SCHEME_KDF1_SP800_56A.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_KDF1_SP800_56A_check(const TPMS_SCHEME_KDF1_SP800_56A *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMS_SCHEME_KDF1_SP800_108.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SCHEME_KDF1_SP800_108_check(const TPMS_SCHEME_KDF1_SP800_108 *in)
{
    return iesys_TPMS_SCHEME_HASH_check(in);
}

/**
 * Check, if a variable is actually TPMU_KDF_SCHEME.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_KDF_SCHEME_check(const TPMU_KDF_SCHEME *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_MGF1:
            return iesys_TPMS_SCHEME_MGF1_check (&in->mgf1);
        case TPM2_ALG_KDF1_SP800_56A:
            return iesys_TPMS_SCHEME_KDF1_SP800_56A_check (&in->kdf1_sp800_56a);
        case TPM2_ALG_KDF1_SP800_108:
            return iesys_TPMS_SCHEME_KDF1_SP800_108_check (&in->kdf1_sp800_108);
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_KDF_SCHEME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_KDF_SCHEME_check(const TPMT_KDF_SCHEME *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_KDF_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_KDF");

    ret = iesys_TPMU_KDF_SCHEME_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_ASYM_SCHEME.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_ASYM_SCHEME_check(const TPMI_ALG_ASYM_SCHEME in)
{
    if ((in == TPM2_ALG_ECDH) ||
        (in == TPM2_ALG_RSASSA) ||
        (in == TPM2_ALG_RSAPSS) ||
        (in == TPM2_ALG_ECDSA) ||
        (in == TPM2_ALG_ECDAA) ||
        (in == TPM2_ALG_SM2) ||
        (in == TPM2_ALG_ECSCHNORR) ||
        (in == TPM2_ALG_RSAES) ||
        (in == TPM2_ALG_OAEP) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_ASYM_SCHEME");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMU_ASYM_SCHEME.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_ASYM_SCHEME_check(const TPMU_ASYM_SCHEME *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_ECDH:
            return iesys_TPMS_KEY_SCHEME_ECDH_check (&in->ecdh);
        case TPM2_ALG_RSASSA:
            return iesys_TPMS_SIG_SCHEME_RSASSA_check (&in->rsassa);
        case TPM2_ALG_RSAPSS:
            return iesys_TPMS_SIG_SCHEME_RSAPSS_check (&in->rsapss);
        case TPM2_ALG_ECDSA:
            return iesys_TPMS_SIG_SCHEME_ECDSA_check (&in->ecdsa);
        case TPM2_ALG_ECDAA:
            return iesys_TPMS_SIG_SCHEME_ECDAA_check (&in->ecdaa);
        case TPM2_ALG_SM2:
            return iesys_TPMS_SIG_SCHEME_SM2_check (&in->sm2);
        case TPM2_ALG_ECSCHNORR:
            return iesys_TPMS_SIG_SCHEME_ECSCHNORR_check (&in->ecschnorr);
        case TPM2_ALG_RSAES:
            return iesys_TPMS_ENC_SCHEME_RSAES_check (&in->rsaes);
        case TPM2_ALG_OAEP:
            return iesys_TPMS_ENC_SCHEME_OAEP_check (&in->oaep);
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_ASYM_SCHEME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_ASYM_SCHEME_check(const TPMT_ASYM_SCHEME *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_ASYM_SCHEME_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_ASYM_SCHEME");

    ret = iesys_TPMU_ASYM_SCHEME_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_RSA_SCHEME.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_RSA_SCHEME_check(const TPMI_ALG_RSA_SCHEME in)
{
    if ((in == TPM2_ALG_RSAES) ||
        (in == TPM2_ALG_OAEP) ||
        (in == TPM2_ALG_RSASSA) ||
        (in == TPM2_ALG_RSAPSS) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_RSA_SCHEME");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMT_RSA_SCHEME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_RSA_SCHEME_check(const TPMT_RSA_SCHEME *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_RSA_SCHEME_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_RSA_SCHEME");

    ret = iesys_TPMU_ASYM_SCHEME_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_RSA_DECRYPT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_RSA_DECRYPT_check(const TPMI_ALG_RSA_DECRYPT in)
{
    if ((in == TPM2_ALG_RSAES) ||
        (in == TPM2_ALG_OAEP) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_RSA_DECRYPT");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMT_RSA_DECRYPT.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_RSA_DECRYPT_check(const TPMT_RSA_DECRYPT *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_RSA_DECRYPT_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_RSA_DECRYPT");

    ret = iesys_TPMU_ASYM_SCHEME_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_PUBLIC_KEY_RSA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_PUBLIC_KEY_RSA_check(const TPM2B_PUBLIC_KEY_RSA *in)
{
    if (in != NULL && in->size > TPM2_MAX_RSA_KEY_BYTES) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_RSA_KEY_BYTES);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_RSA_KEY_BITS.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_RSA_KEY_BITS_check(const TPMI_RSA_KEY_BITS in)
{
    if ((in == 1024) ||
        (in == 2048)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_RSA_KEY_BITS");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPM2B_PRIVATE_KEY_RSA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_PRIVATE_KEY_RSA_check(const TPM2B_PRIVATE_KEY_RSA *in)
{
    if (in != NULL && in->size > TPM2_MAX_RSA_KEY_BYTES/2) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_RSA_KEY_BYTES/2);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_ECC_PARAMETER.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_ECC_PARAMETER_check(const TPM2B_ECC_PARAMETER *in)
{
    if (in != NULL && in->size > TPM2_MAX_ECC_KEY_BYTES) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_ECC_KEY_BYTES);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_ECC_POINT.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ECC_POINT_check(const TPMS_ECC_POINT *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->x);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->y);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_ECC_POINT.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_ECC_POINT_check(const TPM2B_ECC_POINT *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMS_ECC_POINT_check ((in == NULL)? NULL : &in->point);
    return_if_error(ret, "Bad Value for TPMS_ECC_POINT");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_ECC_SCHEME.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_ECC_SCHEME_check(const TPMI_ALG_ECC_SCHEME in)
{
    if ((in == TPM2_ALG_ECDSA) ||
        (in == TPM2_ALG_ECDAA) ||
        (in == TPM2_ALG_SM2) ||
        (in == TPM2_ALG_ECSCHNORR) ||
        (in == TPM2_ALG_ECDH) ||
        (in == TPM2_ALG_NULL)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_ECC_SCHEME");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually of type TPMI_ECC_CURVE.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ECC_CURVE_check(const TPMI_ECC_CURVE in)
{
    if ((in == TPM2_ECC_BN_P256) ||
        (in == TPM2_ECC_NIST_P256) ||
        (in == TPM2_ECC_NIST_P384)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ECC_CURVE");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMT_ECC_SCHEME.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_ECC_SCHEME_check(const TPMT_ECC_SCHEME *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_ECC_SCHEME_check ((in == NULL)? 0 : in->scheme);
    return_if_error(ret, "Bad Value for TPMI_ALG_ECC_SCHEME");

    ret = iesys_TPMU_ASYM_SCHEME_check (&in->details, in->scheme);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_ALGORITHM_DETAIL_ECC.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ALGORITHM_DETAIL_ECC_check(const TPMS_ALGORITHM_DETAIL_ECC *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2_ECC_CURVE_check ((in == NULL)? 0 : in->curveID);
    return_if_error(ret, "Bad Value for TPM2_ECC_CURVE");

    ret = iesys_TPMT_KDF_SCHEME_check ((in == NULL)? NULL : &in->kdf);
    return_if_error(ret, "Bad Value for TPMT_KDF_SCHEME");

    ret = iesys_TPMT_ECC_SCHEME_check ((in == NULL)? NULL : &in->sign);
    return_if_error(ret, "Bad Value for TPMT_ECC_SCHEME");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->p);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->a);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->b);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->gX);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->gY);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->n);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->h);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_SIGNATURE_RSA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_RSA_check(const TPMS_SIGNATURE_RSA *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hash);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    ret = iesys_TPM2B_PUBLIC_KEY_RSA_check ((in == NULL)? NULL : &in->sig);
    return_if_error(ret, "Bad Value for TPM2B_PUBLIC_KEY_RSA");

    return TSS2_RC_SUCCESS;
}
/*** Table 175 - Definition of Types for Table 175 - Definition of Types for  Signature ***/

/**
 * Check, if a variable is actually TPMS_SIGNATURE_RSASSA.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_RSASSA_check(const TPMS_SIGNATURE_RSASSA *in)
{
    return iesys_TPMS_SIGNATURE_RSA_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIGNATURE_RSAPSS.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_RSAPSS_check(const TPMS_SIGNATURE_RSAPSS *in)
{
    return iesys_TPMS_SIGNATURE_RSA_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIGNATURE_ECC.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_ECC_check(const TPMS_SIGNATURE_ECC *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->hash);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->signatureR);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    ret = iesys_TPM2B_ECC_PARAMETER_check ((in == NULL)? NULL : &in->signatureS);
    return_if_error(ret, "Bad Value for TPM2B_ECC_PARAMETER");

    return TSS2_RC_SUCCESS;
}
/*** Table 177 - Definition of Types for Table 177 - Definition of Types for  TPMS_SIGNATURE_ECC ***/

/**
 * Check, if a variable is actually TPMS_SIGNATURE_ECDSA.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_ECDSA_check(const TPMS_SIGNATURE_ECDSA *in)
{
    return iesys_TPMS_SIGNATURE_ECC_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIGNATURE_ECDAA.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_ECDAA_check(const TPMS_SIGNATURE_ECDAA *in)
{
    return iesys_TPMS_SIGNATURE_ECC_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIGNATURE_SM2.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_SM2_check(const TPMS_SIGNATURE_SM2 *in)
{
    return iesys_TPMS_SIGNATURE_ECC_check(in);
}

/**
 * Check, if a variable is actually TPMS_SIGNATURE_ECSCHNORR.
 * @param[in] in Structure to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_SIGNATURE_ECSCHNORR_check(const TPMS_SIGNATURE_ECSCHNORR *in)
{
    return iesys_TPMS_SIGNATURE_ECC_check(in);
}

/**
 * Check, if a variable is actually TPMU_SIGNATURE.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_SIGNATURE_check(const TPMU_SIGNATURE *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_RSASSA:
            return iesys_TPMS_SIGNATURE_RSASSA_check (&in->rsassa);
        case TPM2_ALG_RSAPSS:
            return iesys_TPMS_SIGNATURE_RSAPSS_check (&in->rsapss);
        case TPM2_ALG_ECDSA:
            return iesys_TPMS_SIGNATURE_ECDSA_check (&in->ecdsa);
        case TPM2_ALG_ECDAA:
            return iesys_TPMS_SIGNATURE_ECDAA_check (&in->ecdaa);
        case TPM2_ALG_SM2:
            return iesys_TPMS_SIGNATURE_SM2_check (&in->sm2);
        case TPM2_ALG_ECSCHNORR:
            return iesys_TPMS_SIGNATURE_ECSCHNORR_check (&in->ecschnorr);
        case TPM2_ALG_HMAC:
            return iesys_TPMT_HA_check (&in->hmac);
        case TPM2_ALG_NULL:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_SIGNATURE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_SIGNATURE_check(const TPMT_SIGNATURE *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_SIG_SCHEME_check ((in == NULL)? 0 : in->sigAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_SIG_SCHEME");

    ret = iesys_TPMU_SIGNATURE_check (&in->signature, in->sigAlg);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMU_ENCRYPTED_SECRET.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_ENCRYPTED_SECRET_check(const TPMU_ENCRYPTED_SECRET *in, UINT32 selector)
{
    (void)in;
    switch (selector) {
        case TPM2_ALG_ECC:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_RSA:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_SYMCIPHER:
            return TSS2_RC_SUCCESS;
        case TPM2_ALG_KEYEDHASH:
            return TSS2_RC_SUCCESS;
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPM2B_ENCRYPTED_SECRET.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_ENCRYPTED_SECRET_check(const TPM2B_ENCRYPTED_SECRET *in)
{
    if (in != NULL && in->size > sizeof(TPMU_ENCRYPTED_SECRET)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMU_ENCRYPTED_SECRET));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPMI_ALG_PUBLIC.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMI_ALG_PUBLIC_check(const TPMI_ALG_PUBLIC in)
{
    if ((in == TPM2_ALG_RSA) ||
        (in == TPM2_ALG_KEYEDHASH) ||
        (in == TPM2_ALG_ECC) ||
        (in == TPM2_ALG_SYMCIPHER)) {
        return TSS2_RC_SUCCESS;
    }
    LOG_ERROR("Bad Value for TPMI_ALG_PUBLIC");
    return TSS2_ESYS_RC_BAD_VALUE;
}

/**
 * Check, if a variable is actually TPMU_PUBLIC_ID.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_PUBLIC_ID_check(const TPMU_PUBLIC_ID *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_KEYEDHASH:
            return iesys_TPM2B_DIGEST_check (&in->keyedHash);
        case TPM2_ALG_SYMCIPHER:
            return iesys_TPM2B_DIGEST_check (&in->sym);
        case TPM2_ALG_RSA:
            return iesys_TPM2B_PUBLIC_KEY_RSA_check (&in->rsa);
        case TPM2_ALG_ECC:
            return iesys_TPMS_ECC_POINT_check (&in->ecc);
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMS_KEYEDHASH_PARMS.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_KEYEDHASH_PARMS_check(const TPMS_KEYEDHASH_PARMS *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_KEYEDHASH_SCHEME_check ((in == NULL)? NULL : &in->scheme);
    return_if_error(ret, "Bad Value for TPMT_KEYEDHASH_SCHEME");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_ASYM_PARMS.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ASYM_PARMS_check(const TPMS_ASYM_PARMS *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_SYM_DEF_OBJECT_check ((in == NULL)? NULL : &in->symmetric);
    return_if_error(ret, "Bad Value for TPMT_SYM_DEF_OBJECT");

    ret = iesys_TPMT_ASYM_SCHEME_check ((in == NULL)? NULL : &in->scheme);
    return_if_error(ret, "Bad Value for TPMT_ASYM_SCHEME");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_RSA_PARMS.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_RSA_PARMS_check(const TPMS_RSA_PARMS *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_SYM_DEF_OBJECT_check ((in == NULL)? NULL : &in->symmetric);
    return_if_error(ret, "Bad Value for TPMT_SYM_DEF_OBJECT");

    ret = iesys_TPMT_RSA_SCHEME_check ((in == NULL)? NULL : &in->scheme);
    return_if_error(ret, "Bad Value for TPMT_RSA_SCHEME");

    ret = iesys_TPMI_RSA_KEY_BITS_check ((in == NULL)? 0 : in->keyBits);
    return_if_error(ret, "Bad Value for TPMI_RSA_KEY_BITS");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_ECC_PARMS.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_ECC_PARMS_check(const TPMS_ECC_PARMS *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_SYM_DEF_OBJECT_check ((in == NULL)? NULL : &in->symmetric);
    return_if_error(ret, "Bad Value for TPMT_SYM_DEF_OBJECT");

    ret = iesys_TPMT_ECC_SCHEME_check ((in == NULL)? NULL : &in->scheme);
    return_if_error(ret, "Bad Value for TPMT_ECC_SCHEME");

    ret = iesys_TPMI_ECC_CURVE_check ((in == NULL)? 0 : in->curveID);
    return_if_error(ret, "Bad Value for TPMI_ECC_CURVE");

    ret = iesys_TPMT_KDF_SCHEME_check ((in == NULL)? NULL : &in->kdf);
    return_if_error(ret, "Bad Value for TPMT_KDF_SCHEME");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMU_PUBLIC_PARMS.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_PUBLIC_PARMS_check(const TPMU_PUBLIC_PARMS *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_KEYEDHASH:
            return iesys_TPMS_KEYEDHASH_PARMS_check (&in->keyedHashDetail);
        case TPM2_ALG_SYMCIPHER:
            return iesys_TPMS_SYMCIPHER_PARMS_check (&in->symDetail);
        case TPM2_ALG_RSA:
            return iesys_TPMS_RSA_PARMS_check (&in->rsaDetail);
        case TPM2_ALG_ECC:
            return iesys_TPMS_ECC_PARMS_check (&in->eccDetail);
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_PUBLIC_PARMS.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_PUBLIC_PARMS_check(const TPMT_PUBLIC_PARMS *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_PUBLIC_check ((in == NULL)? 0 : in->type);
    return_if_error(ret, "Bad Value for TPMI_ALG_PUBLIC");

    ret = iesys_TPMU_PUBLIC_PARMS_check (&in->parameters, in->type);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMT_PUBLIC.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_PUBLIC_check(const TPMT_PUBLIC *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_PUBLIC_check ((in == NULL)? 0 : in->type);
    return_if_error(ret, "Bad Value for TPMI_ALG_PUBLIC");

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->nameAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->authPolicy);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    ret = iesys_TPMU_PUBLIC_PARMS_check (&in->parameters, in->type);
    return_if_error(ret, "Bad value");

    ret = iesys_TPMU_PUBLIC_ID_check (&in->unique, in->type);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_PUBLIC.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_PUBLIC_check(const TPM2B_PUBLIC *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_PUBLIC_check ((in == NULL)? NULL : &in->publicArea);
    return_if_error(ret, "Bad Value for TPMT_PUBLIC");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_TEMPLATE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_TEMPLATE_check(const TPM2B_TEMPLATE *in)
{
    if (in != NULL && in->size > sizeof(TPMT_PUBLIC)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMT_PUBLIC));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_PRIVATE_VENDOR_SPECIFIC.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_PRIVATE_VENDOR_SPECIFIC_check(const TPM2B_PRIVATE_VENDOR_SPECIFIC *in)
{
    if (in != NULL && in->size > TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMU_SENSITIVE_COMPOSITE.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMU_SENSITIVE_COMPOSITE_check(const TPMU_SENSITIVE_COMPOSITE *in, UINT32 selector)
{
    switch (selector) {
        case TPM2_ALG_RSA:
            return iesys_TPM2B_PRIVATE_KEY_RSA_check (&in->rsa);
        case TPM2_ALG_ECC:
            return iesys_TPM2B_ECC_PARAMETER_check (&in->ecc);
        case TPM2_ALG_KEYEDHASH:
            return iesys_TPM2B_SENSITIVE_DATA_check (&in->bits);
        case TPM2_ALG_SYMCIPHER:
            return iesys_TPM2B_SYM_KEY_check (&in->sym);
        default:
            LOG_ERROR("Selector %"PRIu32 " did not match", selector);
            return TSS2_ESYS_RC_BAD_VALUE;
    };
}

/**
 * Check, if a variable is actually TPMT_SENSITIVE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMT_SENSITIVE_check(const TPMT_SENSITIVE *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_ALG_PUBLIC_check ((in == NULL)? 0 : in->sensitiveType);
    return_if_error(ret, "Bad Value for TPMI_ALG_PUBLIC");

    ret = iesys_TPM2B_AUTH_check ((in == NULL)? NULL : &in->authValue);
    return_if_error(ret, "Bad Value for TPM2B_AUTH");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->seedValue);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    ret = iesys_TPMU_SENSITIVE_COMPOSITE_check (&in->sensitive, in->sensitiveType);
    return_if_error(ret, "Bad value");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_SENSITIVE.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_SENSITIVE_check(const TPM2B_SENSITIVE *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMT_SENSITIVE_check ((in == NULL)? NULL : &in->sensitiveArea);
    return_if_error(ret, "Bad Value for TPMT_SENSITIVE");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_PRIVATE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_PRIVATE_check(const TPM2B_PRIVATE *in)
{
    if (in != NULL && in->size > sizeof(_PRIVATE)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(_PRIVATE));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_ID_OBJECT.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_ID_OBJECT_check(const TPM2B_ID_OBJECT *in)
{
    if (in != NULL && in->size > sizeof(_ID_OBJECT)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(_ID_OBJECT));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2_NV_INDEX.
 * This functions expects the Bitfield to be encoded as unsinged int in host-endianess.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_NV_INDEX_check(const TPM2_NV_INDEX in)
{
    UINT32 input;
    input = (UINT32) *((unsigned int *) &in);
    if (input != (UINT32) *((unsigned int *) &in)) {
        LOG_ERROR("in value does not fit into UINT32");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_NV_PUBLIC.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_NV_PUBLIC_check(const TPMS_NV_PUBLIC *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_RH_NV_INDEX_check ((in == NULL)? 0 : in->nvIndex);
    return_if_error(ret, "Bad Value for TPMI_RH_NV_INDEX");

    ret = iesys_TPMI_ALG_HASH_check ((in == NULL)? 0 : in->nameAlg);
    return_if_error(ret, "Bad Value for TPMI_ALG_HASH");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->authPolicy);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_NV_PUBLIC.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_NV_PUBLIC_check(const TPM2B_NV_PUBLIC *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMS_NV_PUBLIC_check ((in == NULL)? NULL : &in->nvPublic);
    return_if_error(ret, "Bad Value for TPMS_NV_PUBLIC");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_CONTEXT_SENSITIVE.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_CONTEXT_SENSITIVE_check(const TPM2B_CONTEXT_SENSITIVE *in)
{
    if (in != NULL && in->size > TPM2_MAX_CONTEXT_SIZE) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)TPM2_MAX_CONTEXT_SIZE);
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_CONTEXT_DATA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_CONTEXT_DATA_check(const TPMS_CONTEXT_DATA *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->integrity);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    ret = iesys_TPM2B_CONTEXT_SENSITIVE_check ((in == NULL)? NULL : &in->encrypted);
    return_if_error(ret, "Bad Value for TPM2B_CONTEXT_SENSITIVE");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_CONTEXT_DATA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_CONTEXT_DATA_check(const TPM2B_CONTEXT_DATA *in)
{
    if (in != NULL && in->size > sizeof(TPMS_CONTEXT_DATA)) {
        LOG_ERROR("BAD VALUE %zu > %zu",(size_t)in->size,(size_t)sizeof(TPMS_CONTEXT_DATA));
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_CONTEXT.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_CONTEXT_check(const TPMS_CONTEXT *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMI_DH_CONTEXT_check ((in == NULL)? 0 : in->savedHandle);
    return_if_error(ret, "Bad Value for TPMI_DH_CONTEXT");

    ret = iesys_TPMI_RH_HIERARCHY_check ((in == NULL)? 0 : in->hierarchy);
    return_if_error(ret, "Bad Value for TPMI_RH_HIERARCHY");

    ret = iesys_TPM2B_CONTEXT_DATA_check ((in == NULL)? NULL : &in->contextBlob);
    return_if_error(ret, "Bad Value for TPM2B_CONTEXT_DATA");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPMS_CREATION_DATA.
 * @param[in] in variable to be checked.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPMS_CREATION_DATA_check(const TPMS_CREATION_DATA *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPML_PCR_SELECTION_check ((in == NULL)? NULL : &in->pcrSelect);
    return_if_error(ret, "Bad Value for TPML_PCR_SELECTION");

    ret = iesys_TPM2B_DIGEST_check ((in == NULL)? NULL : &in->pcrDigest);
    return_if_error(ret, "Bad Value for TPM2B_DIGEST");

    ret = iesys_TPM2_ALG_ID_check ((in == NULL)? 0 : in->parentNameAlg);
    return_if_error(ret, "Bad Value for TPM2_ALG_ID");

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->parentName);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    ret = iesys_TPM2B_NAME_check ((in == NULL)? NULL : &in->parentQualifiedName);
    return_if_error(ret, "Bad Value for TPM2B_NAME");

    ret = iesys_TPM2B_DATA_check ((in == NULL)? NULL : &in->outsideInfo);
    return_if_error(ret, "Bad Value for TPM2B_DATA");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually TPM2B_CREATION_DATA.
 * @param[in] in variable to be checked. *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2B_CREATION_DATA_check(const TPM2B_CREATION_DATA *in)
{
    TSS2_RC ret;

    if (in == NULL)
        return TSS2_RC_SUCCESS;

    ret = iesys_TPMS_CREATION_DATA_check ((in == NULL)? NULL : &in->creationData);
    return_if_error(ret, "Bad Value for TPMS_CREATION_DATA");

    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable is actually of type TPM2_NT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE for type error.
 */
TSS2_RC
iesys_TPM2_SU_check(
    const TPM2_SU in)
{
    if ((in == TPM2_SU_CLEAR) ||
        (in == TPM2_SU_STATE))
        return TSS2_RC_SUCCESS;

    LOG_ERROR("Bad Value for TPM2_SU");
    return TSS2_ESYS_RC_BAD_VALUE;
}
