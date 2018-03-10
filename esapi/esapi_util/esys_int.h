/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
#ifndef ESYS_INT_H
#define ESYS_INT_H

#include "tpm20.h"
#include <stdbool.h>
#include <tss2_esys.h>
#include "esys_types.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RSRC_NODE_T {
    ESYS_TR esys_handle;
    TPM2B_AUTH auth;
    IESYS_RESOURCE rsrc;
    struct RSRC_NODE_T * next;
    BYTE authValueSet;
} RSRC_NODE_T;

/*
 * Declares of structs for storing ESAPI input parameters
 */


typedef struct {
    TPM2_SU startupType;
} Startup_IN;


typedef struct {
    TPM2_SU shutdownType;
} Shutdown_IN;


typedef struct {
    TPMI_YES_NO fullTest;
} SelfTest_IN;


typedef struct {
    TPML_ALG *toTest;
    TPML_ALG toTestData;
} IncrementalSelfTest_IN;

typedef TPMS_EMPTY  GetTestResult_IN;


typedef struct {
    ESYS_TR tpmKey;
    ESYS_TR bind;
    TPM2_SE sessionType;
    TPMI_ALG_HASH authHash;
    TPM2B_NONCE *nonceCaller;
    TPM2B_NONCE nonceCallerData;
    TPM2B_ENCRYPTED_SECRET *encryptedSalt;
    TPM2B_ENCRYPTED_SECRET encryptedSaltData;
    TPMT_SYM_DEF *symmetric;
    TPMT_SYM_DEF symmetricData;
} StartAuthSession_IN;


typedef struct {
    ESYS_TR sessionHandle;
} PolicyRestart_IN;


typedef struct {
    ESYS_TR parentHandle;
    TPM2B_SENSITIVE_CREATE *inSensitive;
    TPM2B_SENSITIVE_CREATE inSensitiveData;
    TPM2B_PUBLIC *inPublic;
    TPM2B_PUBLIC inPublicData;
    TPM2B_DATA *outsideInfo;
    TPM2B_DATA outsideInfoData;
    TPML_PCR_SELECTION *creationPCR;
    TPML_PCR_SELECTION creationPCRData;
} Create_IN;


typedef struct {
    ESYS_TR parentHandle;
    TPM2B_PRIVATE *inPrivate;
    TPM2B_PRIVATE inPrivateData;
    TPM2B_PUBLIC *inPublic;
    TPM2B_PUBLIC inPublicData;
} Load_IN;


typedef struct {
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_SENSITIVE *inPrivate;
    TPM2B_SENSITIVE inPrivateData;
    TPM2B_PUBLIC *inPublic;
    TPM2B_PUBLIC inPublicData;
} LoadExternal_IN;


typedef struct {
    ESYS_TR objectHandle;
} ReadPublic_IN;


typedef struct {
    ESYS_TR activateHandle;
    ESYS_TR keyHandle;
    TPM2B_ID_OBJECT *credentialBlob;
    TPM2B_ID_OBJECT credentialBlobData;
    TPM2B_ENCRYPTED_SECRET *secret;
    TPM2B_ENCRYPTED_SECRET secretData;
} ActivateCredential_IN;


typedef struct {
    ESYS_TR handle;
    TPM2B_DIGEST *credential;
    TPM2B_DIGEST credentialData;
    TPM2B_NAME *objectName;
    TPM2B_NAME objectNameData;
} MakeCredential_IN;


typedef struct {
    ESYS_TR itemHandle;
} Unseal_IN;


typedef struct {
    ESYS_TR objectHandle;
    ESYS_TR parentHandle;
    TPM2B_AUTH *newAuth;
    TPM2B_AUTH newAuthData;
} ObjectChangeAuth_IN;


typedef struct {
    ESYS_TR parentHandle;
    TPM2B_SENSITIVE_CREATE *inSensitive;
    TPM2B_SENSITIVE_CREATE inSensitiveData;
    TPM2B_TEMPLATE *inPublic;
    TPM2B_TEMPLATE inPublicData;
} CreateLoaded_IN;


typedef struct {
    ESYS_TR objectHandle;
    ESYS_TR newParentHandle;
    TPM2B_DATA *encryptionKeyIn;
    TPM2B_DATA encryptionKeyInData;
    TPMT_SYM_DEF_OBJECT *symmetricAlg;
    TPMT_SYM_DEF_OBJECT symmetricAlgData;
} Duplicate_IN;


typedef struct {
    ESYS_TR oldParent;
    ESYS_TR newParent;
    TPM2B_PRIVATE *inDuplicate;
    TPM2B_PRIVATE inDuplicateData;
    TPM2B_NAME *name;
    TPM2B_NAME nameData;
    TPM2B_ENCRYPTED_SECRET *inSymSeed;
    TPM2B_ENCRYPTED_SECRET inSymSeedData;
} Rewrap_IN;


typedef struct {
    ESYS_TR parentHandle;
    TPM2B_DATA *encryptionKey;
    TPM2B_DATA encryptionKeyData;
    TPM2B_PUBLIC *objectPublic;
    TPM2B_PUBLIC objectPublicData;
    TPM2B_PRIVATE *duplicate;
    TPM2B_PRIVATE duplicateData;
    TPM2B_ENCRYPTED_SECRET *inSymSeed;
    TPM2B_ENCRYPTED_SECRET inSymSeedData;
    TPMT_SYM_DEF_OBJECT *symmetricAlg;
    TPMT_SYM_DEF_OBJECT symmetricAlgData;
} Import_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPM2B_PUBLIC_KEY_RSA *message;
    TPM2B_PUBLIC_KEY_RSA messageData;
    TPMT_RSA_DECRYPT *inScheme;
    TPMT_RSA_DECRYPT inSchemeData;
    TPM2B_DATA *label;
    TPM2B_DATA labelData;
} RSA_Encrypt_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPM2B_PUBLIC_KEY_RSA *cipherText;
    TPM2B_PUBLIC_KEY_RSA cipherTextData;
    TPMT_RSA_DECRYPT *inScheme;
    TPMT_RSA_DECRYPT inSchemeData;
    TPM2B_DATA *label;
    TPM2B_DATA labelData;
} RSA_Decrypt_IN;


typedef struct {
    ESYS_TR keyHandle;
} ECDH_KeyGen_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPM2B_ECC_POINT *inPoint;
    TPM2B_ECC_POINT inPointData;
} ECDH_ZGen_IN;


typedef struct {
    TPMI_ECC_CURVE curveID;
} ECC_Parameters_IN;


typedef struct {
    ESYS_TR keyA;
    TPMI_ECC_KEY_EXCHANGE inScheme;
    UINT16 counter;
    TPM2B_ECC_POINT *inQsB;
    TPM2B_ECC_POINT inQsBData;
    TPM2B_ECC_POINT *inQeB;
    TPM2B_ECC_POINT inQeBData;
} ZGen_2Phase_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPMI_YES_NO decrypt;
    TPMI_ALG_SYM_MODE mode;
    TPM2B_IV *ivIn;
    TPM2B_IV ivInData;
    TPM2B_MAX_BUFFER *inData;
    TPM2B_MAX_BUFFER inDataData;
} EncryptDecrypt_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPMI_YES_NO decrypt;
    TPMI_ALG_SYM_MODE mode;
    TPM2B_MAX_BUFFER *inData;
    TPM2B_MAX_BUFFER inDataData;
    TPM2B_IV *ivIn;
    TPM2B_IV ivInData;
} EncryptDecrypt2_IN;


typedef struct {
    TPMI_ALG_HASH hashAlg;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_MAX_BUFFER *data;
    TPM2B_MAX_BUFFER dataData;
} Hash_IN;


typedef struct {
    ESYS_TR handle;
    TPMI_ALG_HASH hashAlg;
    TPM2B_MAX_BUFFER *buffer;
    TPM2B_MAX_BUFFER bufferData;
} HMAC_IN;


typedef struct {
    UINT16 bytesRequested;
} GetRandom_IN;


typedef struct {
    TPM2B_SENSITIVE_DATA *inData;
    TPM2B_SENSITIVE_DATA inDataData;
} StirRandom_IN;


typedef struct {
    ESYS_TR handle;
    TPMI_ALG_HASH hashAlg;
    TPM2B_AUTH *auth;
    TPM2B_AUTH authData;
} HMAC_Start_IN;


typedef struct {
    TPMI_ALG_HASH hashAlg;
    TPM2B_AUTH *auth;
    TPM2B_AUTH authData;
} HashSequenceStart_IN;


typedef struct {
    ESYS_TR sequenceHandle;
    TPM2B_MAX_BUFFER *buffer;
    TPM2B_MAX_BUFFER bufferData;
} SequenceUpdate_IN;


typedef struct {
    ESYS_TR sequenceHandle;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_MAX_BUFFER *buffer;
    TPM2B_MAX_BUFFER bufferData;
} SequenceComplete_IN;


typedef struct {
    ESYS_TR pcrHandle;
    ESYS_TR sequenceHandle;
    TPM2B_MAX_BUFFER *buffer;
    TPM2B_MAX_BUFFER bufferData;
} EventSequenceComplete_IN;


typedef struct {
    ESYS_TR objectHandle;
    ESYS_TR signHandle;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
} Certify_IN;


typedef struct {
    ESYS_TR signHandle;
    ESYS_TR objectHandle;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPM2B_DIGEST *creationHash;
    TPM2B_DIGEST creationHashData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
    TPMT_TK_CREATION *creationTicket;
    TPMT_TK_CREATION creationTicketData;
} CertifyCreation_IN;


typedef struct {
    ESYS_TR signHandle;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
    TPML_PCR_SELECTION *PCRselect;
    TPML_PCR_SELECTION PCRselectData;
} Quote_IN;


typedef struct {
    ESYS_TR privacyAdminHandle;
    ESYS_TR signHandle;
    ESYS_TR sessionHandle;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
} GetSessionAuditDigest_IN;


typedef struct {
    ESYS_TR privacyHandle;
    ESYS_TR signHandle;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
} GetCommandAuditDigest_IN;


typedef struct {
    ESYS_TR privacyAdminHandle;
    ESYS_TR signHandle;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
} GetTime_IN;


typedef struct {
    ESYS_TR signHandle;
    TPM2B_ECC_POINT *P1;
    TPM2B_ECC_POINT P1Data;
    TPM2B_SENSITIVE_DATA *s2;
    TPM2B_SENSITIVE_DATA s2Data;
    TPM2B_ECC_PARAMETER *y2;
    TPM2B_ECC_PARAMETER y2Data;
} Commit_IN;


typedef struct {
    TPMI_ECC_CURVE curveID;
} EC_Ephemeral_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPM2B_DIGEST *digest;
    TPM2B_DIGEST digestData;
    TPMT_SIGNATURE *signature;
    TPMT_SIGNATURE signatureData;
} VerifySignature_IN;


typedef struct {
    ESYS_TR keyHandle;
    TPM2B_DIGEST *digest;
    TPM2B_DIGEST digestData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
    TPMT_TK_HASHCHECK *validation;
    TPMT_TK_HASHCHECK validationData;
} Sign_IN;


typedef struct {
    ESYS_TR auth;
    TPMI_ALG_HASH auditAlg;
    TPML_CC *setList;
    TPML_CC setListData;
    TPML_CC *clearList;
    TPML_CC clearListData;
} SetCommandCodeAuditStatus_IN;


typedef struct {
    ESYS_TR pcrHandle;
    TPML_DIGEST_VALUES *digests;
    TPML_DIGEST_VALUES digestsData;
} PCR_Extend_IN;


typedef struct {
    ESYS_TR pcrHandle;
    TPM2B_EVENT *eventData;
    TPM2B_EVENT eventDataData;
} PCR_Event_IN;


typedef struct {
    TPML_PCR_SELECTION *pcrSelectionIn;
    TPML_PCR_SELECTION pcrSelectionInData;
} PCR_Read_IN;


typedef struct {
    ESYS_TR authHandle;
    TPML_PCR_SELECTION *pcrAllocation;
    TPML_PCR_SELECTION pcrAllocationData;
} PCR_Allocate_IN;


typedef struct {
    ESYS_TR authHandle;
    TPMI_ALG_HASH hashAlg;
    TPMI_DH_PCR pcrNum;
    TPM2B_DIGEST *authPolicy;
    TPM2B_DIGEST authPolicyData;
} PCR_SetAuthPolicy_IN;


typedef struct {
    ESYS_TR pcrHandle;
    TPM2B_DIGEST *auth;
    TPM2B_DIGEST authData;
} PCR_SetAuthValue_IN;


typedef struct {
    ESYS_TR pcrHandle;
} PCR_Reset_IN;


typedef struct {
    ESYS_TR authObject;
    ESYS_TR policySession;
    INT32 expiration;
    TPM2B_NONCE *nonceTPM;
    TPM2B_NONCE nonceTPMData;
    TPM2B_DIGEST *cpHashA;
    TPM2B_DIGEST cpHashAData;
    TPM2B_NONCE *policyRef;
    TPM2B_NONCE policyRefData;
    TPMT_SIGNATURE *auth;
    TPMT_SIGNATURE authData;
} PolicySigned_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR policySession;
    INT32 expiration;
    TPM2B_NONCE *nonceTPM;
    TPM2B_NONCE nonceTPMData;
    TPM2B_DIGEST *cpHashA;
    TPM2B_DIGEST cpHashAData;
    TPM2B_NONCE *policyRef;
    TPM2B_NONCE policyRefData;
} PolicySecret_IN;


typedef struct {
    ESYS_TR policySession;
    TPM2B_TIMEOUT *timeout;
    TPM2B_TIMEOUT timeoutData;
    TPM2B_DIGEST *cpHashA;
    TPM2B_DIGEST cpHashAData;
    TPM2B_NONCE *policyRef;
    TPM2B_NONCE policyRefData;
    TPM2B_NAME *authName;
    TPM2B_NAME authNameData;
    TPMT_TK_AUTH *ticket;
    TPMT_TK_AUTH ticketData;
} PolicyTicket_IN;


typedef struct {
    ESYS_TR policySession;
    TPML_DIGEST *pHashList;
    TPML_DIGEST pHashListData;
} PolicyOR_IN;


typedef struct {
    ESYS_TR policySession;
    TPM2B_DIGEST *pcrDigest;
    TPM2B_DIGEST pcrDigestData;
    TPML_PCR_SELECTION *pcrs;
    TPML_PCR_SELECTION pcrsData;
} PolicyPCR_IN;


typedef struct {
    TPMI_SH_POLICY policySession;
    TPMA_LOCALITY locality;
} PolicyLocality_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    ESYS_TR policySession;
    UINT16 offset;
    TPM2_EO operation;
    TPM2B_OPERAND *operandB;
    TPM2B_OPERAND operandBData;
} PolicyNV_IN;


typedef struct {
    ESYS_TR policySession;
    UINT16 offset;
    TPM2_EO operation;
    TPM2B_OPERAND *operandB;
    TPM2B_OPERAND operandBData;
} PolicyCounterTimer_IN;


typedef struct {
    ESYS_TR policySession;
    TPM2_CC code;
} PolicyCommandCode_IN;


typedef struct {
    ESYS_TR policySession;
} PolicyPhysicalPresence_IN;


typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST *cpHashA;
    TPM2B_DIGEST cpHashAData;
} PolicyCpHash_IN;


typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST *nameHash;
    TPM2B_DIGEST nameHashData;
} PolicyNameHash_IN;


typedef struct {
    TPMI_SH_POLICY policySession;
    TPMI_YES_NO includeObject;
    TPM2B_NAME *objectName;
    TPM2B_NAME objectNameData;
    TPM2B_NAME *newParentName;
    TPM2B_NAME newParentNameData;
} PolicyDuplicationSelect_IN;


typedef struct {
    ESYS_TR policySession;
    TPM2B_DIGEST *approvedPolicy;
    TPM2B_DIGEST approvedPolicyData;
    TPM2B_NONCE *policyRef;
    TPM2B_NONCE policyRefData;
    TPM2B_NAME *keySign;
    TPM2B_NAME keySignData;
    TPMT_TK_VERIFIED *checkTicket;
    TPMT_TK_VERIFIED checkTicketData;
} PolicyAuthorize_IN;


typedef struct {
    ESYS_TR policySession;
} PolicyAuthValue_IN;


typedef struct {
    ESYS_TR policySession;
} PolicyPassword_IN;


typedef struct {
    ESYS_TR policySession;
} PolicyGetDigest_IN;


typedef struct {
    ESYS_TR policySession;
    TPMI_YES_NO writtenSet;
} PolicyNvWritten_IN;


typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST *templateHash;
    TPM2B_DIGEST templateHashData;
} PolicyTemplate_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    ESYS_TR policySession;
} PolicyAuthorizeNV_IN;


typedef struct {
    ESYS_TR primaryHandle;
    TPM2B_SENSITIVE_CREATE *inSensitive;
    TPM2B_SENSITIVE_CREATE inSensitiveData;
    TPM2B_PUBLIC *inPublic;
    TPM2B_PUBLIC inPublicData;
    TPM2B_DATA *outsideInfo;
    TPM2B_DATA outsideInfoData;
    TPML_PCR_SELECTION *creationPCR;
    TPML_PCR_SELECTION creationPCRData;
} CreatePrimary_IN;


typedef struct {
    ESYS_TR authHandle;
    TPMI_RH_ENABLES enable;
    TPMI_YES_NO state;
} HierarchyControl_IN;


typedef struct {
    ESYS_TR authHandle;
    TPMI_ALG_HASH hashAlg;
    TPM2B_DIGEST *authPolicy;
    TPM2B_DIGEST authPolicyData;
} SetPrimaryPolicy_IN;


typedef struct {
    ESYS_TR authHandle;
} ChangePPS_IN;


typedef struct {
    ESYS_TR authHandle;
} ChangeEPS_IN;


typedef struct {
    ESYS_TR authHandle;
} Clear_IN;


typedef struct {
    ESYS_TR auth;
    TPMI_YES_NO disable;
} ClearControl_IN;


typedef struct {
    ESYS_TR authHandle;
    TPM2B_AUTH *newAuth;
    TPM2B_AUTH newAuthData;
} HierarchyChangeAuth_IN;


typedef struct {
    ESYS_TR lockHandle;
} DictionaryAttackLockReset_IN;


typedef struct {
    ESYS_TR lockHandle;
    UINT32 newMaxTries;
    UINT32 newRecoveryTime;
    UINT32 lockoutRecovery;
} DictionaryAttackParameters_IN;


typedef struct {
    ESYS_TR auth;
    TPML_CC *setList;
    TPML_CC setListData;
    TPML_CC *clearList;
    TPML_CC clearListData;
} PP_Commands_IN;


typedef struct {
    ESYS_TR authHandle;
    UINT32 algorithmSet;
} SetAlgorithmSet_IN;


typedef struct {
    ESYS_TR authorization;
    ESYS_TR keyHandle;
    TPM2B_DIGEST *fuDigest;
    TPM2B_DIGEST fuDigestData;
    TPMT_SIGNATURE *manifestSignature;
    TPMT_SIGNATURE manifestSignatureData;
} FieldUpgradeStart_IN;


typedef struct {
    TPM2B_MAX_BUFFER *fuData;
    TPM2B_MAX_BUFFER fuDataData;
} FieldUpgradeData_IN;


typedef struct {
    UINT32 sequenceNumber;
} FirmwareRead_IN;


typedef struct {
    ESYS_TR saveHandle;
} ContextSave_IN;


typedef struct {
    TPMS_CONTEXT *context;
    TPMS_CONTEXT contextData;
} ContextLoad_IN;


typedef struct {
    ESYS_TR flushHandle;
} FlushContext_IN;


typedef struct {
    ESYS_TR auth;
    ESYS_TR objectHandle;
    TPMI_DH_PERSISTENT persistentHandle;
} EvictControl_IN;

typedef TPMS_EMPTY  ReadClock_IN;


typedef struct {
    ESYS_TR auth;
    UINT64 newTime;
} ClockSet_IN;


typedef struct {
    ESYS_TR auth;
    TPM2_CLOCK_ADJUST rateAdjust;
} ClockRateAdjust_IN;


typedef struct {
    TPM2_CAP capability;
    UINT32 property;
    UINT32 propertyCount;
} GetCapability_IN;


typedef struct {
    TPMT_PUBLIC_PARMS *parameters;
    TPMT_PUBLIC_PARMS parametersData;
} TestParms_IN;


typedef struct {
    ESYS_TR authHandle;
    TPM2B_AUTH *auth;
    TPM2B_AUTH authData;
    TPM2B_NV_PUBLIC *publicInfo;
    TPM2B_NV_PUBLIC publicInfoData;
} NV_DefineSpace_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
} NV_UndefineSpace_IN;


typedef struct {
    ESYS_TR nvIndex;
    ESYS_TR platform;
} NV_UndefineSpaceSpecial_IN;


typedef struct {
    ESYS_TR nvIndex;
} NV_ReadPublic_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    UINT16 offset;
    TPM2B_MAX_NV_BUFFER *data;
    TPM2B_MAX_NV_BUFFER dataData;
} NV_Write_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
} NV_Increment_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    TPM2B_MAX_NV_BUFFER *data;
    TPM2B_MAX_NV_BUFFER dataData;
} NV_Extend_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    UINT64 bits;
} NV_SetBits_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
} NV_WriteLock_IN;


typedef struct {
    ESYS_TR authHandle;
} NV_GlobalWriteLock_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    UINT16 size;
    UINT16 offset;
} NV_Read_IN;


typedef struct {
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
} NV_ReadLock_IN;


typedef struct {
    ESYS_TR nvIndex;
    TPM2B_AUTH *newAuth;
    TPM2B_AUTH newAuthData;
} NV_ChangeAuth_IN;


typedef struct {
    ESYS_TR signHandle;
    ESYS_TR authHandle;
    ESYS_TR nvIndex;
    UINT16 size;
    UINT16 offset;
    TPM2B_DATA *qualifyingData;
    TPM2B_DATA qualifyingDataData;
    TPMT_SIG_SCHEME *inScheme;
    TPMT_SIG_SCHEME inSchemeData;
} NV_Certify_IN;


typedef struct {
    TPM2B_DATA *inputData;
    TPM2B_DATA inputDataData;
} Vendor_TCG_Test_IN;

typedef union {

    Startup_IN Startup;
    Shutdown_IN Shutdown;
    SelfTest_IN SelfTest;
    IncrementalSelfTest_IN IncrementalSelfTest;
    GetTestResult_IN GetTestResult;
    StartAuthSession_IN StartAuthSession;
    PolicyRestart_IN PolicyRestart;
    Create_IN Create;
    Load_IN Load;
    LoadExternal_IN LoadExternal;
    ReadPublic_IN ReadPublic;
    ActivateCredential_IN ActivateCredential;
    MakeCredential_IN MakeCredential;
    Unseal_IN Unseal;
    ObjectChangeAuth_IN ObjectChangeAuth;
    CreateLoaded_IN CreateLoaded;
    Duplicate_IN Duplicate;
    Rewrap_IN Rewrap;
    Import_IN Import;
    RSA_Encrypt_IN RSA_Encrypt;
    RSA_Decrypt_IN RSA_Decrypt;
    ECDH_KeyGen_IN ECDH_KeyGen;
    ECDH_ZGen_IN ECDH_ZGen;
    ECC_Parameters_IN ECC_Parameters;
    ZGen_2Phase_IN ZGen_2Phase;
    EncryptDecrypt_IN EncryptDecrypt;
    EncryptDecrypt2_IN EncryptDecrypt2;
    Hash_IN Hash;
    HMAC_IN HMAC;
    GetRandom_IN GetRandom;
    StirRandom_IN StirRandom;
    HMAC_Start_IN HMAC_Start;
    HashSequenceStart_IN HashSequenceStart;
    SequenceUpdate_IN SequenceUpdate;
    SequenceComplete_IN SequenceComplete;
    EventSequenceComplete_IN EventSequenceComplete;
    Certify_IN Certify;
    CertifyCreation_IN CertifyCreation;
    Quote_IN Quote;
    GetSessionAuditDigest_IN GetSessionAuditDigest;
    GetCommandAuditDigest_IN GetCommandAuditDigest;
    GetTime_IN GetTime;
    Commit_IN Commit;
    EC_Ephemeral_IN EC_Ephemeral;
    VerifySignature_IN VerifySignature;
    Sign_IN Sign;
    SetCommandCodeAuditStatus_IN SetCommandCodeAuditStatus;
    PCR_Extend_IN PCR_Extend;
    PCR_Event_IN PCR_Event;
    PCR_Read_IN PCR_Read;
    PCR_Allocate_IN PCR_Allocate;
    PCR_SetAuthPolicy_IN PCR_SetAuthPolicy;
    PCR_SetAuthValue_IN PCR_SetAuthValue;
    PCR_Reset_IN PCR_Reset;
    PolicySigned_IN PolicySigned;
    PolicySecret_IN PolicySecret;
    PolicyTicket_IN PolicyTicket;
    PolicyOR_IN PolicyOR;
    PolicyPCR_IN PolicyPCR;
    PolicyLocality_IN PolicyLocality;
    PolicyNV_IN PolicyNV;
    PolicyCounterTimer_IN PolicyCounterTimer;
    PolicyCommandCode_IN PolicyCommandCode;
    PolicyPhysicalPresence_IN PolicyPhysicalPresence;
    PolicyCpHash_IN PolicyCpHash;
    PolicyNameHash_IN PolicyNameHash;
    PolicyDuplicationSelect_IN PolicyDuplicationSelect;
    PolicyAuthorize_IN PolicyAuthorize;
    PolicyAuthValue_IN PolicyAuthValue;
    PolicyPassword_IN PolicyPassword;
    PolicyGetDigest_IN PolicyGetDigest;
    PolicyNvWritten_IN PolicyNvWritten;
    PolicyTemplate_IN PolicyTemplate;
    PolicyAuthorizeNV_IN PolicyAuthorizeNV;
    CreatePrimary_IN CreatePrimary;
    HierarchyControl_IN HierarchyControl;
    SetPrimaryPolicy_IN SetPrimaryPolicy;
    ChangePPS_IN ChangePPS;
    ChangeEPS_IN ChangeEPS;
    Clear_IN Clear;
    ClearControl_IN ClearControl;
    HierarchyChangeAuth_IN HierarchyChangeAuth;
    DictionaryAttackLockReset_IN DictionaryAttackLockReset;
    DictionaryAttackParameters_IN DictionaryAttackParameters;
    PP_Commands_IN PP_Commands;
    SetAlgorithmSet_IN SetAlgorithmSet;
    FieldUpgradeStart_IN FieldUpgradeStart;
    FieldUpgradeData_IN FieldUpgradeData;
    FirmwareRead_IN FirmwareRead;
    ContextSave_IN ContextSave;
    ContextLoad_IN ContextLoad;
    FlushContext_IN FlushContext;
    EvictControl_IN EvictControl;
    ReadClock_IN ReadClock;
    ClockSet_IN ClockSet;
    ClockRateAdjust_IN ClockRateAdjust;
    GetCapability_IN GetCapability;
    TestParms_IN TestParms;
    NV_DefineSpace_IN NV_DefineSpace;
    NV_UndefineSpace_IN NV_UndefineSpace;
    NV_UndefineSpaceSpecial_IN NV_UndefineSpaceSpecial;
    NV_ReadPublic_IN NV_ReadPublic;
    NV_Write_IN NV_Write;
    NV_Increment_IN NV_Increment;
    NV_Extend_IN NV_Extend;
    NV_SetBits_IN NV_SetBits;
    NV_WriteLock_IN NV_WriteLock;
    NV_GlobalWriteLock_IN NV_GlobalWriteLock;
    NV_Read_IN NV_Read;
    NV_ReadLock_IN NV_ReadLock;
    NV_ChangeAuth_IN NV_ChangeAuth;
    NV_Certify_IN NV_Certify;
    Vendor_TCG_Test_IN Vendor_TCG_Test;
} IESYS_CMD_IN_PARAM;

enum _ESYS_STATE {
    _ESYS_STATE_INIT = 0,
    _ESYS_STATE_SENT,
    _ESYS_STATE_ERRORRESPONSE,
    _ESYS_STATE_FINISHED,
    _ESYS_STATE_RESUBMISSION
};

struct ESYS_CONTEXT {
    enum _ESYS_STATE state;
    TSS2_SYS_CONTEXT *sys;
    int32_t timeout;
    int submissionCount;
    TPM2B_DATA salt;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    ESYS_TR esys_handle_cnt;
    RSRC_NODE_T *rsrc_list;
    ESYS_TR session_type[3];
    RSRC_NODE_T *session_tab[3];
    int encryptNonceIdx;
    int authsCount;
    TPM2B_NONCE *encryptNonce;
    ESYS_TR esys_handle;
    IESYS_CMD_IN_PARAM in;
    TSS2_TCTI_CONTEXT *tcti_app_param;
};

#define _ESYS_MAX_SUMBISSIONS 5

#define _ESYS_ASSERT_NON_NULL(x)     if (x == NULL) {         LOG_ERROR(str(x) " == NULL.");         return TSS2_ESYS_RC_BAD_REFERENCE;     }

#ifdef __cplusplus
}
#endif
#endif /* ESYS_INT_H */
