/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
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
#ifndef TSS2_ESYS_H
#define TSS2_ESYS_H

#include "tss2_tcti.h"
#include "tss2_sys.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ESYS_TR;

#define ESYS_TR_NONE    0xfff
#define ESYS_TR_PASSWORD 0x0ff
#define ESYS_TR_PCR0    0
#define ESYS_TR_PCR1    1
#define ESYS_TR_PCR2    2
#define ESYS_TR_PCR3    3
#define ESYS_TR_PCR4    4
#define ESYS_TR_PCR5    5
#define ESYS_TR_PCR6    6
#define ESYS_TR_PCR7    7
#define ESYS_TR_PCR8    8
#define ESYS_TR_PCR9    9
#define ESYS_TR_PCR10    10
#define ESYS_TR_PCR11    11
#define ESYS_TR_PCR12    12
#define ESYS_TR_PCR13    13
#define ESYS_TR_PCR14    14
#define ESYS_TR_PCR15    15
#define ESYS_TR_PCR16    16
#define ESYS_TR_PCR17    17
#define ESYS_TR_PCR18    18
#define ESYS_TR_PCR19    19
#define ESYS_TR_PCR20    20
#define ESYS_TR_PCR21    21
#define ESYS_TR_PCR22    22
#define ESYS_TR_PCR23    23
#define ESYS_TR_PCR24    24
#define ESYS_TR_PCR25    25
#define ESYS_TR_PCR26    26
#define ESYS_TR_PCR27    27
#define ESYS_TR_PCR28    28
#define ESYS_TR_PCR29    29
#define ESYS_TR_PCR30    30
#define ESYS_TR_PCR31    31

/* From TPM_RH_CONSTANTS */
#define ESYS_TR_RH_OWNER    0x101
#define    ESYS_TR_RH_NULL        0x107
#define    ESYS_TR_RH_LOCKOUT    0x10A
#define    ESYS_TR_RH_ENDORSEMENT    0x10B
#define    ESYS_TR_RH_PLATFORM    0x10C
#define ESYS_TR_RH_PLATFORM_NV    0x10D
#define ESYS_TR_RH_AUTH_00    0x110
#define ESYS_TR_RH_AUTH_FF    0x20F

#define ESYS_TR_MIN_OBJECT 0x1000

typedef struct ESYS_CONTEXT ESYS_CONTEXT;

/*
 * TPM 2.0 ESAPI Functions
 */

TSS2_RC
Esys_Initialize(
    ESYS_CONTEXT **esys_context,
    TSS2_TCTI_CONTEXT *tcti,
    TSS2_ABI_VERSION *abiVersion);

void
Esys_Finalize(
    ESYS_CONTEXT **context);

TSS2_RC
Esys_GetTcti(
    ESYS_CONTEXT *esys_context,
    TSS2_TCTI_CONTEXT **tcti);

TSS2_RC
Esys_GetPollHandles(
    ESYS_CONTEXT *esys_context,
    TSS2_TCTI_POLL_HANDLE **handles,
    size_t *count);

TSS2_RC
Esys_SetTimeout(
    ESYS_CONTEXT *esys_context,
    int32_t timeout);

TSS2_RC
Esys_TR_Serialize(
    ESYS_CONTEXT *esys_context,
    ESYS_TR object,
    uint8_t **buffer,
    size_t *buffer_size);

TSS2_RC
Esys_TR_Deserialize(
    ESYS_CONTEXT *esys_context,
    uint8_t const *buffer,
    size_t buffer_size,
    ESYS_TR *esys_handle);

TSS2_RC
Esys_TR_FromTPMPublic_Async(
    ESYS_CONTEXT *esysContext,
    TPM2_HANDLE tpm_handle,
    ESYS_TR optionalSession1,
    ESYS_TR optionalSession2,
    ESYS_TR optionalSession3);

TSS2_RC
Esys_TR_FromTPMPublic_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *object);

TSS2_RC
Esys_TR_FromTPMPublic(
    ESYS_CONTEXT *esysContext,
    TPM2_HANDLE tpm_handle,
    ESYS_TR optionalSession1,
    ESYS_TR optionalSession2,
    ESYS_TR optionalSession3,
    ESYS_TR *object);

TSS2_RC
Esys_TR_Close(
    ESYS_CONTEXT *esys_context,
    ESYS_TR *rsrc_handle);

TSS2_RC
Esys_TR_SetAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_AUTH const *authValue);

TSS2_RC
Esys_TR_GetName(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_NAME **name);

TSS2_RC
Esys_TRSess_GetAttributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION *flags);

TSS2_RC
Esys_TRSess_SetAttributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION flags,
    TPMA_SESSION mask);

TSS2_RC
Esys_TRSess_SetSessionKey(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPM2B_AUTH const *key);

TSS2_RC
Esys_TRSess_GetNonceTPM(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPM2B_NONCE **nonceTPM);

/* Table 5 - TPM2_Startup Command */

TSS2_RC
Esys_Startup(
    ESYS_CONTEXT *esysContext,
    TPM2_SU startupType);

TSS2_RC
Esys_Startup_async(
    ESYS_CONTEXT *esysContext,
    TPM2_SU startupType);

TSS2_RC
Esys_Startup_finish(
    ESYS_CONTEXT *esysContext);

/* Table 7 - TPM2_Shutdown Command */

TSS2_RC
Esys_Shutdown(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_SU shutdownType);

TSS2_RC
Esys_Shutdown_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_SU shutdownType);

TSS2_RC
Esys_Shutdown_finish(
    ESYS_CONTEXT *esysContext);

/* Table 9 - TPM2_SelfTest Command */

TSS2_RC
Esys_SelfTest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO fullTest);

TSS2_RC
Esys_SelfTest_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO fullTest);

TSS2_RC
Esys_SelfTest_finish(
    ESYS_CONTEXT *esysContext);

/* Table 11 - TPM2_IncrementalSelfTest Command */

TSS2_RC
Esys_IncrementalSelfTest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_ALG *toTest,
    TPML_ALG **toDoList);

TSS2_RC
Esys_IncrementalSelfTest_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_ALG *toTest);

TSS2_RC
Esys_IncrementalSelfTest_finish(
    ESYS_CONTEXT *esysContext,
    TPML_ALG **toDoList);

/* Table 13 - TPM2_GetTestResult Command */

TSS2_RC
Esys_GetTestResult(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_MAX_BUFFER **outData,
    TPM2_RC *testResult);

TSS2_RC
Esys_GetTestResult_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_GetTestResult_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **outData,
    TPM2_RC *testResult);

/* Table 15 - TPM2_StartAuthSession Command */

TSS2_RC
Esys_StartAuthSession(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceCaller,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash,
    ESYS_TR *sessionHandle,
    TPM2B_NONCE **nonceTPM);

TSS2_RC
Esys_StartAuthSession_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceCaller,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash);

TSS2_RC
Esys_StartAuthSession_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *sessionHandle,
    TPM2B_NONCE **nonceTPM);

/* Table 17 - TPM2_PolicyRestart Command */

TSS2_RC
Esys_PolicyRestart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyRestart_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyRestart_finish(
    ESYS_CONTEXT *esysContext);

/* Table 19 - TPM2_Create Command */

TSS2_RC
Esys_Create(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

TSS2_RC
Esys_Create_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR);

TSS2_RC
Esys_Create_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

/* Table 21 - TPM2_Load Command */

TSS2_RC
Esys_Load(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    ESYS_TR *objectHandle);

TSS2_RC
Esys_Load_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inPrivate,
    const TPM2B_PUBLIC *inPublic);

TSS2_RC
Esys_Load_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle);

/* Table 23 - TPM2_LoadExternal Command */

TSS2_RC
Esys_LoadExternal(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    TPMI_RH_HIERARCHY hierarchy,
    ESYS_TR *objectHandle);

TSS2_RC
Esys_LoadExternal_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    TPMI_RH_HIERARCHY hierarchy);

TSS2_RC
Esys_LoadExternal_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle);

/* Table 25 - TPM2_ReadPublic Command */

TSS2_RC
Esys_ReadPublic(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_PUBLIC **outPublic,
    TPM2B_NAME **name,
    TPM2B_NAME **qualifiedName);

TSS2_RC
Esys_ReadPublic_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ReadPublic_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PUBLIC **outPublic,
    TPM2B_NAME **name,
    TPM2B_NAME **qualifiedName);

/* Table 27 - TPM2_ActivateCredential Command */

TSS2_RC
Esys_ActivateCredential(
    ESYS_CONTEXT *esysContext,
    ESYS_TR activateHandle,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ID_OBJECT *credentialBlob,
    const TPM2B_ENCRYPTED_SECRET *secret,
    TPM2B_DIGEST **certInfo);

TSS2_RC
Esys_ActivateCredential_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR activateHandle,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ID_OBJECT *credentialBlob,
    const TPM2B_ENCRYPTED_SECRET *secret);

TSS2_RC
Esys_ActivateCredential_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **certInfo);

/* Table 29 - TPM2_MakeCredential Command */

TSS2_RC
Esys_MakeCredential(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *credential,
    const TPM2B_NAME *objectName,
    TPM2B_ID_OBJECT **credentialBlob,
    TPM2B_ENCRYPTED_SECRET **secret);

TSS2_RC
Esys_MakeCredential_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *credential,
    const TPM2B_NAME *objectName);

TSS2_RC
Esys_MakeCredential_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ID_OBJECT **credentialBlob,
    TPM2B_ENCRYPTED_SECRET **secret);

/* Table 31 - TPM2_Unseal Command */

TSS2_RC
Esys_Unseal(
    ESYS_CONTEXT *esysContext,
    ESYS_TR itemHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_SENSITIVE_DATA **outData);

TSS2_RC
Esys_Unseal_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR itemHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_Unseal_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_SENSITIVE_DATA **outData);

/* Table 33 - TPM2_ObjectChangeAuth Command */

TSS2_RC
Esys_ObjectChangeAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth,
    TPM2B_PRIVATE **outPrivate);

TSS2_RC
Esys_ObjectChangeAuth_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

TSS2_RC
Esys_ObjectChangeAuth_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outPrivate);

/* Table 35 - TPM2_CreateLoaded Command */

TSS2_RC
Esys_CreateLoaded(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_TEMPLATE *inPublic,
    ESYS_TR *objectHandle,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic);

TSS2_RC
Esys_CreateLoaded_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_TEMPLATE *inPublic);

TSS2_RC
Esys_CreateLoaded_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic);

/* Table 37 - TPM2_Duplicate Command */

TSS2_RC
Esys_Duplicate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR newParentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_DATA **encryptionKeyOut,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

TSS2_RC
Esys_Duplicate_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR newParentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg);

TSS2_RC
Esys_Duplicate_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DATA **encryptionKeyOut,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

/* Table 39 - TPM2_Rewrap Command */

TSS2_RC
Esys_Rewrap(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

TSS2_RC
Esys_Rewrap_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed);

TSS2_RC
Esys_Rewrap_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

/* Table 41 - TPM2_Import Command */

TSS2_RC
Esys_Import(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKey,
    const TPM2B_PUBLIC *objectPublic,
    const TPM2B_PRIVATE *duplicate,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_PRIVATE **outPrivate);

TSS2_RC
Esys_Import_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKey,
    const TPM2B_PUBLIC *objectPublic,
    const TPM2B_PRIVATE *duplicate,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg);

TSS2_RC
Esys_Import_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outPrivate);

/* Table 45 - TPM2_RSA_Encrypt Command */

TSS2_RC
Esys_RSA_Encrypt(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *message,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label,
    TPM2B_PUBLIC_KEY_RSA **outData);

TSS2_RC
Esys_RSA_Encrypt_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *message,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label);

TSS2_RC
Esys_RSA_Encrypt_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PUBLIC_KEY_RSA **outData);

/* Table 47 - TPM2_RSA_Decrypt Command */

TSS2_RC
Esys_RSA_Decrypt(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *cipherText,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label,
    TPM2B_PUBLIC_KEY_RSA **message);

TSS2_RC
Esys_RSA_Decrypt_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *cipherText,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label);

TSS2_RC
Esys_RSA_Decrypt_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PUBLIC_KEY_RSA **message);

/* Table 49 - TPM2_ECDH_KeyGen Command */

TSS2_RC
Esys_ECDH_KeyGen(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_ECC_POINT **zPoint,
    TPM2B_ECC_POINT **pubPoint);

TSS2_RC
Esys_ECDH_KeyGen_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ECDH_KeyGen_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **zPoint,
    TPM2B_ECC_POINT **pubPoint);

/* Table 51 - TPM2_ECDH_ZGen Command */

TSS2_RC
Esys_ECDH_ZGen(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inPoint,
    TPM2B_ECC_POINT **outPoint);

TSS2_RC
Esys_ECDH_ZGen_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inPoint);

TSS2_RC
Esys_ECDH_ZGen_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **outPoint);

/* Table 53 - TPM2_ECC_Parameters Command */

TSS2_RC
Esys_ECC_Parameters(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID,
    TPMS_ALGORITHM_DETAIL_ECC **parameters);

TSS2_RC
Esys_ECC_Parameters_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID);

TSS2_RC
Esys_ECC_Parameters_finish(
    ESYS_CONTEXT *esysContext,
    TPMS_ALGORITHM_DETAIL_ECC **parameters);

/* Table 55 - TPM2_ZGen_2Phase Command */

TSS2_RC
Esys_ZGen_2Phase(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyA,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inQsB,
    const TPM2B_ECC_POINT *inQeB,
    TPMI_ECC_KEY_EXCHANGE inScheme,
    UINT16 counter,
    TPM2B_ECC_POINT **outZ1,
    TPM2B_ECC_POINT **outZ2);

TSS2_RC
Esys_ZGen_2Phase_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyA,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inQsB,
    const TPM2B_ECC_POINT *inQeB,
    TPMI_ECC_KEY_EXCHANGE inScheme,
    UINT16 counter);

TSS2_RC
Esys_ZGen_2Phase_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **outZ1,
    TPM2B_ECC_POINT **outZ2);

/* Table 58 - TPM2_EncryptDecrypt Command */

TSS2_RC
Esys_EncryptDecrypt(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn,
    const TPM2B_MAX_BUFFER *inData,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

TSS2_RC
Esys_EncryptDecrypt_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn,
    const TPM2B_MAX_BUFFER *inData);

TSS2_RC
Esys_EncryptDecrypt_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

/* Table 60 - TPM2_EncryptDecrypt2 Command */

TSS2_RC
Esys_EncryptDecrypt2(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *inData,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

TSS2_RC
Esys_EncryptDecrypt2_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *inData,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn);

TSS2_RC
Esys_EncryptDecrypt2_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

/* Table 62 - TPM2_Hash Command */

TSS2_RC
Esys_Hash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **outHash,
    TPMT_TK_HASHCHECK **validation);

TSS2_RC
Esys_Hash_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy);

TSS2_RC
Esys_Hash_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **outHash,
    TPMT_TK_HASHCHECK **validation);

/* Table 64 - TPM2_HMAC Command */

TSS2_RC
Esys_HMAC(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_ALG_HASH hashAlg,
    TPM2B_DIGEST **outHMAC);

TSS2_RC
Esys_HMAC_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_ALG_HASH hashAlg);

TSS2_RC
Esys_HMAC_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **outHMAC);

/* Table 66 - TPM2_GetRandom Command */

TSS2_RC
Esys_GetRandom(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 bytesRequested,
    TPM2B_DIGEST **randomBytes);

TSS2_RC
Esys_GetRandom_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 bytesRequested);

TSS2_RC
Esys_GetRandom_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **randomBytes);

/* Table 68 - TPM2_StirRandom Command */

TSS2_RC
Esys_StirRandom(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_DATA *inData);

TSS2_RC
Esys_StirRandom_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_DATA *inData);

TSS2_RC
Esys_StirRandom_finish(
    ESYS_CONTEXT *esysContext);

/* Table 71 - TPM2_HMAC_Start Command */

TSS2_RC
Esys_HMAC_Start(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg,
    ESYS_TR *sequenceHandle);

TSS2_RC
Esys_HMAC_Start_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg);

TSS2_RC
Esys_HMAC_Start_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *sequenceHandle);

/* Table 73 - TPM2_HashSequenceStart Command */

TSS2_RC
Esys_HashSequenceStart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg,
    ESYS_TR *sequenceHandle);

TSS2_RC
Esys_HashSequenceStart_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg);

TSS2_RC
Esys_HashSequenceStart_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *sequenceHandle);

/* Table 75 - TPM2_SequenceUpdate Command */

TSS2_RC
Esys_SequenceUpdate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

TSS2_RC
Esys_SequenceUpdate_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

TSS2_RC
Esys_SequenceUpdate_finish(
    ESYS_CONTEXT *esysContext);

/* Table 77 - TPM2_SequenceComplete Command */

TSS2_RC
Esys_SequenceComplete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation);

TSS2_RC
Esys_SequenceComplete_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_RH_HIERARCHY hierarchy);

TSS2_RC
Esys_SequenceComplete_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation);

/* Table 79 - TPM2_EventSequenceComplete Command */

TSS2_RC
Esys_EventSequenceComplete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPML_DIGEST_VALUES **results);

TSS2_RC
Esys_EventSequenceComplete_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

TSS2_RC
Esys_EventSequenceComplete_finish(
    ESYS_CONTEXT *esysContext,
    TPML_DIGEST_VALUES **results);

/* Table 81 - TPM2_Certify Command */

TSS2_RC
Esys_Certify(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_Certify_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

TSS2_RC
Esys_Certify_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

/* Table 83 - TPM2_CertifyCreation Command */

TSS2_RC
Esys_CertifyCreation(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_CertifyCreation_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket);

TSS2_RC
Esys_CertifyCreation_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

/* Table 85 - TPM2_Quote Command */

TSS2_RC
Esys_Quote(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    const TPML_PCR_SELECTION *PCRselect,
    TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_Quote_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    const TPML_PCR_SELECTION *PCRselect);

TSS2_RC
Esys_Quote_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature);

/* Table 87 - TPM2_GetSessionAuditDigest Command */

TSS2_RC
Esys_GetSessionAuditDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_GetSessionAuditDigest_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

TSS2_RC
Esys_GetSessionAuditDigest_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

/* Table 89 - TPM2_GetCommandAuditDigest Command */

TSS2_RC
Esys_GetCommandAuditDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_GetCommandAuditDigest_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

TSS2_RC
Esys_GetCommandAuditDigest_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

/* Table 91 - TPM2_GetTime Command */

TSS2_RC
Esys_GetTime(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **timeInfo,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_GetTime_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

TSS2_RC
Esys_GetTime_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **timeInfo,
    TPMT_SIGNATURE **signature);

/* Table 93 - TPM2_Commit Command */

TSS2_RC
Esys_Commit(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2,
    TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L,
    TPM2B_ECC_POINT **E,
    UINT16 *counter);

TSS2_RC
Esys_Commit_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2);

TSS2_RC
Esys_Commit_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L,
    TPM2B_ECC_POINT **E,
    UINT16 *counter);

/* Table 95 - TPM2_EC_Ephemeral Command */

TSS2_RC
Esys_EC_Ephemeral(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID,
    TPM2B_ECC_POINT **Q,
    UINT16 *counter);

TSS2_RC
Esys_EC_Ephemeral_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID);

TSS2_RC
Esys_EC_Ephemeral_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **Q,
    UINT16 *counter);

/* Table 97 - TPM2_VerifySignature Command */

TSS2_RC
Esys_VerifySignature(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIGNATURE *signature,
    TPMT_TK_VERIFIED **validation);

TSS2_RC
Esys_VerifySignature_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIGNATURE *signature);

TSS2_RC
Esys_VerifySignature_finish(
    ESYS_CONTEXT *esysContext,
    TPMT_TK_VERIFIED **validation);

/* Table 99 - TPM2_Sign Command */

TSS2_RC
Esys_Sign(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_HASHCHECK *validation,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_Sign_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_HASHCHECK *validation);

TSS2_RC
Esys_Sign_finish(
    ESYS_CONTEXT *esysContext,
    TPMT_SIGNATURE **signature);

/* Table 101 - TPM2_SetCommandCodeAuditStatus Command */

TSS2_RC
Esys_SetCommandCodeAuditStatus(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ALG_HASH auditAlg,
    const TPML_CC *setList,
    const TPML_CC *clearList);

TSS2_RC
Esys_SetCommandCodeAuditStatus_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ALG_HASH auditAlg,
    const TPML_CC *setList,
    const TPML_CC *clearList);

TSS2_RC
Esys_SetCommandCodeAuditStatus_finish(
    ESYS_CONTEXT *esysContext);

/* Table 103 - TPM2_PCR_Extend Command */

TSS2_RC
Esys_PCR_Extend(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST_VALUES *digests);

TSS2_RC
Esys_PCR_Extend_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST_VALUES *digests);

TSS2_RC
Esys_PCR_Extend_finish(
    ESYS_CONTEXT *esysContext);

/* Table 105 - TPM2_PCR_Event Command */

TSS2_RC
Esys_PCR_Event(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_EVENT *eventData,
    TPML_DIGEST_VALUES **digests);

TSS2_RC
Esys_PCR_Event_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_EVENT *eventData);

TSS2_RC
Esys_PCR_Event_finish(
    ESYS_CONTEXT *esysContext,
    TPML_DIGEST_VALUES **digests);

/* Table 107 - TPM2_PCR_Read Command */

TSS2_RC
Esys_PCR_Read(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrSelectionIn,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION **pcrSelectionOut,
    TPML_DIGEST **pcrValues);

TSS2_RC
Esys_PCR_Read_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrSelectionIn);

TSS2_RC
Esys_PCR_Read_finish(
    ESYS_CONTEXT *esysContext,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION **pcrSelectionOut,
    TPML_DIGEST **pcrValues);

/* Table 109 - TPM2_PCR_Allocate Command */

TSS2_RC
Esys_PCR_Allocate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrAllocation,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable);

TSS2_RC
Esys_PCR_Allocate_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrAllocation);

TSS2_RC
Esys_PCR_Allocate_finish(
    ESYS_CONTEXT *esysContext,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable);

/* Table 111 - TPM2_PCR_SetAuthPolicy Command */

TSS2_RC
Esys_PCR_SetAuthPolicy(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg,
    TPMI_DH_PCR pcrNum);

TSS2_RC
Esys_PCR_SetAuthPolicy_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg,
    TPMI_DH_PCR pcrNum);

TSS2_RC
Esys_PCR_SetAuthPolicy_finish(
    ESYS_CONTEXT *esysContext);

/* Table 113 - TPM2_PCR_SetAuthValue Command */

TSS2_RC
Esys_PCR_SetAuthValue(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *auth);

TSS2_RC
Esys_PCR_SetAuthValue_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *auth);

TSS2_RC
Esys_PCR_SetAuthValue_finish(
    ESYS_CONTEXT *esysContext);

/* Table 115 - TPM2_PCR_Reset Command */

TSS2_RC
Esys_PCR_Reset(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PCR_Reset_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PCR_Reset_finish(
    ESYS_CONTEXT *esysContext);

/* Table 117 - TPM2_PolicySigned Command */

TSS2_RC
Esys_PolicySigned(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authObject,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    const TPMT_SIGNATURE *auth,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

TSS2_RC
Esys_PolicySigned_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authObject,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    const TPMT_SIGNATURE *auth);

TSS2_RC
Esys_PolicySigned_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

/* Table 119 - TPM2_PolicySecret Command */

TSS2_RC
Esys_PolicySecret(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

TSS2_RC
Esys_PolicySecret_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration);

TSS2_RC
Esys_PolicySecret_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

/* Table 121 - TPM2_PolicyTicket Command */

TSS2_RC
Esys_PolicyTicket(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_TIMEOUT *timeout,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *authName,
    const TPMT_TK_AUTH *ticket);

TSS2_RC
Esys_PolicyTicket_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_TIMEOUT *timeout,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *authName,
    const TPMT_TK_AUTH *ticket);

TSS2_RC
Esys_PolicyTicket_finish(
    ESYS_CONTEXT *esysContext);

/* Table 123 - TPM2_PolicyOR Command */

TSS2_RC
Esys_PolicyOR(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST *pHashList);

TSS2_RC
Esys_PolicyOR_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST *pHashList);

TSS2_RC
Esys_PolicyOR_finish(
    ESYS_CONTEXT *esysContext);

/* Table 125 - TPM2_PolicyPCR Command */

TSS2_RC
Esys_PolicyPCR(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs);

TSS2_RC
Esys_PolicyPCR_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs);

TSS2_RC
Esys_PolicyPCR_finish(
    ESYS_CONTEXT *esysContext);

/* Table 127 - TPM2_PolicyLocality Command */

TSS2_RC
Esys_PolicyLocality(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    TPMA_LOCALITY locality);

TSS2_RC
Esys_PolicyLocality_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    TPMA_LOCALITY locality);

TSS2_RC
Esys_PolicyLocality_finish(
    ESYS_CONTEXT *esysContext);

/* Table 129 - TPM2_PolicyNV Command */

TSS2_RC
Esys_PolicyNV(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

TSS2_RC
Esys_PolicyNV_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

TSS2_RC
Esys_PolicyNV_finish(
    ESYS_CONTEXT *esysContext);

/* Table 131 - TPM2_PolicyCounterTimer Command */

TSS2_RC
Esys_PolicyCounterTimer(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

TSS2_RC
Esys_PolicyCounterTimer_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

TSS2_RC
Esys_PolicyCounterTimer_finish(
    ESYS_CONTEXT *esysContext);

/* Table 133 - TPM2_PolicyCommandCode Command */

TSS2_RC
Esys_PolicyCommandCode(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code);

TSS2_RC
Esys_PolicyCommandCode_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code);

TSS2_RC
Esys_PolicyCommandCode_finish(
    ESYS_CONTEXT *esysContext);

/* Table 135 - TPM2_PolicyPhysicalPresence Command */

TSS2_RC
Esys_PolicyPhysicalPresence(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyPhysicalPresence_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyPhysicalPresence_finish(
    ESYS_CONTEXT *esysContext);

/* Table 137 - TPM2_PolicyCpHash Command */

TSS2_RC
Esys_PolicyCpHash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_DIGEST *cpHashA);

TSS2_RC
Esys_PolicyCpHash_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_DIGEST *cpHashA);

TSS2_RC
Esys_PolicyCpHash_finish(
    ESYS_CONTEXT *esysContext);

/* Table 139 - TPM2_PolicyNameHash Command */

TSS2_RC
Esys_PolicyNameHash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_DIGEST *nameHash);

TSS2_RC
Esys_PolicyNameHash_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_DIGEST *nameHash);

TSS2_RC
Esys_PolicyNameHash_finish(
    ESYS_CONTEXT *esysContext);

/* Table 141 - TPM2_PolicyDuplicationSelect Command */

TSS2_RC
Esys_PolicyDuplicationSelect(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_NAME *objectName,
    const TPM2B_NAME *newParentName,
    TPMI_YES_NO includeObject);

TSS2_RC
Esys_PolicyDuplicationSelect_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_NAME *objectName,
    const TPM2B_NAME *newParentName,
    TPMI_YES_NO includeObject);

TSS2_RC
Esys_PolicyDuplicationSelect_finish(
    ESYS_CONTEXT *esysContext);

/* Table 143 - TPM2_PolicyAuthorize Command */

TSS2_RC
Esys_PolicyAuthorize(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *approvedPolicy,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *keySign,
    const TPMT_TK_VERIFIED *checkTicket);

TSS2_RC
Esys_PolicyAuthorize_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *approvedPolicy,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *keySign,
    const TPMT_TK_VERIFIED *checkTicket);

TSS2_RC
Esys_PolicyAuthorize_finish(
    ESYS_CONTEXT *esysContext);

/* Table 145 - TPM2_PolicyAuthValue Command */

TSS2_RC
Esys_PolicyAuthValue(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyAuthValue_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyAuthValue_finish(
    ESYS_CONTEXT *esysContext);

/* Table 147 - TPM2_PolicyPassword Command */

TSS2_RC
Esys_PolicyPassword(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyPassword_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyPassword_finish(
    ESYS_CONTEXT *esysContext);

/* Table 149 - TPM2_PolicyGetDigest Command */

TSS2_RC
Esys_PolicyGetDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST **policyDigest);

TSS2_RC
Esys_PolicyGetDigest_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyGetDigest_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **policyDigest);

/* Table 151 - TPM2_PolicyNvWritten Command */

TSS2_RC
Esys_PolicyNvWritten(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO writtenSet);

TSS2_RC
Esys_PolicyNvWritten_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO writtenSet);

TSS2_RC
Esys_PolicyNvWritten_finish(
    ESYS_CONTEXT *esysContext);

/* Table 153 - TPM2_PolicyTemplate Command */

TSS2_RC
Esys_PolicyTemplate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_DIGEST *templateHash);

TSS2_RC
Esys_PolicyTemplate_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_SH_POLICY policySession,
    const TPM2B_DIGEST *templateHash);

TSS2_RC
Esys_PolicyTemplate_finish(
    ESYS_CONTEXT *esysContext);

/* Table 155 - TPM2_PolicyAuthorizeNV Command */

TSS2_RC
Esys_PolicyAuthorizeNV(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyAuthorizeNV_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_PolicyAuthorizeNV_finish(
    ESYS_CONTEXT *esysContext);

/* Table 157 - TPM2_CreatePrimary Command */

TSS2_RC
Esys_CreatePrimary(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

TSS2_RC
Esys_CreatePrimary_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR);

TSS2_RC
Esys_CreatePrimary_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

/* Table 159 - TPM2_HierarchyControl Command */

TSS2_RC
Esys_HierarchyControl(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_RH_ENABLES enable,
    TPMI_YES_NO state);

TSS2_RC
Esys_HierarchyControl_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_RH_ENABLES enable,
    TPMI_YES_NO state);

TSS2_RC
Esys_HierarchyControl_finish(
    ESYS_CONTEXT *esysContext);

/* Table 161 - TPM2_SetPrimaryPolicy Command */

TSS2_RC
Esys_SetPrimaryPolicy(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg);

TSS2_RC
Esys_SetPrimaryPolicy_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg);

TSS2_RC
Esys_SetPrimaryPolicy_finish(
    ESYS_CONTEXT *esysContext);

/* Table 163 - TPM2_ChangePPS Command */

TSS2_RC
Esys_ChangePPS(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ChangePPS_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ChangePPS_finish(
    ESYS_CONTEXT *esysContext);

/* Table 165 - TPM2_ChangeEPS Command */

TSS2_RC
Esys_ChangeEPS(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ChangeEPS_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ChangeEPS_finish(
    ESYS_CONTEXT *esysContext);

/* Table 167 - TPM2_Clear Command */

TSS2_RC
Esys_Clear(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_Clear_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_Clear_finish(
    ESYS_CONTEXT *esysContext);

/* Table 169 - TPM2_ClearControl Command */

TSS2_RC
Esys_ClearControl(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO disable);

TSS2_RC
Esys_ClearControl_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO disable);

TSS2_RC
Esys_ClearControl_finish(
    ESYS_CONTEXT *esysContext);

/* Table 171 - TPM2_HierarchyChangeAuth Command */

TSS2_RC
Esys_HierarchyChangeAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

TSS2_RC
Esys_HierarchyChangeAuth_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

TSS2_RC
Esys_HierarchyChangeAuth_finish(
    ESYS_CONTEXT *esysContext);

/* Table 173 - TPM2_DictionaryAttackLockReset Command */

TSS2_RC
Esys_DictionaryAttackLockReset(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_DictionaryAttackLockReset_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_DictionaryAttackLockReset_finish(
    ESYS_CONTEXT *esysContext);

/* Table 175 - TPM2_DictionaryAttackParameters Command */

TSS2_RC
Esys_DictionaryAttackParameters(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery);

TSS2_RC
Esys_DictionaryAttackParameters_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery);

TSS2_RC
Esys_DictionaryAttackParameters_finish(
    ESYS_CONTEXT *esysContext);

/* Table 177 - TPM2_PP_Commands Command */

TSS2_RC
Esys_PP_Commands(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_CC *setList,
    const TPML_CC *clearList);

TSS2_RC
Esys_PP_Commands_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_CC *setList,
    const TPML_CC *clearList);

TSS2_RC
Esys_PP_Commands_finish(
    ESYS_CONTEXT *esysContext);

/* Table 179 - TPM2_SetAlgorithmSet Command */

TSS2_RC
Esys_SetAlgorithmSet(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 algorithmSet);

TSS2_RC
Esys_SetAlgorithmSet_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 algorithmSet);

TSS2_RC
Esys_SetAlgorithmSet_finish(
    ESYS_CONTEXT *esysContext);

/* Table 181 - TPM2_FieldUpgradeStart Command */

TSS2_RC
Esys_FieldUpgradeStart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authorization,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *fuDigest,
    const TPMT_SIGNATURE *manifestSignature);

TSS2_RC
Esys_FieldUpgradeStart_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authorization,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *fuDigest,
    const TPMT_SIGNATURE *manifestSignature);

TSS2_RC
Esys_FieldUpgradeStart_finish(
    ESYS_CONTEXT *esysContext);

/* Table 183 - TPM2_FieldUpgradeData Command */

TSS2_RC
Esys_FieldUpgradeData(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *fuData,
    TPMT_HA **nextDigest,
    TPMT_HA **firstDigest);

TSS2_RC
Esys_FieldUpgradeData_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *fuData);

TSS2_RC
Esys_FieldUpgradeData_finish(
    ESYS_CONTEXT *esysContext,
    TPMT_HA **nextDigest,
    TPMT_HA **firstDigest);

/* Table 185 - TPM2_FirmwareRead Command */

TSS2_RC
Esys_FirmwareRead(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 sequenceNumber,
    TPM2B_MAX_BUFFER **fuData);

TSS2_RC
Esys_FirmwareRead_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 sequenceNumber);

TSS2_RC
Esys_FirmwareRead_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **fuData);

/* Table 187 - TPM2_ContextSave Command */

TSS2_RC
Esys_ContextSave(
    ESYS_CONTEXT *esysContext,
    ESYS_TR saveHandle,
    TPMS_CONTEXT **context);

TSS2_RC
Esys_ContextSave_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR saveHandle);

TSS2_RC
Esys_ContextSave_finish(
    ESYS_CONTEXT *esysContext,
    TPMS_CONTEXT **context);

/* Table 189 - TPM2_ContextLoad Command */

TSS2_RC
Esys_ContextLoad(
    ESYS_CONTEXT *esysContext,
    const TPMS_CONTEXT *context,
    ESYS_TR *loadedHandle);

TSS2_RC
Esys_ContextLoad_async(
    ESYS_CONTEXT *esysContext,
    const TPMS_CONTEXT *context);

TSS2_RC
Esys_ContextLoad_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *loadedHandle);

/* Table 191 - TPM2_FlushContext Command */

TSS2_RC
Esys_FlushContext(
    ESYS_CONTEXT *esysContext,
    ESYS_TR flushHandle);

TSS2_RC
Esys_FlushContext_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR flushHandle);

TSS2_RC
Esys_FlushContext_finish(
    ESYS_CONTEXT *esysContext);

/* Table 193 - TPM2_EvictControl Command */

TSS2_RC
Esys_EvictControl(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_DH_PERSISTENT persistentHandle,
    ESYS_TR *newObjectHandle);

TSS2_RC
Esys_EvictControl_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_DH_PERSISTENT persistentHandle);

TSS2_RC
Esys_EvictControl_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *newObjectHandle);

/* Table 195 - TPM2_ReadClock Command */

TSS2_RC
Esys_ReadClock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMS_TIME_INFO **currentTime);

TSS2_RC
Esys_ReadClock_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_ReadClock_finish(
    ESYS_CONTEXT *esysContext,
    TPMS_TIME_INFO **currentTime);

/* Table 197 - TPM2_ClockSet Command */

TSS2_RC
Esys_ClockSet(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 newTime);

TSS2_RC
Esys_ClockSet_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 newTime);

TSS2_RC
Esys_ClockSet_finish(
    ESYS_CONTEXT *esysContext);

/* Table 199 - TPM2_ClockRateAdjust Command */

TSS2_RC
Esys_ClockRateAdjust(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CLOCK_ADJUST rateAdjust);

TSS2_RC
Esys_ClockRateAdjust_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CLOCK_ADJUST rateAdjust);

TSS2_RC
Esys_ClockRateAdjust_finish(
    ESYS_CONTEXT *esysContext);

/* Table 201 - TPM2_GetCapability Command */

TSS2_RC
Esys_GetCapability(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CAP capability,
    UINT32 property,
    UINT32 propertyCount,
    TPMI_YES_NO *moreData,
    TPMS_CAPABILITY_DATA **capabilityData);

TSS2_RC
Esys_GetCapability_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CAP capability,
    UINT32 property,
    UINT32 propertyCount);

TSS2_RC
Esys_GetCapability_finish(
    ESYS_CONTEXT *esysContext,
    TPMI_YES_NO *moreData,
    TPMS_CAPABILITY_DATA **capabilityData);

/* Table 203 - TPM2_TestParms Command */

TSS2_RC
Esys_TestParms(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPMT_PUBLIC_PARMS *parameters);

TSS2_RC
Esys_TestParms_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPMT_PUBLIC_PARMS *parameters);

TSS2_RC
Esys_TestParms_finish(
    ESYS_CONTEXT *esysContext);

/* Table 205 - TPM2_NV_DefineSpace Command */

TSS2_RC
Esys_NV_DefineSpace(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    const TPM2B_NV_PUBLIC *publicInfo,
    ESYS_TR *nvHandle);

TSS2_RC
Esys_NV_DefineSpace_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    const TPM2B_NV_PUBLIC *publicInfo);

TSS2_RC
Esys_NV_DefineSpace_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *nvHandle);

/* Table 207 - TPM2_NV_UndefineSpace Command */

TSS2_RC
Esys_NV_UndefineSpace(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_UndefineSpace_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_UndefineSpace_finish(
    ESYS_CONTEXT *esysContext);

/* Table 209 - TPM2_NV_UndefineSpaceSpecial Command */

TSS2_RC
Esys_NV_UndefineSpaceSpecial(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR platform,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_UndefineSpaceSpecial_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR platform,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_UndefineSpaceSpecial_finish(
    ESYS_CONTEXT *esysContext);

/* Table 211 - TPM2_NV_ReadPublic Command */

TSS2_RC
Esys_NV_ReadPublic(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_NV_PUBLIC **nvPublic,
    TPM2B_NAME **nvName);

TSS2_RC
Esys_NV_ReadPublic_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_ReadPublic_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_NV_PUBLIC **nvPublic,
    TPM2B_NAME **nvName);

/* Table 213 - TPM2_NV_Write Command */

TSS2_RC
Esys_NV_Write(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset);

TSS2_RC
Esys_NV_Write_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset);

TSS2_RC
Esys_NV_Write_finish(
    ESYS_CONTEXT *esysContext);

/* Table 215 - TPM2_NV_Increment Command */

TSS2_RC
Esys_NV_Increment(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_Increment_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_Increment_finish(
    ESYS_CONTEXT *esysContext);

/* Table 217 - TPM2_NV_Extend Command */

TSS2_RC
Esys_NV_Extend(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data);

TSS2_RC
Esys_NV_Extend_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data);

TSS2_RC
Esys_NV_Extend_finish(
    ESYS_CONTEXT *esysContext);

/* Table 219 - TPM2_NV_SetBits Command */

TSS2_RC
Esys_NV_SetBits(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 bits);

TSS2_RC
Esys_NV_SetBits_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 bits);

TSS2_RC
Esys_NV_SetBits_finish(
    ESYS_CONTEXT *esysContext);

/* Table 221 - TPM2_NV_WriteLock Command */

TSS2_RC
Esys_NV_WriteLock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_WriteLock_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_WriteLock_finish(
    ESYS_CONTEXT *esysContext);

/* Table 223 - TPM2_NV_GlobalWriteLock Command */

TSS2_RC
Esys_NV_GlobalWriteLock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_GlobalWriteLock_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_GlobalWriteLock_finish(
    ESYS_CONTEXT *esysContext);

/* Table 225 - TPM2_NV_Read Command */

TSS2_RC
Esys_NV_Read(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 size,
    UINT16 offset,
    TPM2B_MAX_NV_BUFFER **data);

TSS2_RC
Esys_NV_Read_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 size,
    UINT16 offset);

TSS2_RC
Esys_NV_Read_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_NV_BUFFER **data);

/* Table 227 - TPM2_NV_ReadLock Command */

TSS2_RC
Esys_NV_ReadLock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_ReadLock_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC
Esys_NV_ReadLock_finish(
    ESYS_CONTEXT *esysContext);

/* Table 229 - TPM2_NV_ChangeAuth Command */

TSS2_RC
Esys_NV_ChangeAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

TSS2_RC
Esys_NV_ChangeAuth_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

TSS2_RC
Esys_NV_ChangeAuth_finish(
    ESYS_CONTEXT *esysContext);

/* Table 231 - TPM2_NV_Certify Command */

TSS2_RC
Esys_NV_Certify(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

TSS2_RC
Esys_NV_Certify_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset);

TSS2_RC
Esys_NV_Certify_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

/* Table 233 - TPM2_Vendor_TCG_Test Command */

TSS2_RC
Esys_Vendor_TCG_Test(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *inputData,
    TPM2B_DATA **outputData);

TSS2_RC
Esys_Vendor_TCG_Test_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *inputData);

TSS2_RC
Esys_Vendor_TCG_Test_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DATA **outputData);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_ESYS_H */
