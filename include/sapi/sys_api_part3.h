/***********************************************************************;
 * Copyright (c) 2015 - 2017 Intel Corporation
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
 ***********************************************************************/

#ifndef TSS2_SYS_API_PART3_H
#define TSS2_SYS_API_PART3_H

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files. \
       Do not include this file, #include <sapi/tpm20.h> instead.
#endif  /* TSS2_API_VERSION_1_1_1_1 */

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_Startup_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_Shutdown_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_SelfTest_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyRestart_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_StirRandom_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_SequenceUpdate_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_SetCommandCodeAuditStatus_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PCR_Extend_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PCR_SetAuthPolicy_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PCR_SetAuthValue_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PCR_Reset_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyTicket_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyOR_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyPCR_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyLocality_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyNV_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyCounterTimer_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyCommandCode_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyPhysicalPresence_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyCpHash_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyNameHash_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyDuplicationSelect_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyAuthorize_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyAuthValue_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyPassword_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PolicyNvWritten_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_HierarchyControl_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_SetPrimaryPolicy_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_ChangePPS_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_ChangeEPS_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_Clear_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_ClearControl_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_HierarchyChangeAuth_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_DictionaryAttackLockReset_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_DictionaryAttackParameters_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_PP_Commands_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_SetAlgorithmSet_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_FieldUpgradeStart_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_FlushContext_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_EvictControl_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_ClockSet_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_ClockRateAdjust_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_TestParms_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_DefineSpace_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_UndefineSpace_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_UndefineSpaceSpecial_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_Write_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_Increment_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_Extend_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_SetBits_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_WriteLock_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_GlobalWriteLock_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_ReadLock_Out;

typedef struct {
	TPM_ST tag;
	UINT32 responseSize;
	UINT32 responseCode;
	UINT8 otherData;
} TPM20_NV_ChangeAuth_Out;



TSS2_RC Tss2_Sys_Startup_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_SU	startupType
    );

TSS2_RC Tss2_Sys_Startup(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_SU	startupType
    );

TSS2_RC Tss2_Sys_Shutdown_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_SU	shutdownType
    );

TSS2_RC Tss2_Sys_Shutdown(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM_SU	shutdownType,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_SelfTest_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO	fullTest
    );

TSS2_RC Tss2_Sys_SelfTest(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_YES_NO	fullTest,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_IncrementalSelfTest_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPML_ALG	*toTest
    );

TSS2_RC Tss2_Sys_IncrementalSelfTest_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPML_ALG	*toDoList
    );

TSS2_RC Tss2_Sys_IncrementalSelfTest(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPML_ALG	*toTest,
    TPML_ALG	*toDoList,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetTestResult_Prepare(
    TSS2_SYS_CONTEXT *sysContext
    );

TSS2_RC Tss2_Sys_GetTestResult_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER	*outData,
    TPM_RC	*testResult
    );

TSS2_RC Tss2_Sys_GetTestResult(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_MAX_BUFFER	*outData,
    TPM_RC	*testResult,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_StartAuthSession_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	tpmKey,
    TPMI_DH_ENTITY	bind,
    const TPM2B_NONCE	*nonceCaller,
    const TPM2B_ENCRYPTED_SECRET	*encryptedSalt,
    TPM_SE	sessionType,
    const TPMT_SYM_DEF	*symmetric,
    TPMI_ALG_HASH	authHash
    );

TSS2_RC Tss2_Sys_StartAuthSession_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_AUTH_SESSION	*sessionHandle,
    TPM2B_NONCE	*nonceTPM
    );

TSS2_RC Tss2_Sys_StartAuthSession(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	tpmKey,
    TPMI_DH_ENTITY	bind,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_NONCE	*nonceCaller,
    const TPM2B_ENCRYPTED_SECRET	*encryptedSalt,
    TPM_SE	sessionType,
    const TPMT_SYM_DEF	*symmetric,
    TPMI_ALG_HASH	authHash,
    TPMI_SH_AUTH_SESSION	*sessionHandle,
    TPM2B_NONCE	*nonceTPM,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyRestart_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	sessionHandle
    );

TSS2_RC Tss2_Sys_PolicyRestart(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	sessionHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Create_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	parentHandle,
    const TPM2B_SENSITIVE_CREATE	*inSensitive,
    const TPM2B_PUBLIC	*inPublic,
    const TPM2B_DATA	*outsideInfo,
    const TPML_PCR_SELECTION	*creationPCR
    );

TSS2_RC Tss2_Sys_Create_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PRIVATE	*outPrivate,
    TPM2B_PUBLIC	*outPublic,
    TPM2B_CREATION_DATA	*creationData,
    TPM2B_DIGEST	*creationHash,
    TPMT_TK_CREATION	*creationTicket
    );

TSS2_RC Tss2_Sys_Create(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	parentHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_SENSITIVE_CREATE	*inSensitive,
    const TPM2B_PUBLIC	*inPublic,
    const TPM2B_DATA	*outsideInfo,
    const TPML_PCR_SELECTION	*creationPCR,
    TPM2B_PRIVATE	*outPrivate,
    TPM2B_PUBLIC	*outPublic,
    TPM2B_CREATION_DATA	*creationData,
    TPM2B_DIGEST	*creationHash,
    TPMT_TK_CREATION	*creationTicket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Load_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	parentHandle,
    const TPM2B_PRIVATE	*inPrivate,
    const TPM2B_PUBLIC	*inPublic
    );

TSS2_RC Tss2_Sys_Load_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_HANDLE	*objectHandle,
    TPM2B_NAME	*name
    );

TSS2_RC Tss2_Sys_Load(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	parentHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_PRIVATE	*inPrivate,
    const TPM2B_PUBLIC	*inPublic,
    TPM_HANDLE	*objectHandle,
    TPM2B_NAME	*name,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_LoadExternal_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPM2B_SENSITIVE	*inPrivate,
    const TPM2B_PUBLIC	*inPublic,
    TPMI_RH_HIERARCHY	hierarchy
    );

TSS2_RC Tss2_Sys_LoadExternal_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_HANDLE	*objectHandle,
    TPM2B_NAME	*name
    );

TSS2_RC Tss2_Sys_LoadExternal(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_SENSITIVE	*inPrivate,
    const TPM2B_PUBLIC	*inPublic,
    TPMI_RH_HIERARCHY	hierarchy,
    TPM_HANDLE	*objectHandle,
    TPM2B_NAME	*name,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ReadPublic_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle
    );

TSS2_RC Tss2_Sys_ReadPublic_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PUBLIC	*outPublic,
    TPM2B_NAME	*name,
    TPM2B_NAME	*qualifiedName
    );

TSS2_RC Tss2_Sys_ReadPublic(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_PUBLIC	*outPublic,
    TPM2B_NAME	*name,
    TPM2B_NAME	*qualifiedName,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ActivateCredential_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	activateHandle,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_ID_OBJECT	*credentialBlob,
    const TPM2B_ENCRYPTED_SECRET	*secret
    );

TSS2_RC Tss2_Sys_ActivateCredential_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST	*certInfo
    );

TSS2_RC Tss2_Sys_ActivateCredential(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	activateHandle,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_ID_OBJECT	*credentialBlob,
    const TPM2B_ENCRYPTED_SECRET	*secret,
    TPM2B_DIGEST	*certInfo,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_MakeCredential_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	handle,
    const TPM2B_DIGEST	*credential,
    const TPM2B_NAME	*objectName
    );

TSS2_RC Tss2_Sys_MakeCredential_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ID_OBJECT	*credentialBlob,
    TPM2B_ENCRYPTED_SECRET	*secret
    );

TSS2_RC Tss2_Sys_MakeCredential(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	handle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*credential,
    const TPM2B_NAME	*objectName,
    TPM2B_ID_OBJECT	*credentialBlob,
    TPM2B_ENCRYPTED_SECRET	*secret,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Unseal_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	itemHandle
    );

TSS2_RC Tss2_Sys_Unseal_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_SENSITIVE_DATA	*outData
    );

TSS2_RC Tss2_Sys_Unseal(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	itemHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_SENSITIVE_DATA	*outData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ObjectChangeAuth_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	parentHandle,
    const TPM2B_AUTH	*newAuth
    );

TSS2_RC Tss2_Sys_ObjectChangeAuth_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PRIVATE	*outPrivate
    );

TSS2_RC Tss2_Sys_ObjectChangeAuth(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	parentHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_AUTH	*newAuth,
    TPM2B_PRIVATE	*outPrivate,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Duplicate_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	newParentHandle,
    const TPM2B_DATA	*encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT	*symmetricAlg
    );

TSS2_RC Tss2_Sys_Duplicate_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DATA	*encryptionKeyOut,
    TPM2B_PRIVATE	*duplicate,
    TPM2B_ENCRYPTED_SECRET	*outSymSeed
    );

TSS2_RC Tss2_Sys_Duplicate(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	newParentHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT	*symmetricAlg,
    TPM2B_DATA	*encryptionKeyOut,
    TPM2B_PRIVATE	*duplicate,
    TPM2B_ENCRYPTED_SECRET	*outSymSeed,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Rewrap_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	oldParent,
    TPMI_DH_OBJECT	newParent,
    const TPM2B_PRIVATE	*inDuplicate,
    const TPM2B_NAME	*name,
    const TPM2B_ENCRYPTED_SECRET	*inSymSeed
    );

TSS2_RC Tss2_Sys_Rewrap_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PRIVATE	*outDuplicate,
    TPM2B_ENCRYPTED_SECRET	*outSymSeed
    );

TSS2_RC Tss2_Sys_Rewrap(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	oldParent,
    TPMI_DH_OBJECT	newParent,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_PRIVATE	*inDuplicate,
    const TPM2B_NAME	*name,
    const TPM2B_ENCRYPTED_SECRET	*inSymSeed,
    TPM2B_PRIVATE	*outDuplicate,
    TPM2B_ENCRYPTED_SECRET	*outSymSeed,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Import_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	parentHandle,
    const TPM2B_DATA	*encryptionKey,
    const TPM2B_PUBLIC	*objectPublic,
    const TPM2B_PRIVATE	*duplicate,
    const TPM2B_ENCRYPTED_SECRET	*inSymSeed,
    const TPMT_SYM_DEF_OBJECT	*symmetricAlg
    );

TSS2_RC Tss2_Sys_Import_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PRIVATE	*outPrivate
    );

TSS2_RC Tss2_Sys_Import(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	parentHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*encryptionKey,
    const TPM2B_PUBLIC	*objectPublic,
    const TPM2B_PRIVATE	*duplicate,
    const TPM2B_ENCRYPTED_SECRET	*inSymSeed,
    const TPMT_SYM_DEF_OBJECT	*symmetricAlg,
    TPM2B_PRIVATE	*outPrivate,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_RSA_Encrypt_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_PUBLIC_KEY_RSA	*message,
    const TPMT_RSA_DECRYPT	*inScheme,
    const TPM2B_DATA	*label
    );

TSS2_RC Tss2_Sys_RSA_Encrypt_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PUBLIC_KEY_RSA	*outData
    );

TSS2_RC Tss2_Sys_RSA_Encrypt(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_PUBLIC_KEY_RSA	*message,
    const TPMT_RSA_DECRYPT	*inScheme,
    const TPM2B_DATA	*label,
    TPM2B_PUBLIC_KEY_RSA	*outData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_RSA_Decrypt_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_PUBLIC_KEY_RSA	*cipherText,
    const TPMT_RSA_DECRYPT	*inScheme,
    const TPM2B_DATA	*label
    );

TSS2_RC Tss2_Sys_RSA_Decrypt_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_PUBLIC_KEY_RSA	*message
    );

TSS2_RC Tss2_Sys_RSA_Decrypt(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_PUBLIC_KEY_RSA	*cipherText,
    const TPMT_RSA_DECRYPT	*inScheme,
    const TPM2B_DATA	*label,
    TPM2B_PUBLIC_KEY_RSA	*message,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ECDH_KeyGen_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle
    );

TSS2_RC Tss2_Sys_ECDH_KeyGen_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT	*zPoint,
    TPM2B_ECC_POINT	*pubPoint
    );

TSS2_RC Tss2_Sys_ECDH_KeyGen(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_ECC_POINT	*zPoint,
    TPM2B_ECC_POINT	*pubPoint,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ECDH_ZGen_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_ECC_POINT	*inPoint
    );

TSS2_RC Tss2_Sys_ECDH_ZGen_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT	*outPoint
    );

TSS2_RC Tss2_Sys_ECDH_ZGen(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_ECC_POINT	*inPoint,
    TPM2B_ECC_POINT	*outPoint,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ECC_Parameters_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_ECC_CURVE	curveID
    );

TSS2_RC Tss2_Sys_ECC_Parameters_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_ALGORITHM_DETAIL_ECC	*parameters
    );

TSS2_RC Tss2_Sys_ECC_Parameters(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_ECC_CURVE	curveID,
    TPMS_ALGORITHM_DETAIL_ECC	*parameters,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ZGen_2Phase_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyA,
    const TPM2B_ECC_POINT	*inQsB,
    const TPM2B_ECC_POINT	*inQeB,
    TPMI_ECC_KEY_EXCHANGE	inScheme,
    UINT16	counter
    );

TSS2_RC Tss2_Sys_ZGen_2Phase_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT	*outZ1,
    TPM2B_ECC_POINT	*outZ2
    );

TSS2_RC Tss2_Sys_ZGen_2Phase(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyA,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_ECC_POINT	*inQsB,
    const TPM2B_ECC_POINT	*inQeB,
    TPMI_ECC_KEY_EXCHANGE	inScheme,
    UINT16	counter,
    TPM2B_ECC_POINT	*outZ1,
    TPM2B_ECC_POINT	*outZ2,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_EncryptDecrypt_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TPMI_YES_NO	decrypt,
    TPMI_ALG_SYM_MODE	mode,
    const TPM2B_IV	*ivIn,
    const TPM2B_MAX_BUFFER	*inData
    );

TSS2_RC Tss2_Sys_EncryptDecrypt_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER	*outData,
    TPM2B_IV	*ivOut
    );

TSS2_RC Tss2_Sys_EncryptDecrypt(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_YES_NO	decrypt,
    TPMI_ALG_SYM_MODE	mode,
    const TPM2B_IV	*ivIn,
    const TPM2B_MAX_BUFFER	*inData,
    TPM2B_MAX_BUFFER	*outData,
    TPM2B_IV	*ivOut,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_EncryptDecrypt2_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_MAX_BUFFER	*inData,
    TPMI_YES_NO	decrypt,
    TPMI_ALG_SYM_MODE	mode,
    const TPM2B_IV	*ivIn
    );

TSS2_RC Tss2_Sys_EncryptDecrypt2_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER	*outData,
    TPM2B_IV	*ivOut
    );

TSS2_RC Tss2_Sys_EncryptDecrypt2(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER	*inData,
    TPMI_YES_NO	decrypt,
    TPMI_ALG_SYM_MODE	mode,
    const TPM2B_IV	*ivIn,
    TPM2B_MAX_BUFFER	*outData,
    TPM2B_IV	*ivOut,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Hash_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPM2B_MAX_BUFFER	*data,
    TPMI_ALG_HASH	hashAlg,
    TPMI_RH_HIERARCHY	hierarchy
    );

TSS2_RC Tss2_Sys_Hash_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST	*outHash,
    TPMT_TK_HASHCHECK	*validation
    );

TSS2_RC Tss2_Sys_Hash(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER	*data,
    TPMI_ALG_HASH	hashAlg,
    TPMI_RH_HIERARCHY	hierarchy,
    TPM2B_DIGEST	*outHash,
    TPMT_TK_HASHCHECK	*validation,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_HMAC_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	handle,
    const TPM2B_MAX_BUFFER	*buffer,
    TPMI_ALG_HASH	hashAlg
    );

TSS2_RC Tss2_Sys_HMAC_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST	*outHMAC
    );

TSS2_RC Tss2_Sys_HMAC(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	handle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER	*buffer,
    TPMI_ALG_HASH	hashAlg,
    TPM2B_DIGEST	*outHMAC,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetRandom_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    UINT16	bytesRequested
    );

TSS2_RC Tss2_Sys_GetRandom_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST	*randomBytes
    );

TSS2_RC Tss2_Sys_GetRandom(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT16	bytesRequested,
    TPM2B_DIGEST	*randomBytes,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_StirRandom_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPM2B_SENSITIVE_DATA	*inData
    );

TSS2_RC Tss2_Sys_StirRandom(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_SENSITIVE_DATA	*inData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_HMAC_Start_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	handle,
    const TPM2B_AUTH	*auth,
    TPMI_ALG_HASH	hashAlg
    );

TSS2_RC Tss2_Sys_HMAC_Start_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	*sequenceHandle
    );

TSS2_RC Tss2_Sys_HMAC_Start(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	handle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_AUTH	*auth,
    TPMI_ALG_HASH	hashAlg,
    TPMI_DH_OBJECT	*sequenceHandle,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_HashSequenceStart_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPM2B_AUTH	*auth,
    TPMI_ALG_HASH	hashAlg
    );

TSS2_RC Tss2_Sys_HashSequenceStart_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	*sequenceHandle
    );

TSS2_RC Tss2_Sys_HashSequenceStart(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_AUTH	*auth,
    TPMI_ALG_HASH	hashAlg,
    TPMI_DH_OBJECT	*sequenceHandle,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_SequenceUpdate_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	sequenceHandle,
    const TPM2B_MAX_BUFFER	*buffer
    );

TSS2_RC Tss2_Sys_SequenceUpdate(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	sequenceHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER	*buffer,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_SequenceComplete_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	sequenceHandle,
    const TPM2B_MAX_BUFFER	*buffer,
    TPMI_RH_HIERARCHY	hierarchy
    );

TSS2_RC Tss2_Sys_SequenceComplete_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST	*result,
    TPMT_TK_HASHCHECK	*validation
    );

TSS2_RC Tss2_Sys_SequenceComplete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	sequenceHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER	*buffer,
    TPMI_RH_HIERARCHY	hierarchy,
    TPM2B_DIGEST	*result,
    TPMT_TK_HASHCHECK	*validation,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_EventSequenceComplete_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    TPMI_DH_OBJECT	sequenceHandle,
    const TPM2B_MAX_BUFFER	*buffer
    );

TSS2_RC Tss2_Sys_EventSequenceComplete_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPML_DIGEST_VALUES	*results
    );

TSS2_RC Tss2_Sys_EventSequenceComplete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    TPMI_DH_OBJECT	sequenceHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER	*buffer,
    TPML_DIGEST_VALUES	*results,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Certify_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	signHandle,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme
    );

TSS2_RC Tss2_Sys_Certify_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*certifyInfo,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_Certify(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_OBJECT	signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    TPM2B_ATTEST	*certifyInfo,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_CertifyCreation_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TPMI_DH_OBJECT	objectHandle,
    const TPM2B_DATA	*qualifyingData,
    const TPM2B_DIGEST	*creationHash,
    const TPMT_SIG_SCHEME	*inScheme,
    const TPMT_TK_CREATION	*creationTicket
    );

TSS2_RC Tss2_Sys_CertifyCreation_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*certifyInfo,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_CertifyCreation(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TPMI_DH_OBJECT	objectHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPM2B_DIGEST	*creationHash,
    const TPMT_SIG_SCHEME	*inScheme,
    const TPMT_TK_CREATION	*creationTicket,
    TPM2B_ATTEST	*certifyInfo,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Quote_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    const TPML_PCR_SELECTION	*PCRselect
    );

TSS2_RC Tss2_Sys_Quote_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*quoted,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_Quote(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    const TPML_PCR_SELECTION	*PCRselect,
    TPM2B_ATTEST	*quoted,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetSessionAuditDigest_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_ENDORSEMENT	privacyAdminHandle,
    TPMI_DH_OBJECT	signHandle,
    TPMI_SH_HMAC	sessionHandle,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme
    );

TSS2_RC Tss2_Sys_GetSessionAuditDigest_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*auditInfo,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_GetSessionAuditDigest(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_ENDORSEMENT	privacyAdminHandle,
    TPMI_DH_OBJECT	signHandle,
    TPMI_SH_HMAC	sessionHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    TPM2B_ATTEST	*auditInfo,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetCommandAuditDigest_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_ENDORSEMENT	privacyHandle,
    TPMI_DH_OBJECT	signHandle,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme
    );

TSS2_RC Tss2_Sys_GetCommandAuditDigest_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*auditInfo,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_GetCommandAuditDigest(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_ENDORSEMENT	privacyHandle,
    TPMI_DH_OBJECT	signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    TPM2B_ATTEST	*auditInfo,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetTime_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_ENDORSEMENT	privacyAdminHandle,
    TPMI_DH_OBJECT	signHandle,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme
    );

TSS2_RC Tss2_Sys_GetTime_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*timeInfo,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_GetTime(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_ENDORSEMENT	privacyAdminHandle,
    TPMI_DH_OBJECT	signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    TPM2B_ATTEST	*timeInfo,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Commit_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    const TPM2B_ECC_POINT	*P1,
    const TPM2B_SENSITIVE_DATA	*s2,
    const TPM2B_ECC_PARAMETER	*y2
    );

TSS2_RC Tss2_Sys_Commit_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT	*K,
    TPM2B_ECC_POINT	*L,
    TPM2B_ECC_POINT	*E,
    UINT16	*counter
    );

TSS2_RC Tss2_Sys_Commit(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_ECC_POINT	*P1,
    const TPM2B_SENSITIVE_DATA	*s2,
    const TPM2B_ECC_PARAMETER	*y2,
    TPM2B_ECC_POINT	*K,
    TPM2B_ECC_POINT	*L,
    TPM2B_ECC_POINT	*E,
    UINT16	*counter,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_EC_Ephemeral_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_ECC_CURVE	curveID
    );

TSS2_RC Tss2_Sys_EC_Ephemeral_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT	*Q,
    UINT16	*counter
    );

TSS2_RC Tss2_Sys_EC_Ephemeral(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_ECC_CURVE	curveID,
    TPM2B_ECC_POINT	*Q,
    UINT16	*counter,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_VerifySignature_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_DIGEST	*digest,
    const TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_VerifySignature_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMT_TK_VERIFIED	*validation
    );

TSS2_RC Tss2_Sys_VerifySignature(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*digest,
    const TPMT_SIGNATURE	*signature,
    TPMT_TK_VERIFIED	*validation,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Sign_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    const TPM2B_DIGEST	*digest,
    const TPMT_SIG_SCHEME	*inScheme,
    const TPMT_TK_HASHCHECK	*validation
    );

TSS2_RC Tss2_Sys_Sign_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_Sign(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*digest,
    const TPMT_SIG_SCHEME	*inScheme,
    const TPMT_TK_HASHCHECK	*validation,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_SetCommandCodeAuditStatus_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TPMI_ALG_HASH	auditAlg,
    const TPML_CC	*setList,
    const TPML_CC	*clearList
    );

TSS2_RC Tss2_Sys_SetCommandCodeAuditStatus(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_ALG_HASH	auditAlg,
    const TPML_CC	*setList,
    const TPML_CC	*clearList,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_Extend_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    const TPML_DIGEST_VALUES	*digests
    );

TSS2_RC Tss2_Sys_PCR_Extend(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPML_DIGEST_VALUES	*digests,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_Event_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    const TPM2B_EVENT	*eventData
    );

TSS2_RC Tss2_Sys_PCR_Event_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPML_DIGEST_VALUES	*digests
    );

TSS2_RC Tss2_Sys_PCR_Event(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_EVENT	*eventData,
    TPML_DIGEST_VALUES	*digests,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_Read_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPML_PCR_SELECTION	*pcrSelectionIn
    );

TSS2_RC Tss2_Sys_PCR_Read_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    UINT32	*pcrUpdateCounter,
    TPML_PCR_SELECTION	*pcrSelectionOut,
    TPML_DIGEST	*pcrValues
    );

TSS2_RC Tss2_Sys_PCR_Read(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPML_PCR_SELECTION	*pcrSelectionIn,
    UINT32	*pcrUpdateCounter,
    TPML_PCR_SELECTION	*pcrSelectionOut,
    TPML_DIGEST	*pcrValues,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_Allocate_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    const TPML_PCR_SELECTION	*pcrAllocation
    );

TSS2_RC Tss2_Sys_PCR_Allocate_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO	*allocationSuccess,
    UINT32	*maxPCR,
    UINT32	*sizeNeeded,
    UINT32	*sizeAvailable
    );

TSS2_RC Tss2_Sys_PCR_Allocate(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPML_PCR_SELECTION	*pcrAllocation,
    TPMI_YES_NO	*allocationSuccess,
    UINT32	*maxPCR,
    UINT32	*sizeNeeded,
    UINT32	*sizeAvailable,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_SetAuthPolicy_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    const TPM2B_DIGEST	*authPolicy,
    TPMI_ALG_HASH	hashAlg,
    TPMI_DH_PCR	pcrNum
    );

TSS2_RC Tss2_Sys_PCR_SetAuthPolicy(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*authPolicy,
    TPMI_ALG_HASH	hashAlg,
    TPMI_DH_PCR	pcrNum,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_SetAuthValue_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    const TPM2B_DIGEST	*auth
    );

TSS2_RC Tss2_Sys_PCR_SetAuthValue(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*auth,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PCR_Reset_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle
    );

TSS2_RC Tss2_Sys_PCR_Reset(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_PCR	pcrHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicySigned_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	authObject,
    TPMI_SH_POLICY	policySession,
    const TPM2B_NONCE	*nonceTPM,
    const TPM2B_DIGEST	*cpHashA,
    const TPM2B_NONCE	*policyRef,
    INT32	expiration,
    const TPMT_SIGNATURE	*auth
    );

TSS2_RC Tss2_Sys_PolicySigned_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_TIMEOUT	*timeout,
    TPMT_TK_AUTH	*policyTicket
    );

TSS2_RC Tss2_Sys_PolicySigned(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	authObject,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_NONCE	*nonceTPM,
    const TPM2B_DIGEST	*cpHashA,
    const TPM2B_NONCE	*policyRef,
    INT32	expiration,
    const TPMT_SIGNATURE	*auth,
    TPM2B_TIMEOUT	*timeout,
    TPMT_TK_AUTH	*policyTicket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicySecret_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_ENTITY	authHandle,
    TPMI_SH_POLICY	policySession,
    const TPM2B_NONCE	*nonceTPM,
    const TPM2B_DIGEST	*cpHashA,
    const TPM2B_NONCE	*policyRef,
    INT32	expiration
    );

TSS2_RC Tss2_Sys_PolicySecret_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_TIMEOUT	*timeout,
    TPMT_TK_AUTH	*policyTicket
    );

TSS2_RC Tss2_Sys_PolicySecret(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_ENTITY	authHandle,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_NONCE	*nonceTPM,
    const TPM2B_DIGEST	*cpHashA,
    const TPM2B_NONCE	*policyRef,
    INT32	expiration,
    TPM2B_TIMEOUT	*timeout,
    TPMT_TK_AUTH	*policyTicket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyTicket_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_TIMEOUT	*timeout,
    const TPM2B_DIGEST	*cpHashA,
    const TPM2B_NONCE	*policyRef,
    const TPM2B_NAME	*authName,
    const TPMT_TK_AUTH	*ticket
    );

TSS2_RC Tss2_Sys_PolicyTicket(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_TIMEOUT	*timeout,
    const TPM2B_DIGEST	*cpHashA,
    const TPM2B_NONCE	*policyRef,
    const TPM2B_NAME	*authName,
    const TPMT_TK_AUTH	*ticket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyOR_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPML_DIGEST	*pHashList
    );

TSS2_RC Tss2_Sys_PolicyOR(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPML_DIGEST	*pHashList,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyPCR_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_DIGEST	*pcrDigest,
    const TPML_PCR_SELECTION	*pcrs
    );

TSS2_RC Tss2_Sys_PolicyPCR(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*pcrDigest,
    const TPML_PCR_SELECTION	*pcrs,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyLocality_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TPMA_LOCALITY	locality
    );

TSS2_RC Tss2_Sys_PolicyLocality(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMA_LOCALITY	locality,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyNV_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TPMI_SH_POLICY	policySession,
    const TPM2B_OPERAND	*operandB,
    UINT16	offset,
    TPM_EO	operation
    );

TSS2_RC Tss2_Sys_PolicyNV(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_OPERAND	*operandB,
    UINT16	offset,
    TPM_EO	operation,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyCounterTimer_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_OPERAND	*operandB,
    UINT16	offset,
    TPM_EO	operation
    );

TSS2_RC Tss2_Sys_PolicyCounterTimer(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_OPERAND	*operandB,
    UINT16	offset,
    TPM_EO	operation,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyCommandCode_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TPM_CC	code
    );

TSS2_RC Tss2_Sys_PolicyCommandCode(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM_CC	code,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyPhysicalPresence_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession
    );

TSS2_RC Tss2_Sys_PolicyPhysicalPresence(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyCpHash_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_DIGEST	*cpHashA
    );

TSS2_RC Tss2_Sys_PolicyCpHash(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*cpHashA,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyNameHash_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_DIGEST	*nameHash
    );

TSS2_RC Tss2_Sys_PolicyNameHash(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*nameHash,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyDuplicationSelect_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_NAME	*objectName,
    const TPM2B_NAME	*newParentName,
    TPMI_YES_NO	includeObject
    );

TSS2_RC Tss2_Sys_PolicyDuplicationSelect(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_NAME	*objectName,
    const TPM2B_NAME	*newParentName,
    TPMI_YES_NO	includeObject,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyAuthorize_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    const TPM2B_DIGEST	*approvedPolicy,
    const TPM2B_NONCE	*policyRef,
    const TPM2B_NAME	*keySign,
    const TPMT_TK_VERIFIED	*checkTicket
    );

TSS2_RC Tss2_Sys_PolicyAuthorize(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*approvedPolicy,
    const TPM2B_NONCE	*policyRef,
    const TPM2B_NAME	*keySign,
    const TPMT_TK_VERIFIED	*checkTicket,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyAuthValue_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession
    );

TSS2_RC Tss2_Sys_PolicyAuthValue(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyPassword_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession
    );

TSS2_RC Tss2_Sys_PolicyPassword(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyGetDigest_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession
    );

TSS2_RC Tss2_Sys_PolicyGetDigest_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST	*policyDigest
    );

TSS2_RC Tss2_Sys_PolicyGetDigest(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_DIGEST	*policyDigest,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PolicyNvWritten_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TPMI_YES_NO	writtenSet
    );

TSS2_RC Tss2_Sys_PolicyNvWritten(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY	policySession,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_YES_NO	writtenSet,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_CreatePrimary_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY	primaryHandle,
    const TPM2B_SENSITIVE_CREATE	*inSensitive,
    const TPM2B_PUBLIC	*inPublic,
    const TPM2B_DATA	*outsideInfo,
    const TPML_PCR_SELECTION	*creationPCR
    );

TSS2_RC Tss2_Sys_CreatePrimary_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_HANDLE	*objectHandle,
    TPM2B_PUBLIC	*outPublic,
    TPM2B_CREATION_DATA	*creationData,
    TPM2B_DIGEST	*creationHash,
    TPMT_TK_CREATION	*creationTicket,
    TPM2B_NAME	*name
    );

TSS2_RC Tss2_Sys_CreatePrimary(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY	primaryHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_SENSITIVE_CREATE	*inSensitive,
    const TPM2B_PUBLIC	*inPublic,
    const TPM2B_DATA	*outsideInfo,
    const TPML_PCR_SELECTION	*creationPCR,
    TPM_HANDLE	*objectHandle,
    TPM2B_PUBLIC	*outPublic,
    TPM2B_CREATION_DATA	*creationData,
    TPM2B_DIGEST	*creationHash,
    TPMT_TK_CREATION	*creationTicket,
    TPM2B_NAME	*name,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_HierarchyControl_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY	authHandle,
    TPMI_RH_ENABLES	enable,
    TPMI_YES_NO	state
    );

TSS2_RC Tss2_Sys_HierarchyControl(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_RH_ENABLES	enable,
    TPMI_YES_NO	state,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_SetPrimaryPolicy_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY_AUTH	authHandle,
    const TPM2B_DIGEST	*authPolicy,
    TPMI_ALG_HASH	hashAlg
    );

TSS2_RC Tss2_Sys_SetPrimaryPolicy(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY_AUTH	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST	*authPolicy,
    TPMI_ALG_HASH	hashAlg,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ChangePPS_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle
    );

TSS2_RC Tss2_Sys_ChangePPS(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ChangeEPS_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle
    );

TSS2_RC Tss2_Sys_ChangeEPS(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Clear_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_CLEAR	authHandle
    );

TSS2_RC Tss2_Sys_Clear(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_CLEAR	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ClearControl_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_CLEAR	auth,
    TPMI_YES_NO	disable
    );

TSS2_RC Tss2_Sys_ClearControl(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_CLEAR	auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_YES_NO	disable,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_HierarchyChangeAuth_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY_AUTH	authHandle,
    const TPM2B_AUTH	*newAuth
    );

TSS2_RC Tss2_Sys_HierarchyChangeAuth(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY_AUTH	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_AUTH	*newAuth,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_DictionaryAttackLockReset_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_LOCKOUT	lockHandle
    );

TSS2_RC Tss2_Sys_DictionaryAttackLockReset(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_LOCKOUT	lockHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_DictionaryAttackParameters_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_LOCKOUT	lockHandle,
    UINT32	newMaxTries,
    UINT32	newRecoveryTime,
    UINT32	lockoutRecovery
    );

TSS2_RC Tss2_Sys_DictionaryAttackParameters(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_LOCKOUT	lockHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT32	newMaxTries,
    UINT32	newRecoveryTime,
    UINT32	lockoutRecovery,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_PP_Commands_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	auth,
    const TPML_CC	*setList,
    const TPML_CC	*clearList
    );

TSS2_RC Tss2_Sys_PP_Commands(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPML_CC	*setList,
    const TPML_CC	*clearList,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_SetAlgorithmSet_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    UINT32	algorithmSet
    );

TSS2_RC Tss2_Sys_SetAlgorithmSet(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT32	algorithmSet,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_FieldUpgradeStart_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authorization,
    TPMI_DH_OBJECT	keyHandle,
    TPM2B_DIGEST	*fuDigest,
    TPMT_SIGNATURE	*manifestSignature
    );

TSS2_RC Tss2_Sys_FieldUpgradeStart(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM	authorization,
    TPMI_DH_OBJECT	keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_DIGEST	*fuDigest,
    TPMT_SIGNATURE	*manifestSignature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_FieldUpgradeData_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER	*fuData
    );

TSS2_RC Tss2_Sys_FieldUpgradeData_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMT_HA	*nextDigest,
    TPMT_HA	*firstDigest
    );

TSS2_RC Tss2_Sys_FieldUpgradeData(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_MAX_BUFFER	*fuData,
    TPMT_HA	*nextDigest,
    TPMT_HA	*firstDigest,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_FirmwareRead_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    UINT32	sequenceNumber
    );

TSS2_RC Tss2_Sys_FirmwareRead_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER	*fuData
    );

TSS2_RC Tss2_Sys_FirmwareRead(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT32	sequenceNumber,
    TPM2B_MAX_BUFFER	*fuData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ContextSave_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT	saveHandle
    );

TSS2_RC Tss2_Sys_ContextSave_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_CONTEXT	*context
    );

TSS2_RC Tss2_Sys_ContextSave(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT	saveHandle,
    TPMS_CONTEXT	*context
    );

TSS2_RC Tss2_Sys_ContextLoad_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT	*context
    );

TSS2_RC Tss2_Sys_ContextLoad_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT	*loadedHandle
    );

TSS2_RC Tss2_Sys_ContextLoad(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT	*context,
    TPMI_DH_CONTEXT	*loadedHandle
    );

TSS2_RC Tss2_Sys_FlushContext_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT	flushHandle
    );

TSS2_RC Tss2_Sys_FlushContext(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT	flushHandle
    );

TSS2_RC Tss2_Sys_EvictControl_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TPMI_DH_OBJECT	objectHandle,
    TPMI_DH_PERSISTENT	persistentHandle
    );

TSS2_RC Tss2_Sys_EvictControl(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TPMI_DH_OBJECT	objectHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPMI_DH_PERSISTENT	persistentHandle,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ReadClock_Prepare(
    TSS2_SYS_CONTEXT *sysContext
    );

TSS2_RC Tss2_Sys_ReadClock_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_TIME_INFO	*currentTime
    );

TSS2_RC Tss2_Sys_ReadClock(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_TIME_INFO	*currentTime
    );

TSS2_RC Tss2_Sys_ClockSet_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    UINT64	newTime
    );

TSS2_RC Tss2_Sys_ClockSet(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT64	newTime,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_ClockRateAdjust_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TPM_CLOCK_ADJUST	rateAdjust
    );

TSS2_RC Tss2_Sys_ClockRateAdjust(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM_CLOCK_ADJUST	rateAdjust,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetCapability_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_CAP	capability,
    UINT32	property,
    UINT32	propertyCount
    );

TSS2_RC Tss2_Sys_GetCapability_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO	*moreData,
    TPMS_CAPABILITY_DATA	*capabilityData
    );

TSS2_RC Tss2_Sys_GetCapability(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM_CAP	capability,
    UINT32	property,
    UINT32	propertyCount,
    TPMI_YES_NO	*moreData,
    TPMS_CAPABILITY_DATA	*capabilityData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_TestParms_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMT_PUBLIC_PARMS	*parameters
    );

TSS2_RC Tss2_Sys_TestParms(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPMT_PUBLIC_PARMS	*parameters,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_DefineSpace_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	authHandle,
    const TPM2B_AUTH	*auth,
    const TPM2B_NV_PUBLIC	*publicInfo
    );

TSS2_RC Tss2_Sys_NV_DefineSpace(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_AUTH	*auth,
    const TPM2B_NV_PUBLIC	*publicInfo,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_UndefineSpace_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	authHandle,
    TPMI_RH_NV_INDEX	nvIndex
    );

TSS2_RC Tss2_Sys_NV_UndefineSpace(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_UndefineSpaceSpecial_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_INDEX	nvIndex,
    TPMI_RH_PLATFORM	platform
    );

TSS2_RC Tss2_Sys_NV_UndefineSpaceSpecial(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_INDEX	nvIndex,
    TPMI_RH_PLATFORM	platform,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_ReadPublic_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_INDEX	nvIndex
    );

TSS2_RC Tss2_Sys_NV_ReadPublic_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_NV_PUBLIC	*nvPublic,
    TPM2B_NAME	*nvName
    );

TSS2_RC Tss2_Sys_NV_ReadPublic(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_NV_PUBLIC	*nvPublic,
    TPM2B_NAME	*nvName,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_Write_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    const TPM2B_MAX_NV_BUFFER	*data,
    UINT16	offset
    );

TSS2_RC Tss2_Sys_NV_Write(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_NV_BUFFER	*data,
    UINT16	offset,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_Increment_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex
    );

TSS2_RC Tss2_Sys_NV_Increment(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_Extend_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    const TPM2B_MAX_NV_BUFFER	*data
    );

TSS2_RC Tss2_Sys_NV_Extend(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_MAX_NV_BUFFER	*data,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_SetBits_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    UINT64	bits
    );

TSS2_RC Tss2_Sys_NV_SetBits(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT64	bits,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_WriteLock_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex
    );

TSS2_RC Tss2_Sys_NV_WriteLock(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_GlobalWriteLock_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	authHandle
    );

TSS2_RC Tss2_Sys_NV_GlobalWriteLock(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION	authHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_Read_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    UINT16	size,
    UINT16	offset
    );

TSS2_RC Tss2_Sys_NV_Read_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_NV_BUFFER	*data
    );

TSS2_RC Tss2_Sys_NV_Read(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT16	size,
    UINT16	offset,
    TPM2B_MAX_NV_BUFFER	*data,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_ReadLock_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex
    );

TSS2_RC Tss2_Sys_NV_ReadLock(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_ChangeAuth_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_INDEX	nvIndex,
    const TPM2B_AUTH	*newAuth
    );

TSS2_RC Tss2_Sys_NV_ChangeAuth(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_AUTH	*newAuth,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_NV_Certify_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    UINT16	size,
    UINT16	offset
    );

TSS2_RC Tss2_Sys_NV_Certify_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ATTEST	*certifyInfo,
    TPMT_SIGNATURE	*signature
    );

TSS2_RC Tss2_Sys_NV_Certify(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT	signHandle,
    TPMI_RH_NV_AUTH	authHandle,
    TPMI_RH_NV_INDEX	nvIndex,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*qualifyingData,
    const TPMT_SIG_SCHEME	*inScheme,
    UINT16	size,
    UINT16	offset,
    TPM2B_ATTEST	*certifyInfo,
    TPMT_SIGNATURE	*signature,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_Vendor_TCG_Test_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPM2B_DATA	*inputData
    );

TSS2_RC Tss2_Sys_Vendor_TCG_Test_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DATA	*outputData
    );

TSS2_RC Tss2_Sys_Vendor_TCG_Test(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DATA	*inputData,
    TPM2B_DATA	*outputData,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

#endif
