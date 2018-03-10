//**********************************************************************;
// Copyright (c) 2015 - 2017 Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include "tpm20.h"
#include "sysapi_util.h"

COMMAND_HANDLES commandArray[] =
{
    { TPM2_CC_Startup, 0, 0 },
    { TPM2_CC_Shutdown, 0, 0 },
    { TPM2_CC_SelfTest, 0, 0 },
    { TPM2_CC_IncrementalSelfTest, 0,  },
    { TPM2_CC_GetTestResult, 0, 0 },
    { TPM2_CC_StartAuthSession, 2, 1 },
    { TPM2_CC_PolicyRestart, 1, 0 },
    { TPM2_CC_Create, 1, 0 },
    { TPM2_CC_Load, 1, 1 },
    { TPM2_CC_LoadExternal, 0, 1 },
    { TPM2_CC_ReadPublic, 1, 0 },
    { TPM2_CC_ActivateCredential, 2, 0 },
    { TPM2_CC_MakeCredential, 1, 0 },
    { TPM2_CC_Unseal, 1, 0 },
    { TPM2_CC_ObjectChangeAuth, 2, 0 },
    { TPM2_CC_Duplicate, 2, 0 },
    { TPM2_CC_Rewrap, 2, 0 },
    { TPM2_CC_Import, 1, 0 },
    { TPM2_CC_RSA_Encrypt, 1, 0 },
    { TPM2_CC_RSA_Decrypt, 1, 0 },
    { TPM2_CC_ECDH_KeyGen, 1, 0 },
    { TPM2_CC_ECDH_ZGen, 1, 0 },
    { TPM2_CC_ECC_Parameters, 0, 0 },
    { TPM2_CC_ZGen_2Phase, 1, 0 },
    { TPM2_CC_EncryptDecrypt, 1, 0 },
    { TPM2_CC_EncryptDecrypt2, 1, 0 },
    { TPM2_CC_Hash, 0, 0 },
    { TPM2_CC_HMAC, 1, 0 },
    { TPM2_CC_GetRandom, 0, 0 },
    { TPM2_CC_StirRandom, 0, 0 },
    { TPM2_CC_HMAC_Start, 1, 1 },
    { TPM2_CC_HashSequenceStart, 0, 1 },
    { TPM2_CC_SequenceUpdate, 1, 0 },
    { TPM2_CC_SequenceComplete, 1, 0 },
    { TPM2_CC_EventSequenceComplete, 2, 0 },
    { TPM2_CC_Certify, 2, 0 },
    { TPM2_CC_CertifyCreation, 2, 0 },
    { TPM2_CC_Quote, 1, 0 },
    { TPM2_CC_GetSessionAuditDigest, 3, 0 },
    { TPM2_CC_GetCommandAuditDigest, 2, 0 },
    { TPM2_CC_GetTime, 2, 0 },
    { TPM2_CC_Commit, 1, 0 },
    { TPM2_CC_EC_Ephemeral, 0, 0 },
    { TPM2_CC_VerifySignature, 1, 0 },
    { TPM2_CC_Sign, 1, 0 },
    { TPM2_CC_SetCommandCodeAuditStatus, 1, 0 },
    { TPM2_CC_PCR_Extend, 1, 0 },
    { TPM2_CC_PCR_Event, 1, 0 },
    { TPM2_CC_PCR_Read, 0, 0 },
    { TPM2_CC_PCR_Allocate, 1, 0 },
    { TPM2_CC_PCR_SetAuthPolicy, 1, 0 },
    { TPM2_CC_PCR_SetAuthValue, 1, 0 },
    { TPM2_CC_PCR_Reset, 1, 0 },
    { TPM2_CC_PolicySigned, 2, 0 },
    { TPM2_CC_PolicySecret, 2, 0 },
    { TPM2_CC_PolicyTicket, 1, 0 },
    { TPM2_CC_PolicyOR, 1, 0 },
    { TPM2_CC_PolicyPCR, 1, 0 },
    { TPM2_CC_PolicyLocality, 1, 0 },
    { TPM2_CC_PolicyNV, 3, 0 },
    { TPM2_CC_PolicyCounterTimer, 1, 0 },
    { TPM2_CC_PolicyCommandCode, 1, 0 },
    { TPM2_CC_PolicyPhysicalPresence, 1, 0 },
    { TPM2_CC_PolicyCpHash, 1, 0 },
    { TPM2_CC_PolicyNameHash, 1, 0 },
    { TPM2_CC_PolicyDuplicationSelect, 1, 0 },
    { TPM2_CC_PolicyAuthorize, 1, 0 },
    { TPM2_CC_PolicyAuthValue, 1, 0 },
    { TPM2_CC_PolicyPassword, 1, 0 },
    { TPM2_CC_PolicyGetDigest, 1, 0 },
    { TPM2_CC_PolicyTemplate, 1, 0 },
    { TPM2_CC_CreatePrimary, 1, 1 },
    { TPM2_CC_HierarchyControl, 1, 0 },
    { TPM2_CC_SetPrimaryPolicy, 1, 0 },
    { TPM2_CC_ChangePPS, 1, 0 },
    { TPM2_CC_ChangeEPS, 1, 0 },
    { TPM2_CC_Clear, 1, 0 },
    { TPM2_CC_ClearControl, 1, 0 },
    { TPM2_CC_HierarchyChangeAuth, 1, 0 },
    { TPM2_CC_DictionaryAttackLockReset, 1, 0 },
    { TPM2_CC_DictionaryAttackParameters, 1, 0 },
    { TPM2_CC_PP_Commands, 1, 0 },
    { TPM2_CC_SetAlgorithmSet, 1, 0 },
    { TPM2_CC_FieldUpgradeStart, 2, 0 },
    { TPM2_CC_FieldUpgradeData, 0, 0 },
    { TPM2_CC_FirmwareRead, 0, 0 },
    { TPM2_CC_ContextSave, 1, 0 },
    { TPM2_CC_ContextLoad, 0, 1 },
    { TPM2_CC_FlushContext, 1, 0 },
    { TPM2_CC_EvictControl, 2, 0 },
    { TPM2_CC_ReadClock, 0, 0 },
    { TPM2_CC_ClockSet, 1, 0 },
    { TPM2_CC_ClockRateAdjust, 1, 0 },
    { TPM2_CC_GetCapability, 0, 0 },
    { TPM2_CC_TestParms, 1, 0 },
    { TPM2_CC_NV_DefineSpace, 1, 0 },
    { TPM2_CC_NV_UndefineSpace, 2, 0 },
    { TPM2_CC_NV_UndefineSpaceSpecial, 2, 0 },
    { TPM2_CC_NV_ReadPublic, 1, 0 },
    { TPM2_CC_NV_Write, 2, 0 },
    { TPM2_CC_NV_Increment, 2, 0 },
    { TPM2_CC_NV_Extend, 2, 0 },
    { TPM2_CC_NV_SetBits, 2, 0 },
    { TPM2_CC_NV_WriteLock, 2, 0 },
    { TPM2_CC_NV_GlobalWriteLock, 1, 0 },
    { TPM2_CC_NV_Read, 2, 0 },
    { TPM2_CC_NV_ReadLock, 2, 0 },
    { TPM2_CC_NV_ChangeAuth, 1, 0 },
    { TPM2_CC_NV_Certify, 3, 0 },
    { TPM2_CC_CreateLoaded, 1, 1 },
    { TPM2_CC_PolicyAuthorizeNV, 3, 0 },
    { TPM2_CC_AC_GetCapability, 1, 0 },
    { TPM2_CC_AC_Send, 3, 0 },
    { TPM2_CC_Policy_AC_SendSelect, 1, 0 }
};

static int GetNumHandles(TPM2_CC commandCode, uint8_t command)
{
    uint8_t i;

    for (i = 0; i < sizeof(commandArray) / sizeof(COMMAND_HANDLES); i++) {
        if (commandCode == commandArray[i].commandCode) {
            if (command)
                return commandArray[i].numCommandHandles;
            else
                return commandArray[i].numResponseHandles;
        }
    }

    return 0;
}

int GetNumCommandHandles(TPM2_CC commandCode)
{
    return GetNumHandles(commandCode, 1);
}

int GetNumResponseHandles( TPM2_CC commandCode )
{
    return GetNumHandles(commandCode, 0);
}
