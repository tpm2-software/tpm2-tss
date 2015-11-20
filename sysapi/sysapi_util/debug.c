//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#include <tpm20.h>   
#include <tss2_sysapi_util.h>
#include <stdio.h>

typedef struct{
    TPM_CC commandCode;
    char *commandString;
} COMMAND_CODE_DEBUG_INFO; 

char *commandCodeStrings[] =
{
    (char *)"TPM2_NV_UndefineSpaceSpecial", // 11f
    (char *)"TPM2_EvictControl", // 120
    (char *)"TPM2_HierarchyControl", // 121
    (char *)"TPM2_NV_UndefineSpace",// 122
    (char *)"", // 123
    (char *)"TPM2_ChangeEPS", // 124
    (char *)"TPM2_ChangePPS", // 125
    (char *)"TPM2_Clear", // 126
    (char *)"TPM2_ClearControl",// 127 
    (char *)"TPM2_ClockSet", // 128
    (char *)"TPM2_HierarchyChangeAuth", // 129
    (char *)"TPM2_NV_DefineSpace", // 12a
    (char *)"TPM2_PCR_Allocate", // 12b
    (char *)"TPM2_PCR_SetAuthPolicy", // 12c
    (char *)"TPM2_PP_Commands", // 12d
    (char *)"TPM2_SetPrimaryPolicy", // 12e
    (char *)"TPM2_FieldUpgradeStart", // 12f
    (char *)"TPM2_ClockRateAdjust", // 130
    (char *)"TPM2_CreatePrimary",         // 131    
    (char *)"TPM2_NV_GlobalWriteLock", // 132
    (char *)"TPM2_GetCommandAuditDigest", // 133
    (char *)"TPM2_NV_Increment", // 134
    (char *)"TPM2_NV_SetBits", // 135
    (char *)"TPM2_NV_Extend", // 136
    (char *)"TPM2_NV_Write", // 137
    (char *)"TPM2_NV_WriteLock", // 138
    (char *)"TPM2_DictionaryAttackLockReset", // 139
    (char *)"TPM2_DictionaryAttackParameters", // 13a
    (char *)"TPM2_NV_ChangeAuth", // 13b
    (char *)"TPM2_PCR_Event", // 13c
    (char *)"TPM2_PCR_Reset", // 13d
    (char *)"TPM2_SequenceComplete",// 13e 
    (char *)"TPM2_SetAlgorithmSet", // 13f
    (char *)"TPM2_SetCommandCodeAuditStatus", // 140
    (char *)"TPM2_FieldUpgradeData", // 141
    (char *)"TPM2_IncrementalSelfTest", // 142
    (char *)"TPM2_SelfTest", // 143
    (char *)"TPM2_Startup", // 144
    (char *)"TPM2_Shutdown", // 145
    (char *)"TPM2_StirRandom", // 146
    (char *)"TPM2_ActivateCredential", // 147
    (char *)"TPM2_Certify", // 148
    (char *)"TPM2_PolicyNV", // 149        
    (char *)"TPM2_CertifyCreation",// 14a 
    (char *)"TPM2_Duplicate", // 14b
    (char *)"TPM2_GetTime", // 14c
    (char *)"TPM2_GetSessionAuditDigest", // 14d
    (char *)"TPM2_NV_Read", // 14e
    (char *)"TPM2_NV_ReadLock", // 14f
    (char *)"TPM2_ObjectChangeAuth", // 150
    (char *)"TPM2_PolicySecret", // 151
    (char *)"TPM2_Rewrap", // 152
    (char *)"TPM2_Create", // 153
    (char *)"TPM2_ECDH_ZGen", // 154
    (char *)"TPM2_HMAC", // 155
    (char *)"TPM2_Import", // 156
    (char *)"TPM2_Load", // 157
    (char *)"TPM2_Quote", // 158
    (char *)"TPM2_RSA_Decrypt",// 159
    (char *)"", // 15a
    (char *)"TPM2_HMAC_Start", // 15b
    (char *)"TPM2_SequenceUpdate", // 15c
    (char *)"TPM2_Sign", // 15d
    (char *)"TPM2_Unseal",// 15e
    (char *)"", // 15f
    (char *)"TPM2_PolicySigned", // 160
    (char *)"TPM2_ContextLoad", // 161
    (char *)"TPM2_ContextSave", // 162
    (char *)"TPM2_ECDH_KeyGen", // 163
    (char *)"TPM2_EncryptDecrypt", // 164
    (char *)"TPM2_FlushContext", // 165
    (char *)"",        
    (char *)"TPM2_LoadExternal", // 167
    (char *)"TPM2_MakeCredential", // 168
    (char *)"TPM2_NV_ReadPublic", // 169
    (char *)"TPM2_PolicyAuthorize", // 16a
    (char *)"TPM2_PolicyAuthValue", // 16b
    (char *)"TPM2_PolicyCommandCode", // 16c
    (char *)"TPM2_PolicyCounterTimer", // 16d
    (char *)"TPM2_PolicyCpHash", // 16e
    (char *)"TPM2_PolicyLocality", // 16f
    (char *)"TPM2_PolicyNameHash", // 170
    (char *)"TPM2_PolicyOR", // 171
    (char *)"TPM2_PolicyTicket", // 172
    (char *)"TPM2_ReadPublic", // 173
    (char *)"TPM2_RSA_Encrypt",// 174
    (char *)"", // 175
    (char *)"TPM2_StartAuthSession", // 176
    (char *)"TPM2_VerifySignature", // 177
    (char *)"TPM2_ECC_Parameters", // 178
    (char *)"TPM2_FirmwareRead", // 179
    (char *)"TPM2_GetCapability", // 17a
    (char *)"TPM2_GetRandom", // 17b
    (char *)"TPM2_GetTestResult", // 17c
    (char *)"TPM2_Hash", // 17d
    (char *)"TPM2_PCR_Read", // 17e
    (char *)"TPM2_PolicyPCR", // 17f
    (char *)"TPM2_PolicyRestart", // 180
    (char *)"TPM2_ReadClock", // 181
    (char *)"TPM2_PCR_Extend", // 182
    (char *)"TPM2_PCR_SetAuthValue", // 183
    (char *)"TPM2_NV_Certify", // 184
    (char *)"TPM2_EventSequenceComplete", // 185
    (char *)"TPM2_HashSequenceStart", // 186
    (char *)"TPM2_PolicyPhysicalPresence", // 187
    (char *)"TPM2_PolicyDuplicationSelect", // 188
    (char *)"TPM2_PolicyGetDigest", // 189
    (char *)"TPM2_TestParms", // 18a
    (char *)"TPM2_Commit", // 18b
    (char *)"TPM2_PolicyPassword", // 18c
    (char *)"TPM2_ZGen_2Phase", // 18d
    (char *)"TPM2_EC_Ephemeral", // 18e
    (char *)"TPM2_PolicyNvWritten" // 18f
};
