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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include "sapi/tpm20.h"
#include "debug.h"

int DebugPrintf( printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if( type == RM_PREFIX )
        printf( "||  " );

    va_start( args, format );
    rval = vprintf( format, args );
    va_end (args);

    return rval;
}

/* This callback function is intended for use with the TCTI log callback
 * mechanism. It provides an additional parameter for receiving arbitrary
 * user specified data.
 */
int DebugPrintfCallback( void *data, printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if( type == RM_PREFIX )
        DebugPrintfCallback( data, NO_PREFIX,  "||  " );

    va_start( args, format );
    rval = vprintf( format, args );
    va_end (args);

    return rval;
}

void DebugPrintBuffer( printf_type type, UINT8 *buffer, UINT32 length )
{
    UINT32  i;

    for( i = 0; i < length; i++ )
    {
        if( ( i % 16 ) == 0 )
        {
            DebugPrintf(NO_PREFIX, "\n");
            if( type == RM_PREFIX )
                DebugPrintf(NO_PREFIX,  "||  " );
        }

        DebugPrintf(NO_PREFIX,  "%2.2x ", buffer[i] );
    }
    DebugPrintf(NO_PREFIX,  "\n\n" );
    fflush( stdout );
}

/* This callback function is intended for use with the TCTI log data
 * callback mechanism. It provides an additional parameter for receiving
 * arbitrary user specified data.
 */
int DebugPrintBufferCallback( void *data, printf_type type, UINT8 *buffer, UINT32 length )
{
    DebugPrintBuffer (type, buffer, length);
    return 0;
}

const char *commandCodeStrings[] =
{
    "TPM2_NV_UndefineSpaceSpecial", // 11f
    "TPM2_EvictControl", // 120
    "TPM2_HierarchyControl", // 121
    "TPM2_NV_UndefineSpace",// 122
    "", // 123
    "TPM2_ChangeEPS", // 124
    "TPM2_ChangePPS", // 125
    "TPM2_Clear", // 126
    "TPM2_ClearControl",// 127
    "TPM2_ClockSet", // 128
    "TPM2_HierarchyChangeAuth", // 129
    "TPM2_NV_DefineSpace", // 12a
    "TPM2_PCR_Allocate", // 12b
    "TPM2_PCR_SetAuthPolicy", // 12c
    "TPM2_PP_Commands", // 12d
    "TPM2_SetPrimaryPolicy", // 12e
    "TPM2_FieldUpgradeStart", // 12f
    "TPM2_ClockRateAdjust", // 130
    "TPM2_CreatePrimary",         // 131
    "TPM2_NV_GlobalWriteLock", // 132
    "TPM2_GetCommandAuditDigest", // 133
    "TPM2_NV_Increment", // 134
    "TPM2_NV_SetBits", // 135
    "TPM2_NV_Extend", // 136
    "TPM2_NV_Write", // 137
    "TPM2_NV_WriteLock", // 138
    "TPM2_DictionaryAttackLockReset", // 139
    "TPM2_DictionaryAttackParameters", // 13a
    "TPM2_NV_ChangeAuth", // 13b
    "TPM2_PCR_Event", // 13c
    "TPM2_PCR_Reset", // 13d
    "TPM2_SequenceComplete",// 13e
    "TPM2_SetAlgorithmSet", // 13f
    "TPM2_SetCommandCodeAuditStatus", // 140
    "TPM2_FieldUpgradeData", // 141
    "TPM2_IncrementalSelfTest", // 142
    "TPM2_SelfTest", // 143
    "TPM2_Startup", // 144
    "TPM2_Shutdown", // 145
    "TPM2_StirRandom", // 146
    "TPM2_ActivateCredential", // 147
    "TPM2_Certify", // 148
    "TPM2_PolicyNV", // 149
    "TPM2_CertifyCreation",// 14a
    "TPM2_Duplicate", // 14b
    "TPM2_GetTime", // 14c
    "TPM2_GetSessionAuditDigest", // 14d
    "TPM2_NV_Read", // 14e
    "TPM2_NV_ReadLock", // 14f
    "TPM2_ObjectChangeAuth", // 150
    "TPM2_PolicySecret", // 151
    "TPM2_Rewrap", // 152
    "TPM2_Create", // 153
    "TPM2_ECDH_ZGen", // 154
    "TPM2_HMAC", // 155
    "TPM2_Import", // 156
    "TPM2_Load", // 157
    "TPM2_Quote", // 158
    "TPM2_RSA_Decrypt",// 159
    "", // 15a
    "TPM2_HMAC_Start", // 15b
    "TPM2_SequenceUpdate", // 15c
    "TPM2_Sign", // 15d
    "TPM2_Unseal",// 15e
    "", // 15f
    "TPM2_PolicySigned", // 160
    "TPM2_ContextLoad", // 161
    "TPM2_ContextSave", // 162
    "TPM2_ECDH_KeyGen", // 163
    "TPM2_EncryptDecrypt", // 164
    "TPM2_FlushContext", // 165
    "",
    "TPM2_LoadExternal", // 167
    "TPM2_MakeCredential", // 168
    "TPM2_NV_ReadPublic", // 169
    "TPM2_PolicyAuthorize", // 16a
    "TPM2_PolicyAuthValue", // 16b
    "TPM2_PolicyCommandCode", // 16c
    "TPM2_PolicyCounterTimer", // 16d
    "TPM2_PolicyCpHash", // 16e
    "TPM2_PolicyLocality", // 16f
    "TPM2_PolicyNameHash", // 170
    "TPM2_PolicyOR", // 171
    "TPM2_PolicyTicket", // 172
    "TPM2_ReadPublic", // 173
    "TPM2_RSA_Encrypt",// 174
    "", // 175
    "TPM2_StartAuthSession", // 176
    "TPM2_VerifySignature", // 177
    "TPM2_ECC_Parameters", // 178
    "TPM2_FirmwareRead", // 179
    "TPM2_GetCapability", // 17a
    "TPM2_GetRandom", // 17b
    "TPM2_GetTestResult", // 17c
    "TPM2_Hash", // 17d
    "TPM2_PCR_Read", // 17e
    "TPM2_PolicyPCR", // 17f
    "TPM2_PolicyRestart", // 180
    "TPM2_ReadClock", // 181
    "TPM2_PCR_Extend", // 182
    "TPM2_PCR_SetAuthValue", // 183
    "TPM2_NV_Certify", // 184
    "TPM2_EventSequenceComplete", // 185
    "TPM2_HashSequenceStart", // 186
    "TPM2_PolicyPhysicalPresence", // 187
    "TPM2_PolicyDuplicationSelect", // 188
    "TPM2_PolicyGetDigest", // 189
    "TPM2_TestParms", // 18a
    "TPM2_Commit", // 18b
    "TPM2_PolicyPassword", // 18c
    "TPM2_ZGen_2Phase", // 18d
    "TPM2_EC_Ephemeral", // 18e
    "TPM2_PolicyNvWritten" // 18f
};

char undefinedCommandString[10] = "";

const char* strTpmCommandCode( TPM_CC code )
{
    if( code >= TPM_CC_NV_UndefineSpaceSpecial && code <= TPM_CC_PolicyNvWritten )
    {
        return commandCodeStrings[ code - TPM_CC_FIRST ];
    }
    else
    {
        snprintf( &undefinedCommandString[0],
                  sizeof (undefinedCommandString),
                  "0x%4.4x",
                  code );
        return &undefinedCommandString[0];
    }
}
