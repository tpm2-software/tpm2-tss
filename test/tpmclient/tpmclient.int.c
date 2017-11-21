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

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sapi/tpm20.h"
#include "../integration/sapi-util.h"
#include "../integration/test.h"
#include "sample.h"
#include "tpmclient.h"
#include "tcti_util.h"
#include "tss2_endian.h"
#include "sysapi_util.h"
#include "tcti/tcti_device.h"
#include "tcti/tcti_socket.h"
#include "syscontext.h"
#include "common/debug.h"

//
// TPM indices and sizes
//
#define NV_AUX_INDEX_SIZE     96
#define NV_PS_INDEX_SIZE      34
#define NV_PO_INDEX_SIZE      34

#define INDEX_AUX                       0x01800003 // NV Storage
#define INDEX_LCP_OWN                   0x01400001 // Launch Policy Owner
#define INDEX_LCP_SUP                   0x01800001 // Launch Policy Default (Supplier)
#define TPM20_INDEX_TEST1               0x01500015
#define TPM20_INDEX_TEST2               0x01500016
#define TPM20_INDEX_PASSWORD_TEST       0x01500020

#define SESSIONS_COUNT 1

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
                                                (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define CLEAR_PCR_SELECT_BITS( pcrSelection ) \
                                              (pcrSelection).pcrSelect[0] = 0; \
                                              (pcrSelection).pcrSelect[1] = 0; \
                                              (pcrSelection).pcrSelect[2] = 0;

#define SET_PCR_SELECT_SIZE( pcrSelection, size ) \
                                                  (pcrSelection).sizeofSelect = size;

TPM2_CC currentCommandCode;
TPM2_CC *currentCommandCodePtr = &currentCommandCode;

#define errorStringSize 200
char errorString[errorStringSize];

UINT8 simulator = 1;

UINT32 tpmMaxResponseLen = TPMBUF_LEN;

UINT8 resMgrInitialized = 0;

UINT8 pcrAfterExtend[20];
TPM2_HANDLE loadedRsaKeyHandle;
TPM2_HANDLE loadedSha1KeyHandle;

TPM2B_AUTH loadedSha1KeyAuth;

TPM2_HANDLE handle1024, handle2048sha1, handle2048rsa;

UINT8 indent = 0;

TSS2_SYS_CONTEXT *sysContext;

TCTI_SOCKET_CONF rmInterfaceConfig = {
    DEFAULT_HOSTNAME,
    DEFAULT_SIMULATOR_TPM_PORT,
    DebugPrintfCallback,
    DebugPrintBufferCallback,
    NULL
};

TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

#define MSFT_MANUFACTURER_ID 0x4d534654
#define IBM_MANUFACTURER_ID 0x49424d20

TPMI_SH_AUTH_SESSION StartPolicySession();
TPMI_SH_AUTH_SESSION InitNvAuxPolicySession();

TSS2_RC CompareTPM2B(TPM2B *buffer1, TPM2B *buffer2)
{
    if (buffer1->size != buffer2->size)
        return TPM2_RC_FAILURE;

    if (memcmp(buffer1->buffer, buffer2->buffer, buffer1->size))
            return TPM2_RC_FAILURE;

    return TPM2_RC_SUCCESS;
}

void PrintSizedBuffer( TPM2B *sizedBuffer )
{
    int i;

    for( i = 0; i < sizedBuffer->size; i++ )
    {
        DebugPrintf( NO_PREFIX, "%2.2x ", sizedBuffer->buffer[i] );

        if( ( (i+1) % 16 ) == 0 )
        {
            DebugPrintf( NO_PREFIX, "\n" );
        }
    }
    DebugPrintf( NO_PREFIX, "\n" );
}

#define LEVEL_STRING_SIZE 50

void ErrorHandler( UINT32 rval )
{
    UINT32 errorLevel = rval & TSS2_ERROR_LEVEL_MASK;
    char levelString[LEVEL_STRING_SIZE + 1];

    switch( errorLevel )
    {
        case TSS2_TPM_ERROR_LEVEL:
            strncpy( levelString, "TPM", LEVEL_STRING_SIZE );
            break;
        case TSS2_APP_ERROR_LEVEL:
            strncpy( levelString, "Application", LEVEL_STRING_SIZE );
            break;
        case TSS2_SYS_ERROR_LEVEL:
            strncpy( levelString, "System API", LEVEL_STRING_SIZE );
            break;
        case TSS2_SYS_PART2_ERROR_LEVEL:
            strncpy( levelString, "System API TPM encoded", LEVEL_STRING_SIZE );
            break;
        case TSS2_TCTI_ERROR_LEVEL:
            strncpy( levelString, "TCTI", LEVEL_STRING_SIZE );
            break;
        case TSS2_RESMGRTPM_ERROR_LEVEL:
            strncpy( levelString, "Resource Mgr TPM encoded", LEVEL_STRING_SIZE );
            break;
        case TSS2_RESMGR_ERROR_LEVEL:
            strncpy( levelString, "Resource Mgr", LEVEL_STRING_SIZE );
            break;
        case TSS2_DRIVER_ERROR_LEVEL:
            strncpy( levelString, "Driver", LEVEL_STRING_SIZE );
            break;
        default:
            strncpy( levelString, "Unknown Level", LEVEL_STRING_SIZE );
            break;
	}

    snprintf(errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval);
}

void Cleanup()
{
    fflush( stdout );

    if( resMgrTctiContext != 0 )
    {
        PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
        TeardownTctiContext( &resMgrTctiContext );
    }

    exit(1);
}

void InitSysContextFailure()
{
    DebugPrintf( NO_PREFIX, "InitSysContext failed, exiting...\n" );
    Cleanup();
}

void Delay( UINT16 delay)
{
    volatile UINT32 i, j;

    for( j = 0; j < delay; j++ )
    {
        for( i = 0; i < 10000000; i++ )
            ;
    }
}

TPMS_AUTH_COMMAND nullSessionData;
TPMS_AUTH_RESPONSE nullSessionDataOut;
TPMS_AUTH_COMMAND *nullSessionDataArray[1] = { &nullSessionData };
TPMS_AUTH_RESPONSE *nullSessionDataOutArray[1] = { &nullSessionDataOut };
TSS2_SYS_CMD_AUTHS nullSessionsData = { 1, &nullSessionDataArray[0] };
TSS2_SYS_RSP_AUTHS nullSessionsDataOut = { 1, &nullSessionDataOutArray[0] };
TPM2B_NONCE nullSessionNonce, nullSessionNonceOut;
TPM2B_AUTH nullSessionHmac;

TSS2_RC TpmReset()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    if( rval == TSS2_RC_SUCCESS )
    {
        rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    }
    return rval;
}

void TestDictionaryAttackLockReset()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nDICTIONARY ATTACK LOCK RESET TEST  :\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_DictionaryAttackLockReset ( sysContext, TPM2_RH_LOCKOUT, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );
}

TSS2_RC StartPolicySession( TPMI_SH_AUTH_SESSION *sessionHandle )
{
    UINT8 i;
    TPM2B_NONCE nonceCaller, nonceTpm;
    TPM2B_ENCRYPTED_SECRET salt;
    TPMT_SYM_DEF symmetric;
    UINT16 digestSize;
    UINT32 rval;

    digestSize = GetDigestSize( TPM2_ALG_SHA1 );
    nonceCaller.size = digestSize;
    for( i = 0; i < nonceCaller.size; i++ )
        nonceCaller.buffer[i] = 0;

    salt.size = 0;
    symmetric.algorithm = TPM2_ALG_NULL;

    // Create policy session
    INIT_SIMPLE_TPM2B_SIZE( nonceTpm );
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM2_RH_NULL, TPM2_RH_NULL, 0, &nonceCaller, &salt,
            TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA1, sessionHandle, &nonceTpm, 0 );
    return( rval );
}

void TestTpmStartup()
{
    UINT32 rval;

    DebugPrintf( NO_PREFIX, "\nSTARTUP TESTS:\n" );

    //
    // First test the one-call interface.
    //

    // First must do TPM reset.
    rval = TpmReset();
    CheckPassed(rval);

    // This one should pass.
    rval = Tss2_Sys_Startup( sysContext, TPM2_SU_CLEAR );
    CheckPassed(rval);

    // This one should fail.
    rval = Tss2_Sys_Startup( sysContext, TPM2_SU_CLEAR );
    CheckFailed( rval, TPM2_RC_INITIALIZE );


    // Cycle power using simulator interface.
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );


    //
    // Now test the synchronous, non-one-call interface.
    //
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM2_SU_CLEAR );
    CheckPassed(rval);

    // Execute the command synchronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed( rval );

    // Cycle power using simulator interface.
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );


    //
    // Now test the asynchronous, non-one-call interface.
    //
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM2_SU_CLEAR );
    CheckPassed(rval);

    // Execute the command asynchronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed(rval);

    // Get the command response. Wait a maximum of 20ms
    // for response.
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed(rval);
}

void TestTpmGetCapability()
{
    UINT32 rval;

    char manuID[5] = "    ";
    char *manuIDPtr = &manuID[0];
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    DebugPrintf( NO_PREFIX, "\nGET_CAPABILITY TESTS:\n" );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );

    *((UINT32 *)manuIDPtr) = BE_TO_HOST_32(capabilityData.data.tpmProperties.tpmProperty[0].value);
    DebugPrintf( NO_PREFIX, "\t\tcount: %d, property: %x, manuId: %s\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            manuID );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MAX_COMMAND_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    DebugPrintf( NO_PREFIX, "\t\tcount: %d, property: %x, max cmd size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );


    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MAX_COMMAND_SIZE, 40, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    DebugPrintf( NO_PREFIX, "\t\tcount: %d, property: %x, max cmd size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );


    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MAX_RESPONSE_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    DebugPrintf( NO_PREFIX, "\t count: %d, property: %x, max response size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );

    rval = Tss2_Sys_GetCapability( sysContext, 0, 0xff, TPM2_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckFailed(rval, TPM2_RC_VALUE+TPM2_RC_1+TPM2_RC_P);
}

void TestTpmClear()
{
    UINT32 rval;
    TPM2B_AUTH      hmac;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPM2B_NONCE     nonce;
    TSS2_SYS_CMD_AUTHS sessionsDataIn;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataIn.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsDataOut.rspAuths[0] = &sessionDataOut;

    DebugPrintf( NO_PREFIX, "\nCLEAR and CLEAR CONTROL TESTS:\n" );

    // Init sessionHandle
    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    nonce.size = 0;
    sessionData.nonce = nonce;

    // init hmac
    hmac.size = 0;
    sessionData.hmac = hmac;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsDataIn.cmdAuthsCount = 1;
    sessionsDataIn.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_Clear ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, YES, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Clear ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, 0 );
    CheckFailed( rval, TPM2_RC_DISABLED );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckPassed( rval );

    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0xff;
    sessionsDataIn.cmdAuths[0] = &sessionData;
    rval = Tss2_Sys_Clear ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_9 + TPM2_RC_RESERVED_BITS );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_9 + TPM2_RC_RESERVED_BITS );

    hmac.size = 0;


}

#define SESSIONS_ABOVE_MAX_ACTIVE 0
#define DEBUG_MAX_ACTIVE_SESSIONS   8
#define DEBUG_GAP_MAX   2*DEBUG_MAX_ACTIVE_SESSIONS

SESSION *sessions[SESSIONS_COUNT];

void TestStartAuthSession()
{
    UINT32 rval;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPMT_SYM_DEF symmetric;
    SESSION *authSession = NULL;
    TPM2B_NONCE nonceCaller;
    UINT16 i;
    TPM2_HANDLE badSessionHandle = 0x03010000;

    TPMS_AUTH_COMMAND sessionData;
    TPM2B_NONCE     nonce;


    TPM2B_AUTH      hmac;


    // Init sessionHandle
    sessionData.sessionHandle = badSessionHandle;

    // Init nonce.
    nonce.size = 0;
    sessionData.nonce = nonce;

    // init hmac
    hmac.size = 0;
    sessionData.hmac = hmac;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    encryptedSalt.size = 0;

    DebugPrintf( NO_PREFIX, "\nSTART_AUTH_SESSION TESTS:\n" );

    symmetric.algorithm = TPM2_ALG_NULL;
    symmetric.keyBits.sym = 0;
    symmetric.mode.sym = 0;

    nonceCaller.size = 0;

    encryptedSalt.size = 0;

     // Init session
    rval = StartAuthSessionWithParams( &authSession, TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, authSession->sessionHandle );
    CheckPassed( rval );
    EndAuthSession( authSession );

    // Init session
    rval = StartAuthSessionWithParams( &authSession, TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, 0xff, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckFailed( rval, TPM2_RC_VALUE + TPM2_RC_P + TPM2_RC_3 );

    // Try starting a bunch to see if resource manager handles this correctly.
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
    {
        // Init session struct
        rval = StartAuthSessionWithParams( &sessions[i], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );
        DebugPrintf( NO_PREFIX, "Number of sessions created: %d\n\n", i+1 );

    }
    // clean up the sessions that I don't want here.
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *)); i++ )
    {
        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );

        rval = EndAuthSession( sessions[i] );
    }

    // Now do some gap tests.
    rval = StartAuthSessionWithParams( &sessions[0], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    for( i = 1; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
    {
        rval = StartAuthSessionWithParams( &sessions[i], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i] );
        CheckPassed( rval );
    }

    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
    {
        rval = StartAuthSessionWithParams( &sessions[i], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i] );
        CheckPassed( rval );

    }
}

void TestChangeEps()
{
    UINT32 rval;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nCHANGE_EPS TESTS:\n" );

	sessionsData.cmdAuthsCount = 1;

    // Init authHandle
    sessionsData.cmdAuths[0]->sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionsData.cmdAuths[0]->nonce.size = 0;

    // init hmac
    sessionsData.cmdAuths[0]->hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionsData.cmdAuths[0]->sessionAttributes ) ) = 0;

    rval = Tss2_Sys_ChangeEPS( sysContext, TPM2_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );
}

void TestChangePps()
{
    UINT32 rval;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nCHANGE_PPS TESTS:\n" );

    sessionsData.cmdAuthsCount = 1;

    // Init authHandle
    sessionsData.cmdAuths[0]->sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionsData.cmdAuths[0]->nonce.size = 0;

    // init hmac
    sessionsData.cmdAuths[0]->hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionsData.cmdAuths[0]->sessionAttributes ) ) = 0;

    rval = Tss2_Sys_ChangePPS( sysContext, TPM2_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );
}

void TestHierarchyChangeAuth()
{
    UINT32 rval;
    TPM2B_AUTH      newAuth;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    int i;

    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;

    sessionsData.cmdAuths = &sessionDataArray[0];

    DebugPrintf( NO_PREFIX, "\nHIERARCHY_CHANGE_AUTH TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    newAuth.size = 0;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    // Init new auth
    newAuth.size = 20;
    for( i = 0; i < newAuth.size; i++ )
        newAuth.buffer[i] = i;

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    sessionData.hmac = newAuth;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    // Init new auth
    newAuth.size = 0;

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    sessionsData.cmdAuths[0] = &sessionData;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckFailed( rval, TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH );

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, 0, &sessionsData, &newAuth, 0 );
    CheckFailed( rval, TPM2_RC_1 + TPM2_RC_VALUE );
}

#define PCR_0   0
#define PCR_1   1
#define PCR_2   2
#define PCR_3   3
#define PCR_4   4
#define PCR_5   5
#define PCR_6   6
#define PCR_7   7
#define PCR_8   8
#define PCR_9   9
#define PCR_10  10
#define PCR_11  11
#define PCR_12  12
#define PCR_13  13
#define PCR_14  14
#define PCR_15  15
#define PCR_16  16
#define PCR_17  17
#define PCR_18  18

#define PCR_SIZE 20

void TestPcrExtend()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    UINT16 i, digestSize;
    TPML_PCR_SELECTION  pcrSelection;
    UINT32 pcrUpdateCounterBeforeExtend;
    UINT32 pcrUpdateCounterAfterExtend;
    UINT8 pcrBeforeExtend[PCR_SIZE];
    TPM2B_EVENT eventData;
    TPML_DIGEST pcrValues;
    TPML_DIGEST_VALUES digests;
    TPML_PCR_SELECTION pcrSelectionOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];

    DebugPrintf( NO_PREFIX, "\nPCR_EXTEND, PCR_EVENT, PCR_ALLOCATE, and PCR_READ TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    // Init digests
    digests.count = 1;
    digests.digests[0].hashAlg = TPM2_ALG_SHA1;
    digestSize = GetDigestSize( digests.digests[0].hashAlg );

    for( i = 0; i < digestSize; i++ )
    {
        digests.digests[0].digest.sha1[i] = (UINT8)(i % 256);
    }

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA1;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;

    // Clear out PCR select bit field
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;

    // Now set the PCR you want to read
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_17 );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterBeforeExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    if( pcrValues.digests[0].size <= PCR_SIZE &&
            pcrValues.digests[0].size <= sizeof( pcrValues.digests[0].buffer ) )
        memcpy( &( pcrBeforeExtend[0] ), &( pcrValues.digests[0].buffer[0] ), pcrValues.digests[0].size );

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_PCR_Extend( sysContext, PCR_17, &sessionsData, &digests, 0  );
    CheckPassed( rval );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    memcpy( &( pcrAfterExtend[0] ), &( pcrValues.digests[0].buffer[0] ), pcrValues.digests[0].size );

    if( pcrUpdateCounterBeforeExtend == pcrUpdateCounterAfterExtend )
    {
        DebugPrintf( NO_PREFIX, "ERROR!! pcrUpdateCounter didn't change value\n" );
        Cleanup();
    }

    if( 0 == memcmp( &( pcrBeforeExtend[0] ), &( pcrAfterExtend[0] ), 20 ) )
    {
        DebugPrintf( NO_PREFIX, "ERROR!! PCR didn't change value\n" );
        Cleanup();
    }

    pcrSelection.pcrSelections[0].sizeofSelect = 255;

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, 0, 0, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    eventData.size = 4;
    eventData.buffer[0] = 0;
    eventData.buffer[1] = 0xff;
    eventData.buffer[2] = 0x55;
    eventData.buffer[3] = 0xaa;

    rval = Tss2_Sys_PCR_Event( sysContext, PCR_18, &sessionsData, &eventData, &digests, 0  );
    CheckPassed( rval );
}

void TestShutdown()
{
    UINT32 rval;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TPMS_AUTH_RESPONSE sessionDataOut;

    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nSHUTDOWN TESTS:\n" );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM2_SU_STATE, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM2_SU_CLEAR, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, 0xff, 0 );
    CheckFailed( rval, TPM2_RC_VALUE+TPM2_RC_1+TPM2_RC_P );
}

void TestNV()
{
    UINT32 rval;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    int i;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    TPM2B_MAX_NV_BUFFER nvData;

    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nNV INDEX TESTS:\n" );

    nvAuth.size = 20;
    for( i = 0; i < nvAuth.size; i++ ) {
        nvAuth.buffer[i] = (UINT8)i;
    }

    publicInfo.size = sizeof( TPMI_RH_NV_INDEX ) +
        sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
        sizeof( UINT16 );
    publicInfo.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = 32;

    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_2 + TPM2_RC_HANDLE );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );

    nvPublic.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_NV_UNINITIALIZED );

    // Should fail since index is already defined.
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_NV_DEFINED );

    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

#if 1
    //
    // Following, at one point, was commented out so that NVDefine will work on successive
    // invocations of client app.
    //
    // Noticed on 12/13/12, this doesn't seem to be necessary anymore.  Maybe something else
    // I did fixed it.
    //
    // Seems to be a bug in TPM 2.0 simulator that if:
    //   First pass of tpmclient.exe after restarting TPM 2.0 simulator will work fine.
    //   If NVWrite is done, subsequent invocations of tpmclient.exe will ALWAYS fail on
    //      first call to Tpm2NVDefineSpace with 0x2cb error. Removing NVWrite removes this.
    //      And restarting TPM 2.0 simulator will make it work the first time and fail
    //      subsequent times.
    //      Removing NVWrite works around this problem.
    //
    rval = Tss2_Sys_NV_Write( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_WriteLock( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Write( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_NV_LOCKED );
#endif

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );

    publicInfo.nvPublic.attributes.TPMA_NV_PPREAD = 0;
    publicInfo.nvPublic.attributes.TPMA_NV_PPWRITE = 0;
    publicInfo.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 0;
    publicInfo.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.nvPublic.nvIndex = TPM20_INDEX_TEST2;
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    nvPublic.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST2, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST2, &sessionsData, 32, 0, &nvData, 0 );
    CheckFailed( rval, TPM2_RC_NV_AUTHORIZATION );

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );
}

void TestHierarchyControl()
{
    UINT32 rval;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    int i;
    TPM2B_NAME nvName;
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_MAX_NV_BUFFER nvData;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nHIERARCHY CONTROL TESTS:\n" );

    nvAuth.size = 20;
    for( i = 0; i < nvAuth.size; i++ ) {
        nvAuth.buffer[i] = i;
    }

    publicInfo.size = sizeof( TPMI_RH_NV_INDEX ) +
        sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
        sizeof( UINT16 );
    publicInfo.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = 32;

    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Test SAPI for case where nvPublic.size != 0
    nvPublic.size = 0xff;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    nvPublic.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Read( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_NV_UNINITIALIZED );

    rval = Tss2_Sys_HierarchyControl( sysContext, TPM2_RH_PLATFORM, &sessionsData, TPM2_RH_PLATFORM, NO, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Read( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_1 + TPM2_RC_HIERARCHY );

    rval = Tss2_Sys_HierarchyControl( sysContext, TPM2_RH_PLATFORM, &sessionsData, TPM2_RH_PLATFORM, YES, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_1 + TPM2_RC_HIERARCHY );

    // Need to do TPM reset and Startup to re-enable platform hierarchy.
    rval = TpmReset();
    CheckPassed(rval);

    rval = Tss2_Sys_Startup ( sysContext, TPM2_SU_CLEAR );
    CheckPassed( rval );

    rval = Tss2_Sys_HierarchyControl( sysContext, TPM2_RH_PLATFORM, &sessionsData, TPM2_RH_PLATFORM, YES, &sessionsDataOut );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );
}

TPM2B_PUBLIC    inPublic = {sizeof( TPM2B_PUBLIC ) - 2,};

void TestCreate(){
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive = {sizeof( TPM2B_SENSITIVE_CREATE ) - 2,};
    TPM2B_DATA              outsideInfo = {sizeof( TPM2B_DATA ) - 2,};
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
	TPM2B_NAME name = {sizeof( TPM2B_NAME ) - 2,};
	TPM2B_NAME name1 = {sizeof( TPM2B_NAME ) - 2,};
    TPM2B_PRIVATE outPrivate = {sizeof( TPM2B_PRIVATE ) - 2,};
    TPM2B_PUBLIC outPublic = {sizeof( TPM2B_PUBLIC ) - 2,};
    TPM2B_CREATION_DATA creationData =  {sizeof( TPM2B_CREATION_DATA ) - 2,};
	TPM2B_DIGEST creationHash = {sizeof( TPM2B_DIGEST ) - 2,};
	TPMT_TK_CREATION creationTicket = { 0, 0, {sizeof( TPM2B_DIGEST ) - 2,} };

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nCREATE, CREATE PRIMARY, and LOAD TESTS:\n" );

    inSensitive.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.sensitive.data.size = 0;
    inSensitive.size = loadedSha1KeyAuth.size + 2;

    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.publicArea.objectAttributes) = 0;
    inPublic.publicArea.objectAttributes.restricted = 1;
    inPublic.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.publicArea.objectAttributes.decrypt = 1;
    inPublic.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.publicArea.objectAttributes.fixedParent = 1;
    inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.publicArea.authPolicy.size = 0;

    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_ECB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.publicArea.unique.rsa.size = 0;

    outsideInfo.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    // Do SAPI test for non-zero sized outPublic
    outPublic.size = 0xff;
    creationData.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM2_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );

    outPublic.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationData );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM2_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );

    outPublic.size = 0;
    creationData.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM2_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    DebugPrintf( NO_PREFIX, "\nNew key successfully created in platform hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );

    sessionData.hmac.size = 2;
    sessionData.hmac.buffer[0] = 0x00;
    sessionData.hmac.buffer[1] = 0xff;

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.objectAttributes.decrypt = 0;
    inPublic.publicArea.objectAttributes.sign = 1;

    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA1;

    inPublic.publicArea.unique.keyedHash.size = 0;

    outsideInfo.size = 0;
    outPublic.size = 0;
    creationData.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = TSS2_RETRY_EXP( Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut ));
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    rval = TpmHandleToName( loadedSha1KeyHandle, &name1 );
    CheckPassed( rval );
    DebugPrintf( NO_PREFIX, "Name of loaded key: " );
    PrintSizedBuffer((TPM2B *)&name1);
    rval = CompareTPM2B((TPM2B *)&name, (TPM2B *)&name1);
    CheckPassed( rval );

    DebugPrintf( NO_PREFIX, "\nLoaded key handle:  %8.8x\n", loadedSha1KeyHandle );
}

void TestEvict()
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;
    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nEVICT CONTROL TESTS:\n" );

    sessionData.sessionHandle = TPM2_RS_PW;
    sessionData.nonce.size = 0;
    sessionData.hmac.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    rval = Tss2_Sys_EvictControl( sysContext, TPM2_RH_PLATFORM, handle2048rsa, &sessionsData, 0x81800000, &sessionsDataOut );
    CheckPassed( rval );

    // Reset persistent key to be transitent.
    sessionData.hmac.size = 0;
    rval = Tss2_Sys_EvictControl( sysContext, TPM2_RH_PLATFORM, 0x81800000, &sessionsData, 0x81800000, &sessionsDataOut );
    CheckPassed( rval );
}

TSS2_RC DefineNvIndex( TPMI_RH_PROVISION authHandle, TPMI_SH_AUTH_SESSION sessionAuthHandle, TPM2B_AUTH *auth, TPM2B_DIGEST *authPolicy,
    TPMI_RH_NV_INDEX nvIndex, TPMI_ALG_HASH nameAlg, TPMA_NV attributes, UINT16 size  )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_NV_PUBLIC publicInfo;

    // Command and response session data structures.
    TPMS_AUTH_COMMAND sessionData = { sessionAuthHandle, };
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };
    // Init nonce.
    sessionData.nonce.size = 0;
    // init hmac
    sessionData.hmac.size = 0;
    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    attributes.TPMA_NV_ORDERLY = 1;

    // Init public info structure.
    publicInfo.nvPublic.attributes = attributes;
    CopySizedByteBuffer((TPM2B *)&publicInfo.nvPublic.authPolicy, (TPM2B *)authPolicy);
    publicInfo.nvPublic.dataSize = size;
    publicInfo.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = nameAlg;

    // Create the index
    rval = Tss2_Sys_NV_DefineSpace( sysContext, authHandle, &sessionsData, auth, &publicInfo, &sessionsDataOut );

    return rval;
}

typedef struct {
    char name[50];
    TSS2_RC (*buildPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *trialPolicySession, TPM2B_DIGEST *policyDigest );
    TSS2_RC (*createObjectFn )( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest );
    TSS2_RC (*testPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession );
} POLICY_TEST_SETUP;

TSS2_RC BuildPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession,
    TSS2_RC (*buildPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest ),
    TPM2B_DIGEST *policyDigest, bool trialSession )
{
    // NOTE:  this policySession will be either a trial or normal policy session
    // depending on the value of the passed in trialSession parameter.
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = {0,};
    TPMT_SYM_DEF symmetric;
    TSS2_RC rval;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    // Start policy session.
    symmetric.algorithm = TPM2_ALG_NULL;
    rval = StartAuthSessionWithParams( policySession, TPM2_RH_NULL, 0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, trialSession ? TPM2_SE_TRIAL : TPM2_SE_POLICY , &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    if( rval != TPM2_RC_SUCCESS )
        return rval;

    // Send policy command.
    rval = ( *buildPolicyFn )( sysContext, *policySession, policyDigest );
    CheckPassed( rval );

    // Get policy hash.
    INIT_SIMPLE_TPM2B_SIZE( *policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, (*policySession)->sessionHandle,
            0, policyDigest, 0 );
    CheckPassed( rval );

    if( trialSession )
    {
        // Need to flush the session here.
        rval = Tss2_Sys_FlushContext( sysContext, (*policySession)->sessionHandle );
        CheckPassed( rval );

        // And remove the session from sessions table.
        rval = EndAuthSession( *policySession );
        CheckPassed( rval );
    }

    return rval;
}

TSS2_RC CreateNVIndex( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPMA_LOCALITY locality;
    TPM2B_ENCRYPTED_SECRET encryptedSalt = {0};
    TPMT_SYM_DEF symmetric;
    TPMA_NV nvAttributes;
    TPM2B_AUTH  nvAuth;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    // Since locality is a fairly simple command and we can guarantee
    // its correctness, we don't need a trial session for this.

    // Start real policy session
    symmetric.algorithm = TPM2_ALG_NULL;
    rval = StartAuthSessionWithParams( policySession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY,
            &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    // Send PolicyLocality command
    *(UINT8 *)( (void *)&locality ) = 0;
    locality.TPM2_LOC_THREE = 1;
    rval = Tss2_Sys_PolicyLocality( sysContext, (*policySession)->sessionHandle,
            0, locality, 0 );
    CheckPassed( rval );

    // Read policyHash
    INIT_SIMPLE_TPM2B_SIZE( *policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext,
            (*policySession)->sessionHandle, 0, policyDigest, 0 );
    CheckPassed( rval );

    nvAuth.size = 0;

    // Now set the attributes.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_POLICYREAD = 1;
    nvAttributes.TPMA_NV_POLICYWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW, &nvAuth, policyDigest,
            TPM20_INDEX_PASSWORD_TEST, TPM2_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    return rval;
}


TSS2_RC TestLocality( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, };
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    // Init write data.
    nvWriteData.size = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0]->sessionHandle = policySession->sessionHandle;
    sessionsData.cmdAuths[0]->nonce.size = 0;
    sessionsData.cmdAuths[0]->hmac.size = 0;

    *(UINT8 *)( (void *)&( sessionsData.cmdAuths[0]->sessionAttributes ) ) = 0;
     sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 1;

    rval = SetLocality( sysContext, 2 );
    CheckPassed( rval );

    // Do NV write using open session's policy.
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_LOCALITY );

    rval = SetLocality( sysContext, 3 );
    CheckPassed( rval );

    // Do NV write using open session's policy.
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckPassed( rval );

    // Do another NV write using open session's policy.
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_POLICY_FAIL + TPM2_RC_S + TPM2_RC_1 );

    // Delete NV index
    sessionsData.cmdAuths[0]->sessionHandle = TPM2_RS_PW;
    sessionsData.cmdAuths[0]->nonce.size = 0;
    sessionsData.cmdAuths[0]->nonce.buffer[0] = 0xa5;
    sessionData.hmac.size = 0;

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );

    rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
    CheckPassed( rval );

    return rval;
}

UINT8 passwordPCRTestPassword[] = "password PCR";
UINT8 dataBlob[] = "some data";
TPM2_HANDLE blobHandle;
TPM2B_AUTH blobAuth;

TSS2_RC BuildPasswordPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;

    rval = Tss2_Sys_PolicyPassword( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    return rval;
}

TSS2_RC BuildAuthValuePolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;

    rval = Tss2_Sys_PolicyAuthValue( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    return rval;
}


TSS2_RC BuildPasswordPcrPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_DIGEST pcrDigest;
    TPML_PCR_SELECTION pcrs;
    TPML_DIGEST pcrValues;
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;

    pcrDigest.size = 0;
    rval = Tss2_Sys_PolicyPassword( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    pcrs.count = 1;
    pcrs.pcrSelections[0].hash = TPM2_ALG_SHA1;
    pcrs.pcrSelections[0].sizeofSelect = 3;
    pcrs.pcrSelections[0].pcrSelect[0] = 0;
    pcrs.pcrSelections[0].pcrSelect[1] = 0;
    pcrs.pcrSelections[0].pcrSelect[2] = 0;
    SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], PCR_0 );
    SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], PCR_3 );

    //
    // Compute pcrDigest
    //
    // Read PCRs
    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrs, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    // Hash them together
    INIT_SIMPLE_TPM2B_SIZE( pcrDigest );
    rval = TpmHashSequence( policySession->authHash, pcrValues.count, &pcrValues.digests[0], &pcrDigest );
    CheckPassed( rval );

    rval = Tss2_Sys_PolicyPCR( sysContext, policySession->sessionHandle, 0, &pcrDigest, &pcrs, 0 );
    CheckPassed( rval );

    return rval;
}


TSS2_RC CreateDataBlob( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo = {0,};
    TPML_PCR_SELECTION creationPcr = { 0 };
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2_HANDLE srkHandle;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME srkName, blobName;
	TPM2B_DIGEST data;
    TPM2B_PRIVATE outPrivate;

    cmdAuth.sessionHandle = TPM2_RS_PW;
    cmdAuth.nonce.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.hmac.size = 0;

    inSensitive.sensitive.userAuth.size = 0;
    inSensitive.sensitive.data.size = 0;

    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;
    *(UINT32 *)&( inPublic.publicArea.objectAttributes) = 0;
    inPublic.publicArea.objectAttributes.restricted = 1;
    inPublic.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.publicArea.objectAttributes.decrypt = 1;
    inPublic.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.publicArea.objectAttributes.fixedParent = 1;
    inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CBC;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    outPublic.size = 0;
    creationData.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( srkName );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM2_RH_PLATFORM, &cmdAuthArray,
            &inSensitive, &inPublic, &outsideInfo, &creationPcr,
            &srkHandle, &outPublic, &creationData, &creationHash,
            &creationTicket, &srkName, 0 );
    CheckPassed( rval );

    cmdAuth.sessionHandle = TPM2_RS_PW;

    inSensitive.sensitive.userAuth.size = 0;
    blobAuth.size = sizeof( passwordPCRTestPassword );
    memcpy( &blobAuth.buffer, passwordPCRTestPassword, sizeof( passwordPCRTestPassword ) );
    CopySizedByteBuffer((TPM2B *)&inSensitive.sensitive.userAuth, (TPM2B *)&blobAuth);
    data.size = sizeof( dataBlob );
    memcpy( &data.buffer, dataBlob, sizeof( dataBlob ) );
    CopySizedByteBuffer((TPM2B *)&inSensitive.sensitive.data, (TPM2B *)&data);

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes.restricted = 0;
    inPublic.publicArea.objectAttributes.decrypt = 0;
    inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 0;
    CopySizedByteBuffer((TPM2B *)&inPublic.publicArea.authPolicy, (TPM2B *)policyDigest);
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.unique.keyedHash.size = 0;

    outPublic.size = 0;
    creationData.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( sysContext, srkHandle, &cmdAuthArray,
            &inSensitive, &inPublic, &outsideInfo, &creationPcr,
            &outPrivate, &outPublic, &creationData, &creationHash,
            &creationTicket, 0 );
    CheckPassed( rval );

    // Now we need to load the object.
    INIT_SIMPLE_TPM2B_SIZE( blobName );
    rval = Tss2_Sys_Load( sysContext, srkHandle, &cmdAuthArray, &outPrivate, &outPublic, &blobHandle, &blobName, 0 );
    CheckPassed( rval );

    return rval;
}

TSS2_RC AuthValueUnseal( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_SENSITIVE_DATA outData;
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    cmdAuth.sessionHandle = policySession->sessionHandle;
    cmdAuth.nonce.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.sessionAttributes.continueSession = 1;
    cmdAuth.hmac.size = 0;

    // Now try to unseal the blob without setting the HMAC.
    // This test should fail.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckFailed( rval, TPM2_RC_S + TPM2_RC_1 + TPM2_RC_AUTH_FAIL );

    // Clear DA lockout.
    TestDictionaryAttackLockReset();

    //
    // Now try to unseal the blob after setting the HMAC.
    // This test should pass.
    //

    // First, call Prepare.
    rval = Tss2_Sys_Unseal_Prepare( sysContext, blobHandle );
    CheckPassed( rval );

    rval = AddEntity( blobHandle, &blobAuth );
    CheckPassed( rval );

    // Roll nonces for command.
    RollNonces( policySession, &cmdAuth.nonce );

    // Now generate the HMAC.
    rval = ComputeCommandHmacs( sysContext,
            blobHandle,
            TPM2_HT_NO_HANDLE, &cmdAuthArray, 1 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckPassed( rval );

    rval = DeleteEntity( blobHandle );
    CheckPassed( rval );

    // Add test to make sure we unsealed correctly.

    // Now we'll want to flush the data blob and remove it
    // from resource manager tables.
    rval = Tss2_Sys_FlushContext( sysContext, blobHandle );
    CheckPassed( rval );

    return rval;
}

TSS2_RC PasswordUnseal( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_SENSITIVE_DATA outData;
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    cmdAuth.sessionHandle = policySession->sessionHandle;
    cmdAuth.nonce.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.sessionAttributes.continueSession = 1;
    cmdAuth.hmac.size = 0;

    // Now try to unseal the blob without setting the password.
    // This test should fail.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckFailed( rval, TPM2_RC_S + TPM2_RC_1 + TPM2_RC_AUTH_FAIL );

    // Clear DA lockout.
    TestDictionaryAttackLockReset();

    // Now try to unseal the blob after setting the password.
    // This test should pass.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    cmdAuth.hmac.size = sizeof( passwordPCRTestPassword );
    memcpy( &cmdAuth.hmac.buffer, passwordPCRTestPassword, sizeof( passwordPCRTestPassword ) );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckPassed( rval );

    // Add test to make sure we unsealed correctly.

    // Now we'll want to flush the data blob and remove it
    // from resource manager tables.
    rval = Tss2_Sys_FlushContext( sysContext, blobHandle );
    CheckPassed( rval );

    return rval;
}

POLICY_TEST_SETUP policyTestSetups[] =
{
    // NOTE:  Since locality is a fairly simple command and we
    // can guarantee its correctness, we don't need a trial
    // session for this. buildPolicyFn pointer can be 0 in
    // this case.
    { "LOCALITY", 0, CreateNVIndex, TestLocality },
    { "PASSWORD", BuildPasswordPolicy, CreateDataBlob, PasswordUnseal },
};

void TestPolicy()
{
    UINT32 rval;
    unsigned int i;
    SESSION *policySession = 0;

    DebugPrintf( NO_PREFIX, "\nPOLICY TESTS:\n" );

    for( i = 0; i < ( sizeof( policyTestSetups ) / sizeof( POLICY_TEST_SETUP ) ); i++ )
    {
        TPM2B_DIGEST policyDigest;

        policyDigest.size = 0;

        rval = TPM2_RC_SUCCESS;

        DebugPrintf( NO_PREFIX, "Policy Test: %s\n", policyTestSetups[i].name );

        // Create trial policy session and run policy commands, in order to create policyDigest.
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, true );
            CheckPassed( rval );
#ifdef DEBUG
            DebugPrintf( NO_PREFIX, "Built policy digest:  \n" );
            DebugPrintBuffer( NO_PREFIX, &(policyDigest.buffer[0]), policyDigest.size );
#endif
        }

        // Create entity that will use that policyDigest as authPolicy.
        if( policyTestSetups[i].createObjectFn != 0 )
        {
#ifdef DEBUG
            DebugPrintf( NO_PREFIX, "Policy digest used to create object:  \n" );
            DebugPrintBuffer( NO_PREFIX, &(policyDigest.buffer[0]), policyDigest.size );
#endif

            rval = ( *policyTestSetups[i].createObjectFn )( sysContext, &policySession, &policyDigest);
            CheckPassed( rval );
        }

        // Create real policy session and run policy commands; after this we're ready
        // to authorize actions on the entity.
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, false );
            CheckPassed( rval );
#ifdef DEBUG
            DebugPrintf( NO_PREFIX, "Command policy digest:  \n" );
            DebugPrintBuffer( NO_PREFIX, &(policyDigest.buffer[0]), policyDigest.size );
#endif
        }

        if( policySession )
        {
            // Now do tests by authorizing actions on the entity.
            rval = ( *policyTestSetups[i].testPolicyFn)( sysContext, policySession );
            CheckPassed( rval );

            // Need to flush the session here.
            rval = Tss2_Sys_FlushContext( sysContext, policySession->sessionHandle );
            CheckPassed( rval );

            // And remove the session from test app session table.
            rval = EndAuthSession( policySession );
        }
        else
        {
            CheckFailed( rval, 0xffffffff );
        }

        CheckPassed( rval );
    }
}

#define MAX_TEST_SEQUENCES 10
void TestHash()
{
    UINT32 rval;
    TPM2B_AUTH auth;
    TPMI_DH_OBJECT  sequenceHandle[MAX_TEST_SEQUENCES];
    TPMS_AUTH_COMMAND sessionData, sessionData1;
    TPMS_AUTH_RESPONSE sessionDataOut, sessionDataOut1;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPM2B_MAX_BUFFER dataToHash;
    TPM2B_DIGEST result;
    TPMT_TK_HASHCHECK validation;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[2];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[2];
    UINT8 memoryToHash[] =
    {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
          0xde, 0xad, 0xbe, 0xef };

    UINT8 goodHashValue[] =
            { 0xB3, 0xFD, 0x6A, 0xD2, 0x9F, 0xD0, 0x13, 0x52, 0xBA, 0xFC,
              0x8B, 0x22, 0xC9, 0x6D, 0x88, 0x42, 0xA3, 0x3C, 0xB0, 0xC9 };


    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;
    sessionDataArray[1] = &sessionData1;
    sessionDataOutArray[1] = &sessionDataOut1;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nHASH TESTS:\n" );

    auth.size = 2;
    auth.buffer[0] = 0;
    auth.buffer[1] = 0xff;
    rval = Tss2_Sys_HashSequenceStart ( sysContext, 0, &auth, TPM2_ALG_SHA1, &sequenceHandle[0], 0 );
    CheckPassed( rval );

    sessionData.sessionHandle = TPM2_RS_PW;
    sessionData.nonce.size = 0;
    sessionData.hmac = auth;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    dataToHash.size = TPM2_MAX_DIGEST_BUFFER;
    memcpy( &dataToHash.buffer[0], &memoryToHash[0], dataToHash.size );

    rval = Tss2_Sys_SequenceUpdate ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash, &sessionsDataOut );
    CheckPassed( rval );
    dataToHash.size = sizeof( memoryToHash ) - TPM2_MAX_DIGEST_BUFFER;
    memcpy( &dataToHash.buffer[0], &memoryToHash[TPM2_MAX_DIGEST_BUFFER], dataToHash.size );
    INIT_SIMPLE_TPM2B_SIZE( result );
    rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash,
            TPM2_RH_PLATFORM, &result, &validation, &sessionsDataOut );
    CheckPassed( rval );

    // Test the resulting hash.
    if (memcmp(result.buffer, goodHashValue, result.size)) {
        DebugPrintf( NO_PREFIX, "ERROR!! resulting hash is incorrect.\n" );
        Cleanup();
    }
}

void TestQuote()
{
    UINT32 rval;
    TPM2B_DATA qualifyingData;
    UINT8 qualDataString[] = { 0x00, 0xff, 0x55, 0xaa };
    TPMT_SIG_SCHEME inScheme;
    TPML_PCR_SELECTION  pcrSelection;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nQUOTE CONTROL TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 2;
    sessionData.hmac.buffer[0] = 0x00;
    sessionData.hmac.buffer[1] = 0xff;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    qualifyingData.size = sizeof( qualDataString );
    memcpy( &( qualifyingData.buffer[0] ), qualDataString, sizeof( qualDataString ) );

    inScheme.scheme = TPM2_ALG_NULL;

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA1;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;

    // Clear out PCR select bit field
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;

    // Now set the PCR you want
    pcrSelection.pcrSelections[0].pcrSelect[( PCR_17/8 )] = ( 1 << ( PCR_18 % 8) );

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    // Test with wrong type of key.
    INIT_SIMPLE_TPM2B_SIZE( quoted );
    rval = Tss2_Sys_Quote ( sysContext, loadedSha1KeyHandle, &sessionsData, &qualifyingData, &inScheme,
            &pcrSelection,  &quoted, &signature, &sessionsDataOut );
    CheckPassed( rval );

    // Create signing key


    // Now test quote operation
//    Tpm20Quote ( ??TPMI_DH_OBJECT signHandle, TPM2B_DATA *qualifyingData,
//    TPMT_SIG_SCHEME *inScheme, TPML_PCR_SELECTION *pcrSelect,
//    TPMS_AUTH_COMMAND *sessionsData)

}

void ProvisionOtherIndices()
{
    UINT32 rval;
    TPMI_SH_AUTH_SESSION otherIndicesPolicyAuthHandle;
    TPM2B_DIGEST  nvPolicyHash;
    TPM2B_AUTH  nvAuth;
    TPMS_AUTH_COMMAND otherIndicesSessionData;
    TPMS_AUTH_RESPONSE otherIndicesSessionDataOut;
    TSS2_SYS_CMD_AUTHS otherIndicesSessionsData;
    TSS2_SYS_RSP_AUTHS otherIndicesSessionsDataOut;
    TPM2B_NV_PUBLIC publicInfo;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &otherIndicesSessionData;
    sessionDataOutArray[0] = &otherIndicesSessionDataOut;

    otherIndicesSessionsDataOut.rspAuths = &sessionDataOutArray[0];
    otherIndicesSessionsData.cmdAuths = &sessionDataArray[0];

    otherIndicesSessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nPROVISION OTHER NV INDICES:\n" );

    //
    // AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer
    // Do this by setting up two policies and ORing them together when creating AuxIndex:
    // 1.  PolicyLocality(3) && PolicyCommand(NVWrite)
    // 2.  EmptyAuth policy && PolicyCommand(NVRead)
    // Page 126 of Part 1 describes how to do this.
    //

    // Steps:
    rval = StartPolicySession( &otherIndicesPolicyAuthHandle );
    CheckPassed( rval );

    // 3.  GetPolicyDigest and save it
    INIT_SIMPLE_TPM2B_SIZE( nvPolicyHash );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, otherIndicesPolicyAuthHandle, 0, &nvPolicyHash, 0 );
    CheckPassed( rval );

    // Now save the policy digest from the first OR branch.
    DEBUG_PRINT_BUFFER( NO_PREFIX, &( nvPolicyHash.buffer[0] ), nvPolicyHash.size );

    // 4.  CreateNvIndex
    otherIndicesSessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    otherIndicesSessionData.nonce.size = 0;

    // init hmac
    otherIndicesSessionData.hmac.size = 0;

    // init nvAuth
    nvAuth.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&otherIndicesSessionData.sessionAttributes ) ) = 0;

    publicInfo.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.nvPublic.nvIndex = INDEX_LCP_SUP;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    // Following commented out for convenience during development.
    // publicInfo.nvPublic.attributes.TPMA_NV_POLICY_DELETE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_WRITEDEFINE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_ORDERLY = 1;

    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = NV_PS_INDEX_SIZE;

    otherIndicesSessionsData.cmdAuthsCount = 1;
    otherIndicesSessionsData.cmdAuths[0] = &otherIndicesSessionData;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &otherIndicesSessionsData,
            &nvAuth, &publicInfo, &otherIndicesSessionsDataOut );
    CheckPassed( rval );

    publicInfo.nvPublic.nvIndex = INDEX_LCP_OWN;
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &otherIndicesSessionsData,
            &nvAuth, &publicInfo, &otherIndicesSessionsDataOut );
    CheckPassed( rval );

    // Now teardown session
    rval = Tss2_Sys_FlushContext( sysContext, otherIndicesPolicyAuthHandle );
    CheckPassed( rval );
}


TSS2_RC InitNvAuxPolicySession( TPMI_SH_AUTH_SESSION *nvAuxPolicySessionHandle )
{
    TPMA_LOCALITY locality;
    TSS2_RC rval;

    rval = StartPolicySession( nvAuxPolicySessionHandle );
    CheckPassed( rval );

    // 2.  PolicyLocality(3)
    *(UINT8 *)((void *)&locality) = 0;
    locality.TPM2_LOC_THREE = 1;
    locality.TPM2_LOC_FOUR = 1;
    rval = Tss2_Sys_PolicyLocality( sysContext, *nvAuxPolicySessionHandle, 0, locality, 0 );

    return( rval );
}

void ProvisionNvAux()
{
    UINT32 rval;
    TPMI_SH_AUTH_SESSION nvAuxPolicyAuthHandle;
    TPM2B_DIGEST  nvPolicyHash;
    TPM2B_AUTH  nvAuth;
    TPMS_AUTH_COMMAND nvAuxSessionData;
    TPMS_AUTH_RESPONSE nvAuxSessionDataOut;
    TSS2_SYS_CMD_AUTHS nvAuxSessionsData;
    TSS2_SYS_RSP_AUTHS nvAuxSessionsDataOut;
    TPM2B_NV_PUBLIC publicInfo;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &nvAuxSessionData;
    sessionDataOutArray[0] = &nvAuxSessionDataOut;

    nvAuxSessionsDataOut.rspAuths = &sessionDataOutArray[0];
    nvAuxSessionsData.cmdAuths = &sessionDataArray[0];

    nvAuxSessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nPROVISION NV AUX:\n" );

    //
    // AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer
    // Do this by setting up two policies and ORing them together when creating AuxIndex:
    // 1.  PolicyLocality(3) && PolicyCommand(NVWrite)
    // 2.  EmptyAuth policy && PolicyCommand(NVRead)
    // Page 126 of Part 1 describes how to do this.
    //

    // Steps:
    rval = InitNvAuxPolicySession( &nvAuxPolicyAuthHandle );
    CheckPassed( rval );

    // 3.  GetPolicyDigest and save it
    INIT_SIMPLE_TPM2B_SIZE( nvPolicyHash );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, nvAuxPolicyAuthHandle, 0, &nvPolicyHash, 0 );
    CheckPassed( rval );

    // Now save the policy digest.
    DEBUG_PRINT_BUFFER( NO_PREFIX, &( nvPolicyHash.buffer[0] ), nvPolicyHash.size );

    // 4.  CreateNvIndex
    nvAuxSessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    nvAuxSessionData.nonce.size = 0;

    // init hmac
    nvAuxSessionData.hmac.size = 0;

    // init nvAuth
    nvAuth.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&nvAuxSessionData.sessionAttributes ) ) = 0;

    nvAuxSessionsData.cmdAuthsCount = 1;
    nvAuxSessionsData.cmdAuths[0] = &nvAuxSessionData;

    publicInfo.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.nvPublic.nvIndex = INDEX_AUX;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_POLICYWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    // Following commented out for convenience during development.
    // publicInfo.nvPublic.attributes.TPMA_NV_POLICY_DELETE = 1;

    publicInfo.nvPublic.authPolicy.size = GetDigestSize( TPM2_ALG_SHA1 );
    memcpy( (UINT8 *)&( publicInfo.nvPublic.authPolicy.buffer ), (UINT8 *)&(nvPolicyHash.buffer[0]),
            nvPolicyHash.size );

    publicInfo.nvPublic.dataSize = NV_AUX_INDEX_SIZE;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &nvAuxSessionsData,
            &nvAuth, &publicInfo, &nvAuxSessionsDataOut );
    CheckPassed( rval );

    // Now teardown session
    rval = Tss2_Sys_FlushContext( sysContext, nvAuxPolicyAuthHandle );
    CheckPassed( rval );
}

void TpmAuxWrite( int locality)
{
    TSS2_RC rval;
    int i;
    TPMI_SH_AUTH_SESSION nvAuxPolicyAuthHandle;
    TPM2B_MAX_NV_BUFFER nvWriteData;

    rval = InitNvAuxPolicySession( &nvAuxPolicyAuthHandle );
    CheckPassed( rval );

    // Now we're going to test it.
    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

    nullSessionData.sessionHandle = nvAuxPolicyAuthHandle;

    // Make sure that session terminates after NVWrite completes.
    nullSessionData.sessionAttributes.continueSession = 0;

    rval = SetLocality( sysContext, locality );
    CheckPassed( rval );

    nullSessionsData.cmdAuthsCount = 1;
    nullSessionsData.cmdAuths[0] = &nullSessionData;

    rval = Tss2_Sys_NV_Write( sysContext, INDEX_AUX, INDEX_AUX, &nullSessionsData, &nvWriteData, 0, &nullSessionsDataOut );

    {
        TSS2_RC setLocalityRval;
        setLocalityRval = SetLocality( sysContext, 3 );
        CheckPassed( setLocalityRval );
    }

    if( locality == 3 || locality == 4 )
    {
        CheckPassed( rval );

        // No teardown of session needed, since the authorization was
        // successful.
    }
    else
    {
        CheckFailed( rval, TPM2_RC_LOCALITY );

        // Now teardown session
        rval = Tss2_Sys_FlushContext( sysContext, nvAuxPolicyAuthHandle );
        CheckPassed( rval );
    }
}

void TpmAuxReadWriteTest()
{
    UINT32 rval;
    int testLocality;
    TPM2B_MAX_NV_BUFFER nvData;

    DebugPrintf( NO_PREFIX, "TPM AUX READ/WRITE TEST\n" );

    nullSessionData.sessionAttributes.continueSession = 0;

    // Try writing it from all localities.  Only locality 3 should work.
    for( testLocality = 0; testLocality < 5; testLocality++ )
    {
        TpmAuxWrite( testLocality );
    }

    nullSessionData.sessionHandle = TPM2_RS_PW;

    nullSessionsData.cmdAuths[0] = &nullSessionData;

    // Try reading it from all localities.  They all should work.
    for( testLocality = 0; testLocality < 5; testLocality++ )
    {
        rval = SetLocality( sysContext, testLocality );
        CheckPassed( rval );

        INIT_SIMPLE_TPM2B_SIZE( nvData );
        rval = TSS2_RETRY_EXP( Tss2_Sys_NV_Read( sysContext, INDEX_AUX, INDEX_AUX, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut ));
        CheckPassed( rval );

        rval = SetLocality( sysContext, 3 );
        CheckPassed( rval );
    }
}

void TpmOtherIndicesReadWriteTest()
{
    UINT32 rval;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    int i;
    TPM2B_MAX_NV_BUFFER nvData;

    nullSessionData.sessionHandle = TPM2_RS_PW;

    DebugPrintf( NO_PREFIX, "TPM OTHER READ/WRITE TEST\n" );

    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

    nullSessionsData.cmdAuthsCount = 1;
    nullSessionsData.cmdAuths[0] = &nullSessionData;

    rval = Tss2_Sys_NV_Write( sysContext, INDEX_LCP_SUP, INDEX_LCP_SUP, &nullSessionsData, &nvWriteData, 0, &nullSessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Write( sysContext, INDEX_LCP_OWN, INDEX_LCP_OWN, &nullSessionsData, &nvWriteData, 0, &nullSessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, INDEX_LCP_SUP, INDEX_LCP_SUP, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, INDEX_LCP_OWN, INDEX_LCP_OWN, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut );
    CheckPassed( rval );
}

void NvIndexProto()
{
    UINT32 rval;

    DebugPrintf( NO_PREFIX, "\nNV INDEX PROTOTYPE TESTS:\n" );


    // AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer
    // PS index: Write and read are unrestricted until TPM2_WriteLock. After that content is write protected
    // PO index: Write is restricted by ownerAuth; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer

    // Now we need to configure NV indices
    ProvisionNvAux();

    ProvisionOtherIndices();

    TpmAuxReadWriteTest();

    TpmOtherIndicesReadWriteTest();

    // Now undefine the aux index, so that subsequent test passes will work.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, INDEX_AUX, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );

    // Now undefine the other indices, so that subsequent test passes will work.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, INDEX_LCP_SUP, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, INDEX_LCP_OWN, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );
}

void TestPcrAllocate()
{
    UINT32 rval;
    TPML_PCR_SELECTION  pcrSelection;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMI_YES_NO allocationSuccess;
    UINT32 maxPcr;
    UINT32 sizeNeeded;
    UINT32 sizeAvailable;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    DebugPrintf( NO_PREFIX, "\nPCR ALLOCATE TEST  :\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    pcrSelection.count = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_PCR_Allocate( sysContext, TPM2_RH_PLATFORM, &sessionsData, &pcrSelection,
            &allocationSuccess, &maxPcr, &sizeNeeded, &sizeAvailable, &sessionsDataOut);
    CheckPassed( rval );

    pcrSelection.count = 3;
    pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[0] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[0], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_5 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_7 );
    pcrSelection.pcrSelections[1].hash = TPM2_ALG_SHA384;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[1] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[1], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[1], PCR_5 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[1], PCR_8 );
    pcrSelection.pcrSelections[2].hash = TPM2_ALG_SHA256;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[2] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[2], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[2], PCR_6 );

    rval = Tss2_Sys_PCR_Allocate( sysContext, TPM2_RH_PLATFORM, &sessionsData, &pcrSelection,
            &allocationSuccess, &maxPcr, &sizeNeeded, &sizeAvailable, &sessionsDataOut);
    CheckPassed( rval );
}

void TestUnseal()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_DATA              outsideInfo;
    TPM2B_PUBLIC            inPublic;
    TPM2_HANDLE loadedObjectHandle;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
    TPM2B_SENSITIVE_DATA outData;


    const char authStr[] = "test";
    const char sensitiveData[] = "this is sensitive";

    DebugPrintf( NO_PREFIX, "\nUNSEAL TEST  :\n" );

    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    sessionData.hmac.size = 2;
    sessionData.hmac.buffer[0] = 0x00;
    sessionData.hmac.buffer[1] = 0xff;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    inSensitive.sensitive.userAuth.size = sizeof( authStr ) - 1;
    memcpy( &( inSensitive.sensitive.userAuth.buffer[0] ), authStr, sizeof( authStr ) - 1 );
    inSensitive.sensitive.data.size = sizeof( sensitiveData ) - 1;
    memcpy( &( inSensitive.sensitive.data.buffer[0] ), sensitiveData, sizeof( sensitiveData ) - 1 );

    inPublic.publicArea.authPolicy.size = 0;

    inPublic.publicArea.unique.keyedHash.size = 0;

    outsideInfo.size = 0;
    creationPCR.count = 0;

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;

    *(UINT32 *)&( inPublic.publicArea.objectAttributes) = 0;
    inPublic.publicArea.objectAttributes.userWithAuth = 1;

    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    inPublic.publicArea.unique.keyedHash.size = 0;

    outsideInfo.size = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0]  = &sessionData;

    outPublic.size = 0;
    creationData.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_LoadExternal ( sysContext, 0, 0, &outPublic,
            TPM2_RH_PLATFORM, &loadedObjectHandle, &name, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedObjectHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    sessionData.hmac.size = sizeof( authStr ) - 1;
    memcpy( &( sessionData.hmac.buffer[0] ), authStr, sizeof( authStr ) - 1 );

    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, loadedObjectHandle, &sessionsData, &outData, &sessionsDataOut );

    rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );

    CheckPassed( rval );
}


void CreatePasswordTestNV( TPMI_RH_NV_INDEX nvIndex, char * password )
{
    UINT32 rval;
    int i;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionData.sessionHandle = TPM2_RS_PW;

    // Init nonce.
    sessionData.nonce.size = 0;

    // init hmac
    sessionData.hmac.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsDataOut.rspAuthsCount = 1;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    nvAuth.size = strlen( password );
    for( i = 0; i < nvAuth.size; i++ ) {
        nvAuth.buffer[i] = password[i];
    }

    publicInfo.size = sizeof( TPMI_RH_NV_INDEX ) +
        sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
        sizeof( UINT16 );
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = 32;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM,
            &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );
}

// Password used to authorize access to the NV index.
char password[] = "test password";

void PasswordTest()
{
    UINT32 rval;
    int i;

    // Authorization structure for command.
    TPMS_AUTH_COMMAND sessionData;

    // Authorization structure for response.
    TPMS_AUTH_RESPONSE sessionDataOut;

    // Create and init authorization area for command:
    // only 1 authorization area.
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };

    // Create authorization area for response:
    // only 1 authorization area.
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };

    // Authorization array for command (only has one auth structure).
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };

    // Authorization array for response (only has one auth structure).
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };
    TPM2B_MAX_NV_BUFFER nvWriteData;

    DebugPrintf( NO_PREFIX, "\nPASSWORD TESTS:\n" );

    // Create an NV index that will use password
    // authorizations the password will be
    // "test password".
    CreatePasswordTestNV( TPM20_INDEX_PASSWORD_TEST, password );

    //
    // Initialize the command authorization area.
    //

    // Init sessionHandle, nonce, session
    // attributes, and hmac (password).
    sessionData.sessionHandle = TPM2_RS_PW;
    // Set zero sized nonce.
    sessionData.nonce.size = 0;
    // sessionAttributes is a bit field.  To initialize
    // it to 0, cast to a pointer to UINT8 and
    // write 0 to that pointer.
    *( (UINT8 *)&sessionData.sessionAttributes ) = 0;

    // Init password (HMAC field in authorization structure).
    sessionData.hmac.size = strlen( password );
    memcpy( &( sessionData.hmac.buffer[0] ),
            &( password[0] ), sessionData.hmac.size );

    // Initialize write data.
    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

    // Attempt write with the correct password.
    // It should pass.
    rval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0,
            &sessionsDataOut );
    // Check that the function passed as
    // expected.  Otherwise, exit.
    CheckPassed( rval );

    // Alter the password so it's incorrect.
    sessionData.hmac.buffer[4] = 0xff;
    rval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0,
            &sessionsDataOut );
    // Check that the function failed as expected,
    // since password was incorrect.  If wrong
    // response code received, exit.
    CheckFailed( rval,
            TPM2_RC_S + TPM2_RC_1 + TPM2_RC_AUTH_FAIL );

    // Change hmac to null one, since null auth is
    // used to undefine the index.
    sessionData.hmac.size = 0;

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );
}


void SimplePolicyTest()
{
    UINT32 rval, sessionCmdRval;
    TPM2B_AUTH  nvAuth;
    SESSION *nvSession = NULL, *trialPolicySession = NULL;
    TPMA_NV nvAttributes;
    TPM2B_DIGEST authPolicy;
    TPM2B_NAME nvName;
    TPM2B_MAX_NV_BUFFER nvWriteData, nvReadData;
    UINT8 dataToWrite[] = { 0x00, 0xff, 0x55, 0xaa };
    int i;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPMT_SYM_DEF symmetric;
    TPMA_SESSION sessionAttributes;

    // Command authorization area: one password session.
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM2_RS_PW, };
    TPMS_AUTH_COMMAND *nvCmdAuthArray[1] = { &nvCmdAuth };
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 1, &nvCmdAuthArray[0] };

    // Response authorization area.
    TPMS_AUTH_RESPONSE nvRspAuth;
    TPMS_AUTH_RESPONSE *nvRspAuthArray[1] = { &nvRspAuth };
    TSS2_SYS_RSP_AUTHS nvRspAuths = { 1, &nvRspAuthArray[0] };
    TPM2_ALG_ID sessionAlg = TPM2_ALG_SHA256;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    DebugPrintf( NO_PREFIX, "\nSIMPLE POLICY TEST:\n" );

    //
    // Create NV index.
    //

    // Setup the NV index's authorization value.
    nvAuth.size = 0;

    // Zero sized encrypted salt, since the session
    // is unsalted.
    encryptedSalt.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM2_ALG_NULL;

    //
    // Create the NV index's authorization policy
    // using a trial policy session.
    //
    rval = StartAuthSessionWithParams( &trialPolicySession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM2_SE_TRIAL,
            &symmetric, sessionAlg, resMgrTctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_PolicyAuthValue( sysContext, trialPolicySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    // Get policy digest.
    INIT_SIMPLE_TPM2B_SIZE( authPolicy );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, trialPolicySession->sessionHandle,
            0, &authPolicy, 0 );
    CheckPassed( rval );

    // End the trial session by flushing it.
    rval = Tss2_Sys_FlushContext( sysContext, trialPolicySession->sessionHandle );
    CheckPassed( rval );

    // And remove the trial policy session from sessions table.
    rval = EndAuthSession( trialPolicySession );
    CheckPassed( rval );

    // Now set the NV index's attributes:
    // policyRead, authWrite, and platormCreate.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_POLICYREAD = 1;
    nvAttributes.TPMA_NV_POLICYWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // Create the NV index.
    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            sessionAlg, nvAttributes, 32  );
    CheckPassed( rval );

    // Add index and associated authorization value to
    // entity table.  This helps when we need
    // to calculate HMACs.
    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    // Get the name of the NV index.
    rval = TpmHandleToName(TPM20_INDEX_PASSWORD_TEST, &nvName);
    CheckPassed( rval );

    //
    // Start real (non-trial) policy authorization session:
    // it's an unbound and unsalted session, no symmetric
    // encryption algorithm, and SHA256 is the session's
    // hash algorithm.
    //

    // Zero sized encrypted salt, since the session
    // is unsalted.
    encryptedSalt.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM2_ALG_NULL;

    // Create the session.
    // Session state (session handle, nonces, etc.) gets
    // saved into nvSession structure for later use.
    rval = StartAuthSessionWithParams( &nvSession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY,
            &symmetric, sessionAlg, resMgrTctiContext );
    CheckPassed( rval );

    // Get the name of the session and save it in
    // the nvSession structure.
    rval = TpmHandleToName( nvSession->sessionHandle,
            &nvSession->name );
    CheckPassed( rval );

    // Initialize NV write data.
    nvWriteData.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.size; i++ )
    {
        nvWriteData.buffer[i] = dataToWrite[i];
    }

    //
    // Now setup for writing the NV index.
    //

    rval = Tss2_Sys_PolicyAuthValue( sysContext, nvSession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    // Get policy digest.
    INIT_SIMPLE_TPM2B_SIZE( authPolicy );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, trialPolicySession->sessionHandle,
            0, &authPolicy, 0 );
    CheckPassed( rval );

    // First call prepare in order to create cpBuffer.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval );

    // Configure command authorization area, except for HMAC.
    nvCmdAuths.cmdAuths[0]->sessionHandle = nvSession->sessionHandle;
    nvCmdAuths.cmdAuths[0]->nonce.size = 1;
    nvCmdAuths.cmdAuths[0]->nonce.buffer[0] = 0xa5;
    *( (UINT8 *)((void *)&sessionAttributes ) ) = 0;
    nvCmdAuths.cmdAuths[0]->sessionAttributes = sessionAttributes;
    nvCmdAuths.cmdAuths[0]->sessionAttributes.continueSession = 1;

    // Roll nonces for command
    RollNonces( nvSession, &nvCmdAuths.cmdAuths[0]->nonce );

    // Complete command authorization area, by computing
    // HMAC and setting it in nvCmdAuths.
    rval = ComputeCommandHmacs( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvCmdAuths,
            TPM2_RC_FAILURE );
    CheckPassed( rval );

    // Finally!!  Write the data to the NV index.
    // If the command is successful, the command
    // HMAC was correct.
    sessionCmdRval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, &nvWriteData, 0, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    // Roll nonces for response
    RollNonces( nvSession, &nvRspAuths.rspAuths[0]->nonce );

    if( sessionCmdRval == TPM2_RC_SUCCESS )
    {
        // If the command was successful, check the
        // response HMAC to make sure that the
        // response was received correctly.
        rval = CheckResponseHMACs( sysContext, sessionCmdRval,
                &nvCmdAuths, TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST, &nvRspAuths );
        CheckPassed( rval );
    }

    rval = Tss2_Sys_PolicyAuthValue( sysContext, nvSession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    // First call prepare in order to create cpBuffer.
    rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, sizeof( dataToWrite ), 0 );
    CheckPassed( rval );

    // Roll nonces for command
    RollNonces( nvSession, &nvCmdAuths.cmdAuths[0]->nonce );

    // End the session after next command.
    nvCmdAuths.cmdAuths[0]->sessionAttributes.continueSession = 0;

    // Complete command authorization area, by computing
    // HMAC and setting it in nvCmdAuths.
    rval = ComputeCommandHmacs( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvCmdAuths,
            TPM2_RC_FAILURE );
    CheckPassed( rval );

    // And now read the data back.
    // If the command is successful, the command
    // HMAC was correct.
    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    sessionCmdRval = Tss2_Sys_NV_Read( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, sizeof( dataToWrite ), 0,
            &nvReadData, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    // Roll nonces for response
    RollNonces( nvSession, &nvRspAuths.rspAuths[0]->nonce );

    if( sessionCmdRval == TPM2_RC_SUCCESS )
    {
        // If the command was successful, check the
        // response HMAC to make sure that the
        // response was received correctly.
        rval = CheckResponseHMACs( sysContext, sessionCmdRval,
                &nvCmdAuths, TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST, &nvRspAuths );
        CheckPassed( rval );
    }

    // Check that write and read data are equal.
    if( memcmp( (void *)&nvReadData.buffer[0],
            (void *)&nvWriteData.buffer[0], nvReadData.size ) )
    {
        DebugPrintf( NO_PREFIX, "ERROR!! read data not equal to written data\n" );
        Cleanup();
    }

    //
    // Now cleanup:  undefine the NV index and delete
    // the NV index's entity table entry.
    //

    // Setup authorization for undefining the NV index.
    nvCmdAuths.cmdAuths[0]->sessionHandle = TPM2_RS_PW;
    nvCmdAuths.cmdAuths[0]->nonce.size = 0;
    nvCmdAuths.cmdAuths[0]->hmac.size = 0;

    // Undefine the NV index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext,
            TPM2_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, 0 );
    CheckPassed( rval );

    // Delete the NV index's entry in the entity table.
    rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
    CheckPassed( rval );
}

void SimpleHmacTest()
{
    UINT32 rval, sessionCmdRval;
    TPM2B_AUTH  nvAuth;
    SESSION *nvSession = NULL;
    TPMA_NV nvAttributes;
    TPM2B_DIGEST authPolicy;
    TPM2B_NAME nvName;
    TPM2B_MAX_NV_BUFFER nvWriteData, nvReadData;
    UINT8 dataToWrite[] = { 0x00, 0xff, 0x55, 0xaa };
    char sharedSecret[] = "shared secret";
    int i;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPMT_SYM_DEF symmetric;
    TPMA_SESSION sessionAttributes;

    // Command authorization area: one password session.
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM2_RS_PW, };
    TPMS_AUTH_COMMAND *nvCmdAuthArray[1] = { &nvCmdAuth };
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 1, &nvCmdAuthArray[0] };

    // Response authorization area.
    TPMS_AUTH_RESPONSE nvRspAuth;
    TPMS_AUTH_RESPONSE *nvRspAuthArray[1] = { &nvRspAuth };
    TSS2_SYS_RSP_AUTHS nvRspAuths = { 1, &nvRspAuthArray[0] };
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    DebugPrintf( NO_PREFIX, "\nSIMPLE HMAC SESSION TEST:\n" );

    //
    // Create NV index.
    //

    // Setup the NV index's authorization value.
    nvAuth.size = strlen( sharedSecret );
    for( i = 0; i < nvAuth.size; i++ )
        nvAuth.buffer[i] = sharedSecret[i];

    // Set NV index's authorization policy
    // to zero sized policy since we won't be
    // using policy to authorize.
    authPolicy.size = 0;

    // Now set the NV index's attributes:
    // policyRead, authWrite, and platormCreate.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_AUTHREAD = 1;
    nvAttributes.TPMA_NV_AUTHWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // Create the NV index.
    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            TPM2_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    // Add index and associated authorization value to
    // entity table.  This helps when we need
    // to calculate HMACs.
    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    // Get the name of the NV index.
    rval = TpmHandleToName( TPM20_INDEX_PASSWORD_TEST,
            &nvName );
    CheckPassed( rval );

    //
    // Start HMAC authorization session:  it's an
    // unbound and unsalted session, no symmetric
    // encryption algorithm, and SHA256 is the session's
    // hash algorithm.
    //

    // Zero sized encrypted salt, since the session
    // is unsalted.
    encryptedSalt.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM2_ALG_NULL;

    // Create the session.
    // Session state (session handle, nonces, etc.) gets
    // saved into nvSession structure for later use.
    rval = StartAuthSessionWithParams( &nvSession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM2_SE_HMAC,
            &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    // Get the name of the session and save it in
    // the nvSession structure.
    rval = TpmHandleToName( nvSession->sessionHandle,
            &nvSession->name );
    CheckPassed( rval );

    // Initialize NV write data.
    nvWriteData.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.size; i++ )
    {
        nvWriteData.buffer[i] = dataToWrite[i];
    }

    //
    // Now setup for writing the NV index.
    //

    // First call prepare in order to create cpBuffer.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval );

    // Configure command authorization area, except for HMAC.
    nvCmdAuths.cmdAuths[0]->sessionHandle = nvSession->sessionHandle;
    nvCmdAuths.cmdAuths[0]->nonce.size = 1;
    nvCmdAuths.cmdAuths[0]->nonce.buffer[0] = 0xa5;
    *( (UINT8 *)(&sessionAttributes ) ) = 0;
    nvCmdAuths.cmdAuths[0]->sessionAttributes = sessionAttributes;
    nvCmdAuths.cmdAuths[0]->sessionAttributes.continueSession = 1;

    // Roll nonces for command
    RollNonces( nvSession, &nvCmdAuths.cmdAuths[0]->nonce );

    // Complete command authorization area, by computing
    // HMAC and setting it in nvCmdAuths.
    rval = ComputeCommandHmacs( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvCmdAuths,
            TPM2_RC_FAILURE );
    CheckPassed( rval );

    // Finally!!  Write the data to the NV index.
    // If the command is successful, the command
    // HMAC was correct.
    sessionCmdRval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, &nvWriteData, 0, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    // Roll nonces for response
    RollNonces( nvSession, &nvRspAuths.rspAuths[0]->nonce );

    if( sessionCmdRval == TPM2_RC_SUCCESS )
    {
        // If the command was successful, check the
        // response HMAC to make sure that the
        // response was received correctly.
        rval = CheckResponseHMACs( sysContext, sessionCmdRval,
                &nvCmdAuths, TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST, &nvRspAuths );
        CheckPassed( rval );
    }

    // First call prepare in order to create cpBuffer.
    rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, sizeof( dataToWrite ), 0 );
    CheckPassed( rval );

    // Roll nonces for command
    RollNonces( nvSession, &nvCmdAuths.cmdAuths[0]->nonce );

    // End the session after next command.
    nvCmdAuths.cmdAuths[0]->sessionAttributes.continueSession = 0;

    // Complete command authorization area, by computing
    // HMAC and setting it in nvCmdAuths.
    rval = ComputeCommandHmacs( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvCmdAuths,
            TPM2_RC_FAILURE );
    CheckPassed( rval );

    // And now read the data back.
    // If the command is successful, the command
    // HMAC was correct.
    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    sessionCmdRval = Tss2_Sys_NV_Read( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, sizeof( dataToWrite ), 0,
            &nvReadData, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    // Roll nonces for response
    RollNonces( nvSession, &nvRspAuths.rspAuths[0]->nonce );

    if( sessionCmdRval == TPM2_RC_SUCCESS )
    {
        // If the command was successful, check the
        // response HMAC to make sure that the
        // response was received correctly.
        rval = CheckResponseHMACs( sysContext, sessionCmdRval,
                &nvCmdAuths, TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST, &nvRspAuths );
        CheckPassed( rval );
    }

    // Check that write and read data are equal.
    if( memcmp( (void *)&nvReadData.buffer[0],
            (void *)&nvWriteData.buffer[0], nvReadData.size ) )
    {
        DebugPrintf( NO_PREFIX, "ERROR!! read data not equal to written data\n" );
        Cleanup();
    }

    //
    // Now cleanup:  undefine the NV index and delete
    // the NV index's entity table entry.
    //

    // Setup authorization for undefining the NV index.
    nvCmdAuths.cmdAuths[0]->sessionHandle = TPM2_RS_PW;
    nvCmdAuths.cmdAuths[0]->nonce.size = 0;
    nvCmdAuths.cmdAuths[0]->hmac.size = 0;

    // Undefine the NV index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext,
            TPM2_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, 0 );
    CheckPassed( rval );

    // Delete the NV index's entry in the entity table.
    rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
    CheckPassed( rval );

    rval = EndAuthSession( nvSession );

    CheckPassed( rval );

    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
}


void SimpleHmacOrPolicyTest( bool hmacTest )
{
    UINT32 rval, sessionCmdRval;
    TPM2B_AUTH  nvAuth;
    SESSION *nvSession, *trialPolicySession;
    TPMA_NV nvAttributes;
    TPM2B_DIGEST authPolicy;
    TPM2B_NAME nvName;
    TPM2B_MAX_NV_BUFFER nvWriteData, nvReadData;
    UINT8 dataToWrite[] = { 0x00, 0xff, 0x55, 0xaa };
    char sharedSecret[] = "shared secret";
    int i;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPMT_SYM_DEF symmetric;
    TPMA_SESSION sessionAttributes;
    TPM2_SE tpmSe;
    char *testString;
    char testStringHmac[] = "HMAC";
    char testStringPolicy[] = "POLICY";

    // Command authorization area: one password session.
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM2_RS_PW, };
    TPMS_AUTH_COMMAND *nvCmdAuthArray[1] = {&nvCmdAuth};
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 1, &nvCmdAuthArray[0] };

    // Response authorization area.
    TPMS_AUTH_RESPONSE nvRspAuth;
    TPMS_AUTH_RESPONSE *nvRspAuthArray[1] = { &nvRspAuth };
    TSS2_SYS_RSP_AUTHS nvRspAuths = { 1, &nvRspAuthArray[0] };

    TSS2_SYS_CONTEXT *simpleTestContext;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    if( hmacTest )
        testString = testStringHmac;
    else
        testString = testStringPolicy;

    DebugPrintf( NO_PREFIX, "\nSIMPLE %s SESSION TEST:\n", testString );

    // Create sysContext structure.
    simpleTestContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( simpleTestContext == 0 )
    {
        InitSysContextFailure();
    }

    // Setup the NV index's authorization value.
    nvAuth.size = strlen( sharedSecret );
    for( i = 0; i < nvAuth.size; i++ )
        nvAuth.buffer[i] = sharedSecret[i];

    //
    // Create NV index.
    //
    if( hmacTest )
    {
        // Setup the NV index's authorization value.
        nvAuth.size = strlen( sharedSecret );
        for( i = 0; i < nvAuth.size; i++ )
            nvAuth.buffer[i] = sharedSecret[i];

        // Set NV index's authorization policy
        // to zero sized policy since we won't be
        // using policy to authorize.

        authPolicy.size = 0;
    }
    else
    {
        // Zero sized encrypted salt, since the session
        // is unsalted.

        encryptedSalt.size = 0;

        // No symmetric algorithm.
        symmetric.algorithm = TPM2_ALG_NULL;

        //
        // Create the NV index's authorization policy
        // using a trial policy session.
        //
        rval = StartAuthSessionWithParams( &trialPolicySession,
                TPM2_RH_NULL, 0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt,
                TPM2_SE_TRIAL,
                &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                trialPolicySession->sessionHandle, 0, 0 );
        CheckPassed( rval );

        // Get policy digest.
        INIT_SIMPLE_TPM2B_SIZE( authPolicy );
        rval = Tss2_Sys_PolicyGetDigest( simpleTestContext,
                trialPolicySession->sessionHandle,
                0, &authPolicy, 0 );
        CheckPassed( rval );

        // End the trial session by flushing it.
        rval = Tss2_Sys_FlushContext( simpleTestContext,
                trialPolicySession->sessionHandle );
        CheckPassed( rval );

        // And remove the trial policy session from
        // sessions table.
        rval = EndAuthSession( trialPolicySession );
        CheckPassed( rval );
    }

    // Now set the NV index's attributes:
    // policyRead, authWrite, and platormCreate.
    *(UINT32 *)( &nvAttributes ) = 0;
    if( hmacTest )
    {
        nvAttributes.TPMA_NV_AUTHREAD = 1;
        nvAttributes.TPMA_NV_AUTHWRITE = 1;
    }
    else
    {
        nvAttributes.TPMA_NV_POLICYREAD = 1;
        nvAttributes.TPMA_NV_POLICYWRITE = 1;
    }
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // Create the NV index.
    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            TPM2_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    // Add index and associated authorization value to
    // entity table.  This helps when we need
    // to calculate HMACs.
    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    // Get the name of the NV index.
    rval = TpmHandleToName(
            TPM20_INDEX_PASSWORD_TEST,
            &nvName );
    CheckPassed( rval );


    //
    // Start HMAC or real (non-trial) policy authorization session:
    // it's an unbound and unsalted session, no symmetric
    // encryption algorithm, and SHA256 is the session's
    // hash algorithm.
    //

    // Zero sized encrypted salt, since the session
    // is unsalted.
    encryptedSalt.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM2_ALG_NULL;

    // Create the session, hmac or policy depending
    // on hmacTest.
    // Session state (session handle, nonces, etc.) gets
    // saved into nvSession structure for later use.
    if( hmacTest )
        tpmSe = TPM2_SE_HMAC;
    else
        tpmSe = TPM2_SE_POLICY;

    rval = StartAuthSessionWithParams( &nvSession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, tpmSe,
            &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    // Get the name of the session and save it in
    // the nvSession structure.
    rval = TpmHandleToName( nvSession->sessionHandle,
            &(nvSession->name) );
    CheckPassed( rval );

    // Initialize NV write data.
    nvWriteData.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.size; i++ )
    {
        nvWriteData.buffer[i] = dataToWrite[i];
    }

    //
    // Now setup for writing the NV index.
    //
    if( !hmacTest )
    {
        // Send policy command.
        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                nvSession->sessionHandle, 0, 0 );
        CheckPassed( rval );
    }

    // First call prepare in order to create cpBuffer.
    rval = Tss2_Sys_NV_Write_Prepare( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval );

    // Configure command authorization area, except for HMAC.
    nvCmdAuths.cmdAuths[0]->sessionHandle =
            nvSession->sessionHandle;
    nvCmdAuths.cmdAuths[0]->nonce.size = 1;
    nvCmdAuths.cmdAuths[0]->nonce.buffer[0] = 0xa5;
    *( (UINT8 *)(&sessionAttributes ) ) = 0;
    nvCmdAuths.cmdAuths[0]->sessionAttributes = sessionAttributes;
    nvCmdAuths.cmdAuths[0]->sessionAttributes.continueSession = 1;

    // Roll nonces for command
    RollNonces( nvSession, &nvCmdAuths.cmdAuths[0]->nonce );

    // Complete command authorization area, by computing
    // HMAC and setting it in nvCmdAuths.
    rval = ComputeCommandHmacs( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvCmdAuths,
            TPM2_RC_FAILURE );
    CheckPassed( rval );
    // Finally!!  Write the data to the NV index.
    // If the command is successful, the command
    // HMAC was correct.
    sessionCmdRval = Tss2_Sys_NV_Write( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, &nvWriteData, 0, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    // Roll nonces for response
    RollNonces( nvSession, &nvRspAuths.rspAuths[0]->nonce );

    if( sessionCmdRval == TPM2_RC_SUCCESS )
    {
        // If the command was successful, check the
        // response HMAC to make sure that the
        // response was received correctly.
        rval = CheckResponseHMACs( simpleTestContext, sessionCmdRval,
                &nvCmdAuths, TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST, &nvRspAuths );
        CheckPassed( rval );
    }

    if( !hmacTest )
    {
        // Send policy command.
        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                nvSession->sessionHandle, 0, 0 );
        CheckPassed( rval );
    }
    // First call prepare in order to create cpBuffer.
    rval = Tss2_Sys_NV_Read_Prepare( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            sizeof( dataToWrite ), 0 );
    CheckPassed( rval );

    // Roll nonces for command
    RollNonces( nvSession, &nvCmdAuths.cmdAuths[0]->nonce );

    // End the session after next command.
    nvCmdAuths.cmdAuths[0]->sessionAttributes.continueSession = 0;

    // Complete command authorization area, by computing
    // HMAC and setting it in nvCmdAuths.
    rval = ComputeCommandHmacs( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvCmdAuths,
            TPM2_RC_FAILURE );
    CheckPassed( rval );

    // And now read the data back.
    // If the command is successful, the command
    // HMAC was correct.
    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    sessionCmdRval = Tss2_Sys_NV_Read( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, sizeof( dataToWrite ), 0,
            &nvReadData, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    // Roll nonces for response
    RollNonces( nvSession, &nvRspAuths.rspAuths[0]->nonce );

    if( sessionCmdRval == TPM2_RC_SUCCESS )
    {
        // If the command was successful, check the
        // response HMAC to make sure that the
        // response was received correctly.
        rval = CheckResponseHMACs( simpleTestContext, sessionCmdRval,
                &nvCmdAuths, TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST, &nvRspAuths );
        CheckPassed( rval );
    }

    // Check that write and read data are equal.
    if( memcmp( (void *)&nvReadData.buffer[0],
            (void *)&nvWriteData.buffer[0], nvReadData.size ) )
    {
        DebugPrintf( NO_PREFIX, "ERROR!! read data not equal to written data\n" );
        Cleanup();
    }

    //
    // Now cleanup:  undefine the NV index and delete
    // the NV index's entity table entry.
    //

    // Setup authorization for undefining the NV index.
    nvCmdAuths.cmdAuths[0]->sessionHandle = TPM2_RS_PW;
    nvCmdAuths.cmdAuths[0]->nonce.size = 0;
    nvCmdAuths.cmdAuths[0]->hmac.size = 0;

    // Undefine the NV index.
    rval = Tss2_Sys_NV_UndefineSpace( simpleTestContext,
            TPM2_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, 0 );
    CheckPassed( rval );

    // Delete the NV index's entry in the entity table.
    rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
    CheckPassed( rval );

    // Remove the real session from sessions table.
    rval = EndAuthSession( nvSession );

    CheckPassed( rval );

    TeardownSysContext( &simpleTestContext );

}

UINT32 writeDataString = 0xdeadbeef;

void TestEncryptDecryptSession()
{
    TSS2_RC             rval = TSS2_RC_SUCCESS;
    SESSION             *encryptDecryptSession = NULL;
    TPMT_SYM_DEF        symmetric;
    TPM2B_MAX_NV_BUFFER writeData, encryptedWriteData;
    TPM2B_MAX_NV_BUFFER encryptedReadData, decryptedReadData,
                        readData;
    size_t              decryptParamSize;
    uint8_t             *decryptParamBuffer;
    size_t              encryptParamSize;
    uint8_t             *encryptParamBuffer;
    TPM2B_AUTH          nvAuth;
    TPM2B_DIGEST        authPolicy;
    TPMA_NV             nvAttributes;
    int                 i;
    TPMA_SESSION        sessionAttributes;
    TPM2B_NONCE         nonceCaller;

    nonceCaller.size = 0;

    // Authorization structure for undefine command.
    TPMS_AUTH_COMMAND nvUndefineAuth;

    // Create and init authorization area for undefine command:
    // only 1 authorization area.
    TPMS_AUTH_COMMAND *nvUndefineAuthArray[1] = { &nvUndefineAuth };

    // Authorization array for command (only has one auth structure).
    TSS2_SYS_CMD_AUTHS nvUndefineAuths = { 1, &nvUndefineAuthArray[0] };

    DebugPrintf( NO_PREFIX, "\n\nDECRYPT/ENCRYPT SESSION TESTS:\n" );

    writeData.size = sizeof( writeDataString );
    memcpy( (void *)&writeData.buffer, (void *)&writeDataString,
            sizeof( writeDataString ) );


    // Create NV index with empty auth value.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_AUTHREAD = 1;
    nvAttributes.TPMA_NV_AUTHWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // No authorization required.
    authPolicy.size = 0;
    nvAuth.size = 0;
    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_TEST1,
            TPM2_ALG_SHA1, nvAttributes,
            sizeof( writeDataString ) );

    //
    // 1st pass with CFB mode.
    // 2nd pass with XOR mode.
    //
    for( i = 0; i < 2; i++ )
    {
        // Authorization structure for NV
        // read/write commands.
        TPMS_AUTH_COMMAND nvRdWrCmdAuth;

        // Authorization structure for
        // encrypt/decrypt session.
        TPMS_AUTH_COMMAND decryptEncryptSessionCmdAuth;

        // Create and init authorization area for
        // NV read/write commands:
        // 2 authorization areas.
        TPMS_AUTH_COMMAND *nvRdWrCmdAuthArray[2] =
                { &nvRdWrCmdAuth, &decryptEncryptSessionCmdAuth };

        // Authorization array for commands
        // (has two auth structures).
        TSS2_SYS_CMD_AUTHS nvRdWrCmdAuths =
                { 2, &nvRdWrCmdAuthArray[0] };

        // Authorization structure for NV read/write responses.
        TPMS_AUTH_RESPONSE nvRdWrRspAuth;
        // Authorization structure for decrypt/encrypt
        // session responses.
        TPMS_AUTH_RESPONSE decryptEncryptSessionRspAuth;

        // Create and init authorization area for NV
        // read/write responses:  2 authorization areas.
        TPMS_AUTH_RESPONSE *nvRdWrRspAuthArray[2] =
                { &nvRdWrRspAuth, &decryptEncryptSessionRspAuth };
        // Authorization array for responses
        // (has two auth structures).
        TSS2_SYS_RSP_AUTHS nvRdWrRspAuths =
                { 2, &nvRdWrRspAuthArray[0] };

        // Setup session parameters.
        if( i == 0 )
        {
            // AES encryption/decryption and CFB mode.
            symmetric.algorithm = TPM2_ALG_AES;
            symmetric.keyBits.aes = 128;
            symmetric.mode.aes = TPM2_ALG_CFB;
        }
        else
        {
            // XOR encryption/decryption.
            symmetric.algorithm = TPM2_ALG_XOR;
            symmetric.keyBits.exclusiveOr = TPM2_ALG_SHA256;
        }

        // Start policy session for decrypt/encrypt session.
        rval = StartAuthSessionWithParams( &encryptDecryptSession,
                TPM2_RH_NULL, 0, TPM2_RH_NULL, 0, &nonceCaller, 0, TPM2_SE_POLICY,
                &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        //
        // Write TPM index with encrypted parameter used
        // as the data to write.  Set session for encrypt.
        // Use asynchronous APIs to do this.
        //
        // 1st time:  use null buffer, 2nd time use populated one;
        // this tests different cases for SetDecryptParam function.
        //

        // Prepare the input parameters, using unencypted
        // write data.  This will be encrypted before the
        // command is sent to the TPM.
        rval = Tss2_Sys_NV_Write_Prepare( sysContext,
                TPM20_INDEX_TEST1, TPM20_INDEX_TEST1,
                ( i == 0 ? (TPM2B_MAX_NV_BUFFER *)0 : &writeData ),
                0 );
        CheckPassed( rval );

        // Set up password authorization session structure.
        nvRdWrCmdAuth.sessionHandle = TPM2_RS_PW;
        nvRdWrCmdAuth.nonce.size = 0;
        *( (UINT8 *)((void *)&nvRdWrCmdAuth.sessionAttributes ) ) = 0;
        nvRdWrCmdAuth.hmac.size = nvAuth.size;
        memcpy( (void *)&nvRdWrCmdAuth.hmac.buffer[0],
                (void *)&nvAuth.buffer[0],
                nvRdWrCmdAuth.hmac.size );

        // Set up encrypt/decrypt session structure.
        decryptEncryptSessionCmdAuth.sessionHandle =
                encryptDecryptSession->sessionHandle;
        decryptEncryptSessionCmdAuth.nonce.size = 0;
        *( (UINT8 *)((void *)&sessionAttributes ) ) = 0;
        decryptEncryptSessionCmdAuth.sessionAttributes =
                sessionAttributes;
        decryptEncryptSessionCmdAuth.sessionAttributes.continueSession
                = 1;
        decryptEncryptSessionCmdAuth.sessionAttributes.decrypt = 1;
        decryptEncryptSessionCmdAuth.hmac.size = 0;

        rval = Tss2_Sys_SetCmdAuths( sysContext, &nvRdWrCmdAuths );
        CheckPassed( rval );

        // Get decrypt parameter.
        rval = Tss2_Sys_GetDecryptParam( sysContext,
                &decryptParamSize,
                (const uint8_t **)&decryptParamBuffer );
        CheckPassed( rval );

        if( i == 0 )
        {
            // 1st pass:  test case of Prepare inputting a NULL decrypt
            // param; decryptParamSize should be 0.
            if( decryptParamSize != 0 )
            {
                DebugPrintf( NO_PREFIX, "ERROR!! decryptParamSize != 0\n" );
                Cleanup();
            }
        }

        // Roll nonces for command.
        RollNonces( encryptDecryptSession,
                &decryptEncryptSessionCmdAuth.nonce );

        // Encrypt write data.
        rval = EncryptCommandParam(encryptDecryptSession,
                (TPM2B_MAX_BUFFER *)&encryptedWriteData,
                (TPM2B_MAX_BUFFER *)&writeData, &nvAuth);
        CheckPassed( rval );

        // Now set decrypt parameter.
        rval = Tss2_Sys_SetDecryptParam( sysContext,
                (uint8_t )encryptedWriteData.size,
                (uint8_t *)&encryptedWriteData.buffer[0] );
        CheckPassed( rval );

        // Now write the data to the NV index.
        rval = Tss2_Sys_ExecuteAsync( sysContext );
        CheckPassed( rval );

        rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
        CheckPassed( rval );

        rval = Tss2_Sys_GetRspAuths( sysContext, &nvRdWrRspAuths );
        CheckPassed( rval );

        // Roll the nonces for response
        RollNonces( encryptDecryptSession,
                &nvRdWrRspAuths.rspAuths[1]->nonce );


        // Don't need nonces for anything else, so roll
        // the nonces for next command.
        RollNonces( encryptDecryptSession,
                &decryptEncryptSessionCmdAuth.nonce );

        // Now read the data without encrypt set.
        nvRdWrCmdAuths.cmdAuthsCount = 1;
        nvRdWrRspAuths.rspAuthsCount = 1;
        INIT_SIMPLE_TPM2B_SIZE( readData );
        rval = Tss2_Sys_NV_Read( sysContext, TPM20_INDEX_TEST1,
                TPM20_INDEX_TEST1, &nvRdWrCmdAuths,
                sizeof( writeDataString ), 0, &readData,
                &nvRdWrRspAuths );
        CheckPassed( rval );
        nvRdWrCmdAuths.cmdAuthsCount = 2;
        nvRdWrRspAuths.rspAuthsCount = 2;

        // Roll the nonces for response
        RollNonces( encryptDecryptSession,
                &nvRdWrRspAuths.rspAuths[1]->nonce );

        // Check that write and read data are equal.  This
        // verifies that the decrypt session was setup correctly.
        // If it wasn't, the data stored in the TPM would still
        // be encrypted, and this test would fail.
        if( memcmp( (void *)&readData.buffer[0],
                (void *)&writeData.buffer[0], readData.size ) )
        {
            DebugPrintf( NO_PREFIX, "ERROR!! read data not equal to written data\n" );
            Cleanup();
        }

        //
        // Read TPM index with encrypt session; use
        // synchronous APIs to do this.
        //

        rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_TEST1,
                TPM20_INDEX_TEST1, sizeof( writeDataString ), 0 );
        CheckPassed( rval );

        // Roll the nonces for next command.
        RollNonces( encryptDecryptSession,
                &decryptEncryptSessionCmdAuth.nonce );

        decryptEncryptSessionCmdAuth.sessionAttributes.decrypt = 0;
        decryptEncryptSessionCmdAuth.sessionAttributes.encrypt = 1;
        decryptEncryptSessionCmdAuth.sessionAttributes.continueSession =
                1;

        rval = Tss2_Sys_SetCmdAuths( sysContext, &nvRdWrCmdAuths );
        CheckPassed( rval );

        //
        // Now Read the data.
        //
        rval = Tss2_Sys_Execute( sysContext );
        CheckPassed( rval );

        rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize,
                (const uint8_t **)&encryptParamBuffer );
        CheckPassed( rval );

        rval = Tss2_Sys_GetRspAuths( sysContext, &nvRdWrRspAuths );
        CheckPassed( rval );

        // Roll the nonces for response
        RollNonces( encryptDecryptSession,
                &nvRdWrRspAuths.rspAuths[1]->nonce );

        // Decrypt read data.
        encryptedReadData.size = encryptParamSize;
        memcpy( (void *)&encryptedReadData.buffer[0],
                (void *)encryptParamBuffer, encryptParamSize );
        INIT_SIMPLE_TPM2B_SIZE( decryptedReadData );
        rval = DecryptResponseParam( encryptDecryptSession,
                (TPM2B_MAX_BUFFER *)&decryptedReadData,
                (TPM2B_MAX_BUFFER *)&encryptedReadData, &nvAuth );
        CheckPassed( rval );

        // Roll the nonces.
        RollNonces( encryptDecryptSession,
                &nvRdWrRspAuths.rspAuths[1]->nonce );

        rval = Tss2_Sys_SetEncryptParam( sysContext,
                (uint8_t)decryptedReadData.size,
                (uint8_t *)&decryptedReadData.buffer[0] );
        CheckPassed( rval );

        // Get the command results, in this case the read data.
        INIT_SIMPLE_TPM2B_SIZE( readData );
        rval = Tss2_Sys_NV_Read_Complete( sysContext, &readData );
        CheckPassed( rval );

        DebugPrintf( NO_PREFIX, "Decrypted read data = " );
        DEBUG_PRINT_BUFFER( NO_PREFIX, &readData.buffer[0], (UINT32 )readData.size );

        // Check that write and read data are equal.
        if( memcmp( (void *)&readData.buffer[0],
                (void *)&writeData.buffer[0], readData.size ) )
        {
            DebugPrintf( NO_PREFIX, "ERROR!! read data not equal to written data\n" );
            Cleanup();
        }

        rval = Tss2_Sys_FlushContext( sysContext,
                encryptDecryptSession->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( encryptDecryptSession );
        CheckPassed( rval );
    }

    // Set authorization for NV undefine command.
    nvUndefineAuth.sessionHandle = TPM2_RS_PW;
    nvUndefineAuth.nonce.size = 0;
    *( (UINT8 *)((void *)&nvUndefineAuth.sessionAttributes ) ) = 0;
    nvUndefineAuth.hmac.size = 0;

    // Undefine NV index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext,
            TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &nvUndefineAuths, 0 );
    CheckPassed( rval );
}

void GetSetDecryptParamTests()
{
    TPM2B_MAX_NV_BUFFER nvWriteData = {4, { 0xde, 0xad, 0xbe, 0xef,} };
    TPM2B_MAX_NV_BUFFER nvWriteData1 = {4, { 0x01, 0x01, 0x02, 0x03,} };
    const uint8_t *decryptParamBuffer;
    size_t decryptParamSize;
    size_t cpBufferUsedSize1, cpBufferUsedSize2;
    const uint8_t *cpBuffer1, *cpBuffer2;
    TSS2_RC rval;
    int i;
    TSS2_SYS_CONTEXT *decryptParamTestSysContext;

    DebugPrintf( NO_PREFIX, "\nGET/SET DECRYPT PARAM TESTS:\n" );

    // Create two sysContext structures.
    decryptParamTestSysContext = InitSysContext( TPM2_MAX_NV_BUFFER_SIZE, resMgrTctiContext, &abiVersion );
    if( decryptParamTestSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // Test for bad sequence:  Tss2_Sys_GetDecryptParam
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    // Test for bad sequence:  Tss2_Sys_SetDecryptParam
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    // NOTE:  Two tests for BAD_SEQUENCE for GetDecryptParam and SetDecryptParam after ExecuteAsync
    // are in the GetSetEncryptParamTests function, just because it's easier to do this way.

    // Do Prepare.
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData1, 0x55aa );
    CheckPassed( rval );

    // Test for bad reference:  Tss2_Sys_GetDecryptParam
    rval = Tss2_Sys_GetDecryptParam( 0, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, 0, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );


    // Test for bad reference:  Tss2_Sys_SetDecryptParam
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_SetDecryptParam( 0, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );


    // Test for bad size.
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 5, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 3, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    // Test for good size.
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckPassed( rval );

    // Make sure that the set operation really did the right thing.
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );
    for( i = 0; i < 4; i++ )
    {
        if( decryptParamBuffer[i] != nvWriteData.buffer[i] )
        {
            DebugPrintf( NO_PREFIX, "ERROR!!  decryptParamBuffer[%d] s/b: %2.2x, was: %2.2x\n", i, nvWriteData.buffer[i], decryptParamBuffer[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize1, &cpBuffer1 );
    CheckPassed( rval );

#ifdef DEBUG
    DebugPrintf( NO_PREFIX, "cpBuffer = ");
#endif
    DEBUG_PRINT_BUFFER( NO_PREFIX, (UINT8 *)cpBuffer1, cpBufferUsedSize1 );

    // Test for no decrypt param.
    rval = Tss2_Sys_NV_Read_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, sizeof( nvWriteData ) - 2, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_NO_DECRYPT_PARAM );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_NO_DECRYPT_PARAM );

    // Null decrypt param.
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, 0, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );

    // Check that size == 0.
    if( decryptParamSize != 0 )
    {
        DebugPrintf( NO_PREFIX, "ERROR!!  decryptParamSize s/b: 0, was: %u\n", (unsigned int)decryptParamSize );
        Cleanup();
    }

    // Test for insufficient size.
    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize2, &cpBuffer2 );
    CheckPassed( rval );
    nvWriteData.size = TPM2_MAX_NV_BUFFER_SIZE -
            BE_TO_HOST_32(((TPM20_Header_In *)(((_TSS2_SYS_CONTEXT_BLOB *)decryptParamTestSysContext)->cmdBuffer))->commandSize) + 1;

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, nvWriteData.size, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT );

    // Test that one less will work.  This tests that we're checking the correct corner case.
    nvWriteData.size -= 1;
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, nvWriteData.size, &( nvWriteData.buffer[0] ) );
    CheckPassed( rval );


    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, 0, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckPassed( rval );

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize2, &cpBuffer2 );
    CheckPassed( rval );

#ifdef DEBUG
    DebugPrintf( NO_PREFIX, "cpBuffer = ");
#endif
    DEBUG_PRINT_BUFFER( NO_PREFIX, (UINT8 *)cpBuffer2, cpBufferUsedSize2 );

    if( cpBufferUsedSize1 != cpBufferUsedSize2 )
    {
        DebugPrintf( NO_PREFIX, "ERROR!!  cpBufferUsedSize1(%x) != cpBufferUsedSize2(%x)\n", (UINT32)cpBufferUsedSize1, (UINT32)cpBufferUsedSize2 );
        Cleanup();
    }
    for( i = 0; i < (int)cpBufferUsedSize1; i++ )
    {
        if( cpBuffer1[i] != cpBuffer2[i] )
        {
            DebugPrintf( NO_PREFIX, "ERROR!! cpBufferUsedSize1[%d] s/b: %2.2x, was: %2.2x\n", i, cpBuffer1[i], cpBuffer2[i] );
            Cleanup();
        }
    }

    // Test case of zero sized decrypt param, another case of bad size.
    nvWriteData1.size = 0;
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData1, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 1, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    TeardownSysContext( &decryptParamTestSysContext );
}

void SysFinalizeTests()
{
    DebugPrintf( NO_PREFIX, "\nSYS FINALIZE TESTS:\n" );

    Tss2_Sys_Finalize( 0 );

    // Note:  other cases tested by other tests.
}

void GetContextSizeTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_CONTEXT *testSysContext;

    DebugPrintf( NO_PREFIX, "\nSYS GETCONTEXTSIZE TESTS:\n" );

    testSysContext = InitSysContext( 9, resMgrTctiContext, &abiVersion );
    if( testSysContext == 0 )
    {
        InitSysContextFailure();
    }

    rval = Tss2_Sys_Startup( testSysContext, TPM2_SU_CLEAR );
    CheckFailed( rval, TSS2_TYPES_RC_INSUFFICIENT_BUFFER );

	rval = Tss2_Sys_GetTestResult_Prepare( testSysContext );
	CheckPassed( rval );

    // Note:  other cases tested by other tests.

    TeardownSysContext( &testSysContext );
}

void GetTctiContextTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_CONTEXT *testSysContext;
    TSS2_TCTI_CONTEXT *tctiContext;

    DebugPrintf( NO_PREFIX, "\nSYS GETTCTICONTEXT TESTS:\n" );

    testSysContext = InitSysContext( 9, resMgrTctiContext, &abiVersion );
    if( testSysContext == 0 )
    {
        InitSysContextFailure();
    }

    rval = Tss2_Sys_GetTctiContext( testSysContext, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetTctiContext( 0, &tctiContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    TeardownSysContext( &testSysContext );
}

void GetSetEncryptParamTests()
{
    TPM2B_MAX_NV_BUFFER nvWriteData = {4, { 0xde, 0xad, 0xbe, 0xef,} };
    const uint8_t *encryptParamBuffer;
    const uint8_t encryptParamBuffer1[4] = { 01, 02, 03, 04 };
    size_t encryptParamSize;
    TSS2_RC rval;
    int i;
    TPM2B_DIGEST authPolicy;
    TPMA_NV nvAttributes;
    TPM2B_AUTH  nvAuth;

    TPMS_AUTH_COMMAND sessionData = { TPM2_RS_PW, };
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };

    TPM2B_MAX_NV_BUFFER nvReadData;
    const uint8_t 		*cpBuffer;

    DebugPrintf( NO_PREFIX, "\nGET/SET ENCRYPT PARAM TESTS:\n" );

    // Do Prepare.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval ); // #1

    // Test for bad sequence
    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #2

    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #3

    // Create NV index

    // Set empty policy and auth value.
    authPolicy.size = 0;
    nvAuth.size = 0;

    // Now set the attributes.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_AUTHREAD = 1;
    nvAttributes.TPMA_NV_AUTHWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW, &nvAuth, &authPolicy,
            TPM20_INDEX_PASSWORD_TEST, TPM2_ALG_SHA1, nvAttributes, 32  );
    CheckPassed( rval ); // #4

    // Write the index.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval ); // #5

    // NOTE: add GetCpBuffer tests here, just because its easier.
    rval = Tss2_Sys_GetCpBuffer( 0, (size_t *)4, (const uint8_t **)4 );
	CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #6

    rval = Tss2_Sys_GetCpBuffer( sysContext, (size_t *)0, (const uint8_t **)4 );
	CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #7

    rval = Tss2_Sys_GetCpBuffer( sysContext, (size_t *)4, (const uint8_t **)0 );
	CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #8


    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval ); // #9

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval ); // #10

    // NOTE: Stick two tests for BAD_SEQUENCE for GetDecryptParam and SetDecryptParam here, just
    // because it's easier to do this way.
    rval = Tss2_Sys_GetDecryptParam( sysContext, (size_t *)4, (const uint8_t **)4 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #11

    rval = Tss2_Sys_SetDecryptParam( sysContext, 10, (uint8_t *)4 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #12

    // NOTE: Stick test for BAD_SEQUENCE for GetCpBuffer here, just
    // because it's easier to do this way.
    rval = Tss2_Sys_GetCpBuffer( sysContext, (size_t *)4, &cpBuffer );
	CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #13

    // Now finish the write command so that TPM isn't stuck trying
    // to send a response.
    rval = Tss2_Sys_ExecuteFinish( sysContext, -1 );
    CheckPassed( rval ); // #14

    // Test GetEncryptParam for no encrypt param case.
    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_NO_ENCRYPT_PARAM ); // #15

    // Test SetEncryptParam for no encrypt param case.
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckFailed( rval, TSS2_SYS_RC_NO_ENCRYPT_PARAM ); // #16

    // Now read it and do tests on get/set encrypt functions
    rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, 4, 0 );
    CheckPassed( rval ); // #17

    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 4, 0, &nvReadData, &sessionsDataOut );
    CheckPassed( rval ); // #18

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckPassed( rval ); // #19

    // Test case of encryptParamSize being too small.
    encryptParamSize--;
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE ); // #20
    encryptParamSize += 2;

    // Size too large...
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE ); // #21

    encryptParamSize--;
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckPassed( rval ); // #22

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckPassed( rval ); // #23

    // Test that encryptParamBuffer is the same as encryptParamBuffer1
    for( i = 0; i < 4; i++ )
    {
        if( encryptParamBuffer[i] != encryptParamBuffer1[i] )
        {
            DebugPrintf( NO_PREFIX, "ERROR!! encryptParamBuffer[%d] s/b: %2.2x, was: %2.2x\n", i, encryptParamBuffer[i], encryptParamBuffer1[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval ); // #24


    // Test for bad reference
    rval = Tss2_Sys_GetEncryptParam( 0, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #25

    rval = Tss2_Sys_GetEncryptParam( sysContext, 0, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #26

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #27

    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #28

    rval = Tss2_Sys_SetEncryptParam( 0, 4, encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #29
}

void EcEphemeralTest()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_ECC_POINT Q;
    UINT16 counter;

    DebugPrintf( NO_PREFIX, "\nEC Ephemeral TESTS:\n" );

    // Test SAPI for case of Q size field not being set to 0.
    INIT_SIMPLE_TPM2B_SIZE( Q );
    rval = Tss2_Sys_EC_Ephemeral( sysContext, 0, TPM2_ECC_BN_P256, &Q, &counter, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    Q.size = 0;
    rval = Tss2_Sys_EC_Ephemeral( sysContext, 0, TPM2_ECC_BN_P256, &Q, &counter, 0 );
    CheckPassed( rval );
}

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    sysContext = sapi_context;
    rval = Tss2_Sys_GetTctiContext (sapi_context, &resMgrTctiContext);
    if (rval != TSS2_RC_SUCCESS) {
        printf ("Failed to get TCTI context from sapi_context: 0x%" PRIx32
                "\n", rval);
        return 1;
    }

    nullSessionsDataOut.rspAuthsCount = 1;
    nullSessionsDataOut.rspAuths[0]->nonce = nullSessionNonceOut;
    nullSessionsDataOut.rspAuths[0]->hmac = nullSessionHmac;
    nullSessionNonceOut.size = 0;
    nullSessionNonce.size = 0;

    loadedSha1KeyAuth.size = 2;
    loadedSha1KeyAuth.buffer[0] = 0x00;
    loadedSha1KeyAuth.buffer[1] = 0xff;

    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );

    InitEntities();

    InitNullSession( &nullSessionData);

    SysFinalizeTests();

    GetContextSizeTests();

    GetTctiContextTests();

    GetSetDecryptParamTests();

    TestTpmStartup();

    // Run this directly after Startup tests to test for
    // a resource mgr corner case with SaveContext.
    TestStartAuthSession();
    // Clear DA lockout.
    TestDictionaryAttackLockReset();
    TestDictionaryAttackLockReset();
    TestCreate();
    TestHierarchyControl();
    NvIndexProto();
    GetSetEncryptParamTests();
    TestEncryptDecryptSession();
    SimpleHmacOrPolicyTest( true );
    TestTpmGetCapability();
    TestPcrExtend();
    TestHash();
    TestPolicy();
    TestTpmClear();
    TestChangeEps();
    TestChangePps();
    TestHierarchyChangeAuth();
    TestShutdown();
    TestNV();
    TestCreate();
    TestEvict();
    NvIndexProto();
    PasswordTest();
    TestQuote();
    TestDictionaryAttackLockReset();
    TestPcrAllocate();
    TestUnseal();
    EcEphemeralTest();
    // Clear out RM entries for objects.
    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );
    rval = Tss2_Sys_FlushContext( sysContext, loadedSha1KeyHandle );
    CheckPassed( rval );

    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    return 0;
}
