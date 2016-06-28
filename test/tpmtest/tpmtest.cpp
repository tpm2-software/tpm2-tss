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

//
// tpmtest.cpp : Defines the entry point for the console test application.
//


#ifdef _WIN32
#include "stdafx.h"
//++++
#else
#include <stdarg.h>
//++++
#endif

#ifndef UNICODE
#define UNICODE 1
#endif

#ifdef _WIN32
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
//++++++
#else
#define sprintf_s   snprintf
#define sscanf_s    sscanf
//+++++
#endif

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi
#include <string.h>
#include <unistd.h>   // Needed for isatty

#include <tss2/tpm20.h>
//#include "simulator.h"
#include "sample.h"
//#include "simdriver.h"
#include "resourcemgr.h"
#include "tpmclient.h"
#include "sysapi_util.h"
//+++++
#include <tcti/tcti_socket.h>
#include "syscontext.h"
#include "debug.h"
#include "utils.h"
//#include "cases.h"

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


#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
(pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define CLEAR_PCR_SELECT_BITS( pcrSelection ) \
(pcrSelection).pcrSelect[0] = 0; \
(pcrSelection).pcrSelect[1] = 0; \
(pcrSelection).pcrSelect[2] = 0;

#define SET_PCR_SELECT_SIZE( pcrSelection, size ) \
(pcrSelection).sizeofSelect = size;

TPM_CC currentCommandCode;
TPM_CC *currentCommandCodePtr = &currentCommandCode;

//----
//char errorString[200];
//----

//+++
#define errorStringSize 200
char errorString[errorStringSize];

UINT8 simulator = 1;
//+++

UINT32 tpmMaxResponseLen = TPMBUF_LEN;

UINT8 pcrAfterExtend[20];
TPM_HANDLE loadedRsaKeyHandle;
TPM_HANDLE loadedSha1KeyHandle;

TPM2B_AUTH loadedSha1KeyAuth;

TPM_HANDLE handle1024, handle2048sha1, handle2048rsa;

UINT32 passCount = 1;
UINT32 demoDelay = 0;
int debugLevel = 0;
int startAuthSessionTestOnly = 0;
UINT8 indent = 0;

TSS2_SYS_CONTEXT *sysContext;

TCTI_SOCKET_CONF rmInterfaceConfig = {
    DEFAULT_HOSTNAME,
    DEFAULT_RESMGR_TPM_PORT,
    DebugPrintfCallback,
    DebugPrintBufferCallback,
    NULL
};

TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
//TSS2_ABI_VERSION abiVersion = { 1, 1, 1, 1 };
TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

UINT32 tpmSpecVersion = 0;

enum TPM_TYPES
{
    TPM_TYPE_SIMULATOR, TPM_TYPE_PTT, TPM_TYPE_DTPM
} tpmType = TPM_TYPE_SIMULATOR;
UINT32 nullPlatformAuth = 1;

//
// These are helper functions that are called through function pointers so that
// they could be swapped easily to point to different functions.
//
// Currently they are set to functions that use the TPM to perform the function, but SW-only
// implementations could be substituted as well.
//
UINT32 ( *ComputeSessionHmacPtr )(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_AUTH_COMMAND *cmdAuth, // Pointer to session input struct
    TPM_HANDLE entityHandle,             // Used to determine if we're accessing a different
                                         // resource than the bound resoure.
    TPM_RC responseCode,                 // Response code for the command, 0xffff for "none" is
                                         // used to indicate that no response code is present
                                         // (used for calculating command HMACs vs response HMACs).
    TPM_HANDLE handle1,                  // First handle == 0xff000000 indicates no handle
    TPM_HANDLE handle2,                  // Second handle == 0xff000000 indicates no handle
    TPMA_SESSION sessionAttributes,      // Current session attributes
    TPM2B_DIGEST *result,                // Where the result hash is saved.
    TPM_RC sessionCmdRval
    ) = TpmComputeSessionHmac;

TPM_RC ( *GetSessionAlgIdPtr )( TPMI_SH_AUTH_SESSION authHandle, TPMI_ALG_HASH *sessionAlgId ) = GetSessionAlgId;

TPM_RC ( *CalcPHash )( TSS2_SYS_CONTEXT *sysContext,TPM_HANDLE handle1, TPM_HANDLE handle2, TPMI_ALG_HASH authHash,
    TPM_RC responseCode, TPM2B_DIGEST *pHash ) = TpmCalcPHash;

UINT32 (*HmacFunctionPtr)( TPM_ALG_ID hashAlg, TPM2B *key,TPM2B **bufferList, TPM2B_DIGEST *result ) = TpmHmac;

UINT32 (*HashFunctionPtr)( TPMI_ALG_HASH hashAlg, UINT16 size, BYTE *data, TPM2B_DIGEST *result ) = TpmHash;

UINT32 (*HandleToNameFunctionPtr)( TPM_HANDLE handle, TPM2B_NAME *name ) = TpmHandleToName;

TPMI_SH_AUTH_SESSION StartPolicySession();

TPMI_SH_AUTH_SESSION InitNvAuxPolicySession();

//-------
/*
void ErrorHandler( UINT32 rval )
{
    sprintf( errorString, "TPM Error -- TPM Error: 0x%x\n", rval );
}
*/
//------

//+++++++++++
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

    sprintf_s( errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval );
}

char resMgrInterfaceName[] = "Resource Manager";

TSS2_RC InitTctiResMgrContext( TCTI_SOCKET_CONF *rmInterfaceConfig, TSS2_TCTI_CONTEXT **tctiContext, char *name )
{
    size_t size;

    TSS2_RC rval;

    rval = InitSocketTcti(NULL, &size, rmInterfaceConfig, 0 );
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    *tctiContext = (TSS2_TCTI_CONTEXT *)malloc(size);
    if( *tctiContext )
    {
        DebugPrintf( NO_PREFIX, "Initializing %s Interface\n", name );
        rval = InitSocketTcti(*tctiContext, &size, rmInterfaceConfig, 0 );
    }
    else
    {
        rval = TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return rval;

}
//----------
/*
TSS2_RC TeardownTctiResMgrContext( char *driverConfig )
{
    return resMgrTctiDriverInfo.teardown(resMgrTctiContext, driverConfig );
}
*/
//-----------
//+++++++++++
TSS2_RC TeardownTctiResMgrContext( TSS2_TCTI_CONTEXT *tctiContext )
{
    return TeardownSocketTcti( tctiContext );
}
//+++++++++++
void Cleanup()
{
    fflush( stdout );
//-----------
/*
    if( simulatorTest == 1 )
    {
        PlatformCommand( MS_SIM_POWER_OFF );
    }

    TeardownTctiResMgrContext( driverConfig );
*/
//----------

	PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );

	TeardownTctiResMgrContext( resMgrTctiContext );

#ifdef _WIN32
    WSACleanup();
#endif
    exit(1);
}

void InitSysContextFailure()
{
//    printf( "InitSysContext failed, exiting...\n" );
	DebugPrintf( NO_PREFIX, "InitSysContext failed, exiting...\n" );
    Cleanup();
}

void Delay( UINT32 delay)
{
    volatile UINT32 i, j;

    for( j = 0; j < delay; j++ )
    {
        for( i = 0; i < 10000000; i++ )
            ;
    }
}

void CheckPassed( UINT32 rval )
{
    DebugPrintf( NO_PREFIX, "\tpassing case:  " );
    if ( rval != TPM_RC_SUCCESS) {
        ErrorHandler( rval);
//        printf( "\tFAILED!  %s\n", errorString );
		DebugPrintf( NO_PREFIX, "\tFAILED!  %s\n", errorString );
        Cleanup();
    }
    else
    {
        printf( "\tPASSED!\n" );
    }

    Delay(demoDelay);
}

TPMS_AUTH_COMMAND nullSessionData;
TPMS_AUTH_RESPONSE nullSessionDataOut;
TPMS_AUTH_COMMAND *nullSessionDataArray[1] = { &nullSessionData };
TPMS_AUTH_RESPONSE *nullSessionDataOutArray[1] = { &nullSessionDataOut };
TSS2_SYS_CMD_AUTHS nullSessionsData = { 1, &nullSessionDataArray[0] };
TSS2_SYS_RSP_AUTHS nullSessionsDataOut = { 1, &nullSessionDataOutArray[0] };
TPM2B_NONCE nullSessionNonce, nullSessionNonceOut;
TPM2B_AUTH nullSessionHmac;

void CheckFailed( UINT32 rval, UINT32 expectedTpmErrorCode )
{
    DebugPrintf( NO_PREFIX, "\tfailing case: " );
    if ( rval != expectedTpmErrorCode) {
        ErrorHandler( rval);
        DebugPrintf( NO_PREFIX, "\tFAILED!  Ret code s/b: %x, but was: %x\n", expectedTpmErrorCode, rval );
        Cleanup();
    }
    else
    {
        DebugPrintf( NO_PREFIX, "\tPASSED!\n" );
    }
    Delay(demoDelay);
}

TSS2_RC TpmReset()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tpmType == TPM_TYPE_SIMULATOR )
    {
        rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
        if( rval == TSS2_RC_SUCCESS )
        {
            rval = (TSS2_RC)PlatformCommand(  resMgrTctiContext, MS_SIM_POWER_ON );
        }
    }
    else
    {
        TSS2_SYS_RSP_AUTHS sessionsDataOut;
        TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
        TPMS_AUTH_RESPONSE sessionDataOut;
        sessionDataOutArray[0] = &sessionDataOut;
        sessionsDataOut.rspAuths = &sessionDataOutArray[0];
        sessionsDataOut.rspAuthsCount = 1;

        rval = Tss2_Sys_Startup ( sysContext, TPM_SU_CLEAR );
        {
            // Need to add a Shutdown, otherwise the follow Startup(CLEAR) will be failed.
            rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_CLEAR, &sessionsDataOut );
        }
    }

    return rval;
}

TSS2_RC TpmShutdown()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TPMS_AUTH_RESPONSE sessionDataOut;
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_CLEAR, &sessionsDataOut );

    return rval;
}

void GetTpmVersion()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMS_CAPABILITY_DATA capabilityData;

    rval = Tss2_Sys_GetCapability( sysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_REVISION,
            1, 0, &capabilityData, 0 );
    CheckPassed( rval );

    if( capabilityData.data.tpmProperties.count == 1 &&
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_REVISION) )
    {
        tpmSpecVersion = capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else
    {
        DebugPrintf( NO_PREFIX, "Failed to get TPM spec version!!\n" );
        Cleanup();
    }
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

    printf( "\nDICTIONARY ATTACK LOCK RESET TEST:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_DictionaryAttackLockReset ( sysContext, TPM_RH_LOCKOUT, &sessionsData, &sessionsDataOut );
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

    digestSize = GetDigestSize( TPM_ALG_SHA1 );
    nonceCaller.t.size = digestSize;
    for( i = 0; i < nonceCaller.t.size; i++ )
        nonceCaller.t.buffer[i] = 0;

    salt.t.size = 0;
    symmetric.algorithm = TPM_ALG_NULL;
    INIT_SIMPLE_TPM2B_SIZE( nonceTpm );

    // Create policy session
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM_RH_NULL, TPM_RH_NULL, 0, &nonceCaller, &salt,
            TPM_SE_POLICY, &symmetric, TPM_ALG_SHA1, sessionHandle, &nonceTpm, 0 );
    return( rval );
}

void TestTpmStartup()
{
    UINT32 rval;
    UINT8 startupAlreadyDone = 0;

    printf( "\nSTARTUP TESTS:\n" );

    //
    // First test the one-call interface.
    //

    // First must do TPM reset.
    rval = TpmReset();
    CheckPassed(rval);

    // This one should pass.
    rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
    if( rval != TPM_RC_INITIALIZE )
        CheckPassed(rval);
    else
        startupAlreadyDone = 1;

    // This one should fail.
    rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
    CheckFailed( rval, TPM_RC_INITIALIZE );

    rval = TpmReset();
    CheckPassed(rval);

    //
    // Now test the syncronous, non-one-call interface.
    //
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval);

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute( sysContext );
    if( startupAlreadyDone == 1 )
    {
        CheckFailed(rval, TPM_RC_INITIALIZE);
    }
    else
    {
        CheckPassed(rval);
    }

    rval = TpmReset();
    CheckPassed(rval);

    //
    // Now test the asyncronous, non-one-call interface.
    //
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval);

    // Execute the command asyncronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed(rval);

    // Get the command response. Wait a maximum of 20ms
    // for response.
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    if( startupAlreadyDone == 1 )
    {
        CheckFailed(rval, TPM_RC_INITIALIZE);
    }
    else
    {
        CheckPassed(rval);
    }
}

void TestSapiApis()
{
    UINT32 rval;
    TPM2B_MAX_BUFFER    outData = { { MAX_DIGEST_BUFFER, } };
    TPM_RC              testResult;

    printf( "\nGET TEST RESULT TESTS:\n" );

    //
    // First test the one-call interface.
    //
    rval = Tss2_Sys_GetTestResult( sysContext, 0, &outData, &testResult, 0 );
    CheckPassed(rval);

    //
    // Now test the syncronous, non-one-call interface.
    //
    rval = Tss2_Sys_GetTestResult_Prepare( sysContext );
    CheckPassed(rval);

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed(rval);

    // Get the command results
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckPassed(rval);

    //
    // Now test the asyncronous, non-one-call interface.
    //
    rval = Tss2_Sys_GetTestResult_Prepare( sysContext );
    CheckPassed(rval);

    // Execute the command asyncronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed(rval);

    // Get the command response. Wait a maximum of 20ms
    // for response.
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed(rval);

    // Get the command results
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckPassed(rval);

#if 0
//    if( simulatorTest == 1 )
    {
        // Check case of ExecuteFinish receving TPM error code.
        // Subsequent _Complete call should fail with SEQUENCE error.
        rval = TpmReset();
        CheckPassed(rval);

        rval = Tss2_Sys_GetCapability_Prepare( sysContext,
                TPM_CAP_TPM_PROPERTIES, TPM_PT_ACTIVE_SESSIONS_MAX,
                1 );
        CheckPassed(rval);

        // Execute the command asyncronously.
        rval = Tss2_Sys_ExecuteAsync( sysContext );
        CheckPassed(rval);

        // Get the command response. Wait a maximum of 20ms
        // for response.
        rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
        CheckFailed( rval, TPM_RC_INITIALIZE );

        // Get the command results
        rval = Tss2_Sys_GetCapability_Complete( sysContext, 0, 0 );
        CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

        rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
        CheckPassed(rval);
    }
#endif
}


void TestTpmSelftest()
{
    UINT32 rval;

    printf( "\nSELFTEST TESTS:\n" );

    rval = Tss2_Sys_SelfTest( sysContext, 0, YES, 0);
    CheckPassed( rval );

    rval = Tss2_Sys_SelfTest( sysContext, 0, NO, 0);
    CheckPassed( rval );

    rval = Tss2_Sys_SelfTest( sysContext, 0, YES, 0);
    CheckPassed( rval );

}

void TestTpmGetCapability()
{
    UINT32 rval;

    char manuID[5] = "    ";
	char *manuIDPtr = &manuID[0];
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    printf( "\nGET_CAPABILITY TESTS:\n" );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );

//    *( (UINT32 *)manuID ) = CHANGE_ENDIAN_DWORD( capabilityData.data.tpmProperties.tpmProperty[0].value );
	*( (UINT32 *)manuIDPtr ) = CHANGE_ENDIAN_DWORD( capabilityData.data.tpmProperties.tpmProperty[0].value );
    printf( "\t\tcount: %d, property: %x, manuId: %s\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            manuID );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_COMMAND_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    printf( "\t\tcount: %d, property: %x, max cmd size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );


    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_COMMAND_SIZE, 40, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    printf( "\t\tcount: %d, property: %x, max cmd size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );


    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_RESPONSE_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    printf( "\t count: %d, property: %x, max response size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );

    rval = Tss2_Sys_GetCapability( sysContext, 0, 0xff, TPM_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );

    if( tpmSpecVersion == 115 || tpmSpecVersion == 119 )
    {
        CheckFailed( rval, TPM_RC_VALUE );
    }
    else
    {
        CheckFailed( rval, TPM_RC_VALUE+TPM_RC_1+TPM_RC_P );
    }
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

    printf( "\nCLEAR and CLEAR CONTROL TESTS:\n" );

    // Init sessionHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    nonce.t.size = 0;
    sessionData.nonce = nonce;

    // init hmac
    hmac.t.size = 0;
    sessionData.hmac = hmac;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsDataIn.cmdAuthsCount = 1;
    sessionsDataIn.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_ClearControl ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Clear ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, YES, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Clear ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, 0 );
    CheckFailed( rval, TPM_RC_DISABLED );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckPassed( rval );

    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0xff;
    sessionsDataIn.cmdAuths[0] = &sessionData;
    rval = Tss2_Sys_Clear ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_9 + TPM_RC_RESERVED_BITS );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_9 + TPM_RC_RESERVED_BITS );

    hmac.t.size = 0;


}

#ifdef DEBUG_GAP_HANDLING

#define SESSIONS_ABOVE_MAX_ACTIVE 1
//    SESSION sessions[DEBUG_GAP_MAX*3];
    SESSION *sessions[300];
#else

#define SESSIONS_ABOVE_MAX_ACTIVE 0
#define DEBUG_MAX_ACTIVE_SESSIONS   8
#define DEBUG_GAP_MAX   2*DEBUG_MAX_ACTIVE_SESSIONS
    SESSION *sessions[5];

#endif

void TestStartAuthSession()
{
    UINT32 rval;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPMT_SYM_DEF symmetric;
    SESSION *authSession;
    TPM2B_NONCE nonceCaller;
    UINT16 i;
#ifdef DEBUG_GAP_HANDLING    
    UINT16 debugGapMax = DEBUG_GAP_MAX, debugMaxActiveSessions = DEBUG_MAX_ACTIVE_SESSIONS;    
    TPMS_CONTEXT    evictedSessionContext;
    TPM_HANDLE   evictedHandle;
#endif
    TPMA_LOCALITY locality;
    TPM_HANDLE badSessionHandle = 0x03010000;

    TPMS_AUTH_COMMAND sessionData;
    TPM2B_NONCE     nonce;
    TSS2_SYS_CMD_AUTHS sessionsDataIn;

    TPMS_AUTH_COMMAND *sessionDataArray[1];

    TPM2B_AUTH      hmac;

    sessionDataArray[0] = &sessionData;

    sessionsDataIn.cmdAuths = &sessionDataArray[0];

    sessionsDataIn.cmdAuthsCount = 1;

    // Init sessionHandle
    sessionData.sessionHandle = badSessionHandle;

    // Init nonce.
    nonce.t.size = 0;
    sessionData.nonce = nonce;

    // init hmac
    hmac.t.size = 0;
    sessionData.hmac = hmac;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    encryptedSalt.t.size = 0;

    printf( "\nSTART_AUTH_SESSION TESTS:\n" );

    symmetric.algorithm = TPM_ALG_NULL;
    symmetric.keyBits.sym = 0;
    symmetric.mode.sym = 0;

    nonceCaller.t.size = 0;

    encryptedSalt.t.size = 0;

     // Init session
    rval = StartAuthSessionWithParams( &authSession, TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, authSession->sessionHandle );
    CheckPassed( rval );
    EndAuthSession( authSession );

    // Init session
    rval = StartAuthSessionWithParams( &authSession, TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, 0xff, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckFailed( rval, TPM_RC_VALUE + TPM_RC_P + TPM_RC_3 );

    // Try starting a bunch to see if resource manager handles this correctly.

#ifdef DEBUG_GAP_HANDLING
    for( i = 0; i < debugMaxActiveSessions*3; i++ )
#else
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
#endif
    {
//        printf( "i = 0x%4.4x\n", i );

        // Init session struct
        rval = StartAuthSessionWithParams( &sessions[i], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );
        printf( "Number of sessions created: %d\n\n", i );

#ifdef DEBUG_GAP_HANDLING
        if( i == 0 )
        {
           // Save evicted session's context so we can use it for a test.
           rval = Tss2_Sys_ContextSave( sysContext, sessions[i]->sessionHandle, &evictedSessionContext );
           CheckPassed( rval );
        }
#endif
    }

#ifdef DEBUG_GAP_HANDLING
    printf( "loading evicted session's context\n" );
    // Now try loading an evicted session's context.
    // NOTE: simulator versions 01.19 and earlier this test will fail due to a
    // simulator bug (unless patches have been applied).
    rval = Tss2_Sys_ContextLoad( sysContext, &evictedSessionContext, &evictedHandle );
    CheckFailed( rval, TPM_RC_HANDLE + TPM_RC_P + ( 1 << 8  ));
#endif

    // Now try two ways of using a bad session handle.  Both should fail.

    // first way is to use as command parameter.
    *(UINT8 *)( (void *)&locality ) = 0;
    locality.TPM_LOC_THREE = 1;
    rval = Tss2_Sys_PolicyLocality( sysContext, badSessionHandle, 0, locality, 0 );
    CheckFailed( rval, TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_HANDLE + ( 1 << 8 ) );

    // Second way is to use as handle in session area.
    rval = Tss2_Sys_PolicyLocality( sysContext, sessions[0]->sessionHandle, &sessionsDataIn, locality, 0 );
    CheckFailed( rval, TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_VALUE + TPM_RC_S + ( 1 << 8 ) );

    // clean up the sessions that I don't want here.
#ifdef DEBUG_GAP_HANDLING
    for( i = 0; i < ( debugMaxActiveSessions*3); i++ )
#else
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *)); i++ )
#endif
    {
//        printf( "i(2) = 0x%4.4x\n", i );
        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );

        rval = EndAuthSession( sessions[i] );
    }

    // Now do some gap tests.
    rval = StartAuthSessionWithParams( &sessions[0], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

#ifdef DEBUG_GAP_HANDLING
//    for( i = 1; i < debugGapMax/2; i++ )
    for( i = 1; i < 300; i++ )
#else
    for( i = 1; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
#endif
    {
//        printf( "i(3) = 0x%4.4x\n", i );

        rval = StartAuthSessionWithParams( &sessions[i], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i] );
        CheckPassed( rval );
    }

#ifdef DEBUG_GAP_HANDLING
    // Now do some gap tests.
    rval = StartAuthSessionWithParams( &sessions[8], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );
#endif

#ifdef DEBUG_GAP_HANDLING
    for( i = 9; i < debugGapMax; i++ )
#else
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
#endif
    {
//        printf( "i(4) = 0x%4.4x\n", i );
        rval = StartAuthSessionWithParams( &sessions[i], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i] );
        CheckPassed( rval );

    }

#ifdef DEBUG_GAP_HANDLING
    for( i = 0; i < 5; i++ )
    {
//        printf( "i(5) = 0x%4.4x\n", i );
        rval = StartAuthSessionWithParams( &sessions[i+16], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );
    }

    for( i = 0; i < 5; i++ )
    {
//        printf( "i(6) = 0x%4.4x\n", i );
        rval = Tss2_Sys_FlushContext( sysContext, sessions[i+16]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i+16] );
        CheckPassed( rval );
    }

    rval = Tss2_Sys_FlushContext( sysContext, sessions[0]->sessionHandle );
    CheckPassed( rval );

    rval = EndAuthSession( sessions[0] );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, sessions[8]->sessionHandle );
    CheckPassed( rval );

    rval = EndAuthSession( sessions[8] );
    CheckPassed( rval );
#endif

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

    printf( "\nCHANGE_EPS TESTS:\n" );

	sessionsData.cmdAuthsCount = 1;

    // Init authHandle
    sessionsData.cmdAuths[0]->sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionsData.cmdAuths[0]->nonce.t.size = 0;

    // init hmac
    sessionsData.cmdAuths[0]->hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionsData.cmdAuths[0]->sessionAttributes ) ) = 0;

    rval = Tss2_Sys_ChangeEPS( sysContext, TPM_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );

    sessionsData.cmdAuths[0]->hmac.t.size = 0x10;

    rval = Tss2_Sys_ChangeEPS( sysContext, TPM_RH_PLATFORM, &sessionsData, 0 );
    CheckFailed( rval, TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH );
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

    printf( "\nCHANGE_PPS TESTS:\n" );

    sessionsData.cmdAuthsCount = 1;

    // Init authHandle
    sessionsData.cmdAuths[0]->sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionsData.cmdAuths[0]->nonce.t.size = 0;

    // init hmac
    sessionsData.cmdAuths[0]->hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionsData.cmdAuths[0]->sessionAttributes ) ) = 0;

    rval = Tss2_Sys_ChangePPS( sysContext, TPM_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );

    sessionsData.cmdAuths[0]->hmac.t.size = 0x10;

    rval = Tss2_Sys_ChangePPS( sysContext, TPM_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH );
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

    printf( "\nHIERARCHY_CHANGE_AUTH TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    newAuth.t.size = 0;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    // Init new auth
    newAuth.t.size = 20;
    for( i = 0; i < newAuth.t.size; i++ )
        newAuth.t.buffer[i] = i;

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    sessionData.hmac = newAuth;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    // Init new auth
    newAuth.t.size = 0;

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    sessionsData.cmdAuths[0] = &sessionData;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckFailed( rval, TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH );

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, 0, &sessionsData, &newAuth, 0 );
    CheckFailed( rval, TPM_RC_1 + TPM_RC_VALUE );
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

void TestPcrExtend()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    UINT16 i, digestSize;
    TPML_PCR_SELECTION  pcrSelection;
    UINT32 pcrUpdateCounterBeforeExtend;
    UINT32 pcrUpdateCounterAfterExtend;
    UINT8 pcrBeforeExtend[20];
    TPM2B_EVENT eventData;
    TPML_DIGEST pcrValues;
    TPML_DIGEST_VALUES digests;
    TPML_PCR_SELECTION pcrSelectionOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];

    printf( "\nPCR_EXTEND, PCR_EVENT, PCR_ALLOCATE, and PCR_READ TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    // Init digests
    digests.count = 1;
    digests.digests[0].hashAlg = TPM_ALG_SHA1;
    digestSize = GetDigestSize( digests.digests[0].hashAlg );

    for( i = 0; i < digestSize; i++ )
    {
        digests.digests[0].digest.sha1[i] = (UINT8)(i % 256);
    }

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM_ALG_SHA1;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;

    // Clear out PCR select bit field
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;

    // Now set the PCR you want to read
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_7 );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterBeforeExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    memcpy( &( pcrBeforeExtend[0] ), &( pcrValues.digests[0].t.buffer[0] ), pcrValues.digests[0].t.size );

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_PCR_Extend( sysContext, PCR_7, &sessionsData, &digests, 0  );
    CheckPassed( rval );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    memcpy( &( pcrAfterExtend[0] ), &( pcrValues.digests[0].t.buffer[0] ), pcrValues.digests[0].t.size );

    if( pcrUpdateCounterBeforeExtend == pcrUpdateCounterAfterExtend )
    {
        printf( "ERROR!! pcrUpdateCounter didn't change value\n" );
        Cleanup();
    }

    if( 0 == memcmp( &( pcrBeforeExtend[0] ), &( pcrAfterExtend[0] ), 20 ) )
    {
        printf( "ERROR!! PCR didn't change value\n" );
        Cleanup();
    }

    pcrSelection.pcrSelections[0].sizeofSelect = 4;

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, 0, 0, 0 );
    CheckFailed( rval, TPM_RC_1 + TPM_RC_P + TPM_RC_VALUE );

    eventData.t.size = 4;
    eventData.t.buffer[0] = 0;
    eventData.t.buffer[1] = 0xff;
    eventData.t.buffer[2] = 0x55;
    eventData.t.buffer[3] = 0xaa;

    rval = Tss2_Sys_PCR_Event( sysContext, PCR_8, &sessionsData, &eventData, &digests, 0  );
    CheckPassed( rval );
}

void TestGetRandom()
{
    UINT32 rval;
    TPM2B_DIGEST        randomBytes1, randomBytes2;

    printf( "\nGET_RANDOM TESTS:\n" );

    INIT_SIMPLE_TPM2B_SIZE( randomBytes1 );
    rval = Tss2_Sys_GetRandom( sysContext, 0, 20, &randomBytes1, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( randomBytes2 );
    rval = Tss2_Sys_GetRandom( sysContext, 0, 20, &randomBytes2, 0 );
    CheckPassed( rval );

    if( 0 == memcmp( &randomBytes1, &randomBytes2, 20 ) )
    {
        printf( "ERROR!! Random value is the same\n" );
        Cleanup();
    }
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

    printf( "\nSHUTDOWN TESTS:\n" );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_STATE, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_CLEAR, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, 0xff, 0 );
    if( tpmSpecVersion == 115 || tpmSpecVersion == 119 )
    {
        CheckFailed( rval, TPM_RC_VALUE );
    }
    else
    {
        CheckFailed( rval, TPM_RC_VALUE+TPM_RC_1+TPM_RC_P );
    }
}

void TestNVDefineCase()
{
    UINT32 rval;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;
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

    nvAuth.t.size = 0;
/*    for( int i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = (UINT8)i;
*/
	publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
//    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = 32;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );
}
void TestNVReadCase()
{
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_MAX_NV_BUFFER nvData;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    UINT32 rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
//    CheckFailed( rval, TPM_RC_NV_UNINITIALIZED );
    CheckPassed( rval );
    for (int i=0; i<nvData.t.size; i++)
    {
        printf(" %2.2x ", nvData.t.buffer[i]);
    }
}
void TestNVReadPublicCase()
{
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;
    nvPublic.t.size = 0;
    UINT32 rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );
}
void TestNVWriteCase()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_MAX_NV_BUFFER nvWriteData;

    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;
    // init hmac
    sessionData.hmac.t.size = 0;
    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    nvWriteData.t.size = 8;
    for( int i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = 0x1f - i;
    rval = Tss2_Sys_NV_Write( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckPassed(rval);
}
void TestNVUndefineCase()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionData.sessionHandle = TPM_RS_PW;
    // Init nonce.
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed(rval);
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

    printf( "\nNV INDEX TESTS:\n" );

    nvAuth.t.size = 20;
    for( i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = (UINT8)i;

	publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
//    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = 32;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_2 + TPM_RC_HANDLE );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );

    nvPublic.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_NV_UNINITIALIZED );

    // Should fail since index is already defined.
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_NV_DEFINED );

    nvWriteData.t.size = 4;
    for( i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = 0xff - i;

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
    rval = Tss2_Sys_NV_Write( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckPassed( rval );

    if (tpmType != TPM_TYPE_PTT)
    {
        rval = Tss2_Sys_NV_WriteLock( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &sessionsDataOut );
        CheckPassed( rval );

        rval = Tss2_Sys_NV_Write( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
        CheckFailed( rval, TPM_RC_NV_LOCKED );
    }
#endif

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );

    publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = 0;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 0;
    publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 0;
//    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.nvIndex = TPM20_INDEX_TEST2;
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    nvPublic.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST2, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST2, &sessionsData, 32, 0, &nvData, 0 );
    if (tpmType != TPM_TYPE_PTT)
        CheckFailed( rval, TPM_RC_NV_AUTHORIZATION );
    else
        CheckFailed( rval, TPM_RC_NV_UNINITIALIZED );

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );

#if 0
    printf( "\nStart of NVUndefineSpaceSpecial test\n" );

    // Init nonceNewer
    digestSize = GetDigestSize( TPM_ALG_SHA1 );
    nonceNewer.t.size = digestSize;
    for( i = 0; i < nonceNewer.t.size; i++ )
        nonceNewer.t.buffer[i] = 0;

    // Init salt
    salt.t.size = 0;

    // Init symmetric.
    symmetric.algorithm = TPM_ALG_NULL;
    symmetric.keyBits.sym = 0;
    symmetric.mode.sym = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvSessionNonce );
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM_RH_NULL, TPM_RH_PLATFORM, 0, &nonceNewer, &salt,
            TPM_SE_TRIAL, &symmetric, TPM_ALG_SHA1, &nvSessionHandle, &nvSessionNonce );
    CheckPassed( rval );

    nvSessionHandle = ( ( TPM20_StartAuthSession_Out *)(TpmOutBuff) )->sessionHandle;

    rval = Tss2_Sys_PolicyCommandCode ( sysContext, nvSessionHandle, 0, TPM_CC_NV_UndefineSpaceSpecial, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvAuth1 );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, nvSessionHandle, 0, &nvAuth1, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, nvSessionHandle );

    nvAuth1 = (TPM2B_AUTH *)&( ( ( TPM20_PolicyGetDigest_Out *)(TpmOutBuff) )->otherData );
    publicInfo.t.nvPublic.authPolicy.t.size = nvAuth1->t.size;
    memcpy( &( publicInfo.t.nvPublic.authPolicy.t.buffer[0] ),c
            &( nvAuth1->t.buffer[0] ),
            publicInfo.t.nvPublic.authPolicy.t.size );

    publicInfo.t.nvPublic.attributes.TPMA_NV_POLICY_DELETE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERREAD = 0;
    publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERWRITE = 0;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;

    InitNullSession( &nvSession );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvSessionNonce );
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM_RH_NULL, TPM_RH_PLATFORM, 0, &nonceCaller, &salt,
            TPM_SE_POLICY, &symmetric, TPM_ALG_SHA1, &nvSessionHandle, &nvSessionNonce );
    CheckPassed( rval );

    nvSession.sessionHandle = nvSessionHandle = ( ( TPM20_StartAuthSession_Out *)(TpmOutBuff) )->sessionHandle;

    rval = Tss2_Sys_PolicyCommandCode ( sysContext, nvSessionHandle, 0, TPM_CC_NV_UndefineSpaceSpecial, 0 );
    CheckPassed( rval );

    nvSession->hmac = publicInfo.t.nvPublic.authPolicy;

    nvSessions.cmdAuthsCount = 2;
    nvSessions.session[0] = nvSession;

    rval = Tss2_Sys_NVUndefineSpaceSpecial( sysContext, TPM20_INDEX_TEST2, TPM_RH_PLATFORM, &nvSessions, &sessionsData );
    CheckPassed( rval );
#endif
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

    printf( "\nHIERARCHY CONTROL TESTS:\n" );

    nvAuth.t.size = 20;
    for( i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = i;

	publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
//    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = 32;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Test SAPI for case where nvPublic.t.size != 0
    nvPublic.t.size = 0xff;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    nvPublic.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_NV_UNINITIALIZED );

#if 0
//    if( simulatorTest == 1 )
    {
        rval = Tss2_Sys_HierarchyControl( sysContext, TPM_RH_PLATFORM, &sessionsData, TPM_RH_PLATFORM, NO, &sessionsDataOut );
        CheckPassed( rval );

        rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut );
        CheckFailed( rval, TPM_RC_1 + TPM_RC_HIERARCHY );

        rval = Tss2_Sys_HierarchyControl( sysContext, TPM_RH_PLATFORM, &sessionsData, TPM_RH_PLATFORM, YES, &sessionsDataOut );
        CheckFailed( rval, TPM_RC_1 + TPM_RC_HIERARCHY );

        // Need to do TPM reset and Startup to re-enable platform hierarchy.
        rval = TpmReset();
        CheckPassed(rval);

        rval = Tss2_Sys_Startup ( sysContext, TPM_SU_CLEAR );
        CheckPassed( rval );

        rval = Tss2_Sys_HierarchyControl( sysContext, TPM_RH_PLATFORM, &sessionsData, TPM_RH_PLATFORM, YES, &sessionsDataOut );
        CheckPassed( rval );
    }
#endif
    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );
}
void TPM2CreatePrimary()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;

    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
	printf("\nerrorcode: 0x%x\n", rval);
    CheckPassed( rval );
}
void TPM2Create()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;

    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.sign = 1;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA1;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );
}
void TPM2Load()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );
}
void TestCreate()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name;
    TPM2B_NAME name1;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket = { 0, 0, { { sizeof( TPM2B_DIGEST ) - 2, } } };

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    printf( "\nCREATE, CREATE PRIMARY, and LOAD TESTS:\n" );

    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;

    // Do SAPI test for non-zero sized outPublic
    outPublic.t.size = 0xff;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_NULL, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

#if 0
    // Do SAPI test for non-zero sized creationData
    outPublic.t.size = 0;
    creationData.t.size = 0x10;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_BUFFER );
#endif

    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_NULL, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nNew key successfully created in NULL hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );

    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.sign = 1;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA1;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name1 );
    rval = (*HandleToNameFunctionPtr)( loadedSha1KeyHandle, &name1 );
    CheckPassed( rval );
    printf( "Name of loaded key: " );
    PrintSizedBuffer( (TPM2B *)&name1 );

    rval = CompareTPM2B( &name.b, &name1.b );
    CheckPassed( rval );

    printf( "\nLoaded key handle:  %8.8x\n", loadedSha1KeyHandle );
}

TPM_RC DefineNvIndex( TPMI_RH_PROVISION authHandle, TPMI_SH_AUTH_SESSION sessionAuthHandle, TPM2B_AUTH *auth, TPM2B_DIGEST *authPolicy,
    TPMI_RH_NV_INDEX nvIndex, TPMI_ALG_HASH nameAlg, TPMA_NV attributes, UINT16 size  )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_NV_PUBLIC publicInfo;

    // Command and response session data structures.
    TPMS_AUTH_COMMAND sessionData = { sessionAuthHandle, };
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };
    // Init nonce.
    sessionData.nonce.t.size = 0;
    // init hmac
    sessionData.hmac.t.size = 0;
    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    attributes.TPMA_NV_ORDERLY = 1;

    // Init public info structure.
    publicInfo.t.nvPublic.attributes = attributes;
    CopySizedByteBuffer( &publicInfo.t.nvPublic.authPolicy.b, &authPolicy->b );
    publicInfo.t.nvPublic.dataSize = size;
    publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = nvIndex;
    publicInfo.t.nvPublic.nameAlg = nameAlg;

    // Create the index
    rval = Tss2_Sys_NV_DefineSpace( sysContext, authHandle, &sessionsData, auth, &publicInfo, &sessionsDataOut );

    return rval;
}

typedef struct {
    char name[50];
    TPM_RC (*buildPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *trialPolicySession, TPM2B_DIGEST *policyDigest );
    TPM_RC (*createObjectFn )( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest );
    TPM_RC (*testPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession );
} POLICY_TEST_SETUP;

TPM_RC BuildPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession,
    TPM_RC (*buildPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest ),
    TPM2B_DIGEST *policyDigest, bool trialSession )
{
    // NOTE:  this policySession will be either a trial or normal policy session
    // depending on the value of the passed in trialSession parameter.
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = { {0}, };
    TPMT_SYM_DEF symmetric;
    TPM_RC rval;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    // Start policy session.
    symmetric.algorithm = TPM_ALG_NULL;
    rval = StartAuthSessionWithParams( policySession, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, trialSession ? TPM_SE_TRIAL : TPM_SE_POLICY , &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    if( rval != TPM_RC_SUCCESS )
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

TPM_RC CreateNVIndex( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPMA_LOCALITY locality;
    TPM2B_ENCRYPTED_SECRET encryptedSalt = { {0}, };
    TPMT_SYM_DEF symmetric;
    TPMA_NV nvAttributes;
    TPM2B_AUTH  nvAuth;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    // Since locality is a fairly simple command and we can guarantee
    // its correctness, we don't need a trial session for this.

    // Start real policy session
    symmetric.algorithm = TPM_ALG_NULL;
    rval = StartAuthSessionWithParams( policySession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY,
            &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    // Send PolicyLocality command
    *(UINT8 *)( (void *)&locality ) = 0;
    locality.TPM_LOC_THREE = 1;
    rval = Tss2_Sys_PolicyLocality( sysContext, (*policySession)->sessionHandle,
            0, locality, 0 );
    CheckPassed( rval );

    // Read policyHash
    INIT_SIMPLE_TPM2B_SIZE( *policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext,
            (*policySession)->sessionHandle, 0, policyDigest, 0 );
    CheckPassed( rval );

    nvAuth.t.size = 0;

    // Now set the attributes.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_POLICYREAD = 1;
    nvAttributes.TPMA_NV_POLICYWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW, &nvAuth, policyDigest,
            TPM20_INDEX_PASSWORD_TEST, TPM_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    return rval;
}


TPM_RC TestLocality( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TSS2_RC rval = TPM_RC_SUCCESS;
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
    nvWriteData.t.size = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0]->sessionHandle = policySession->sessionHandle;
    sessionsData.cmdAuths[0]->nonce.t.size = 0;
    sessionsData.cmdAuths[0]->hmac.t.size = 0;

    *(UINT8 *)( (void *)&( sessionsData.cmdAuths[0]->sessionAttributes ) ) = 0;
     sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 1;

    rval = SetLocality( sysContext, 2 );
    CheckPassed( rval );

    // Do NV write using open session's policy.
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_LOCALITY );

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
    CheckFailed( rval, TPM_RC_POLICY_FAIL + TPM_RC_S + TPM_RC_1 );

    // Delete NV index
    sessionsData.cmdAuths[0]->sessionHandle = TPM_RS_PW;
    sessionsData.cmdAuths[0]->nonce.t.size = 0;
    sessionsData.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
    sessionData.hmac.t.size = 0;

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );

    rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
    CheckPassed( rval );

    return rval;
}

UINT8 passwordPCRTestPassword[] = "password PCR";
UINT8 dataBlob[] = "some data";
TPM_HANDLE blobHandle;
TPM2B_AUTH blobAuth;

TPM_RC BuildPasswordPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TPM_RC rval = TPM_RC_SUCCESS;

    rval = Tss2_Sys_PolicyPassword( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    return rval;
}

TPM_RC BuildAuthValuePolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TPM_RC rval = TPM_RC_SUCCESS;

    rval = Tss2_Sys_PolicyAuthValue( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    return rval;
}


TPM_RC BuildPasswordPcrPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_DIGEST pcrDigest;
    TPML_PCR_SELECTION pcrs;
    TPML_DIGEST pcrValues;
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;

    pcrDigest.t.size = 0;
    rval = Tss2_Sys_PolicyPassword( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    pcrs.count = 1;
    pcrs.pcrSelections[0].hash = TPM_ALG_SHA1;
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

    rval = Tss2_Sys_PolicyPCR( sysContext, policySession->sessionHandle, 0, &pcrDigest, &pcrs, 0 );
    CheckPassed( rval );

    return rval;
}


TPM_RC CreateDataBlob( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo = { { 0, } };
    TPML_PCR_SELECTION creationPcr = { 0 };
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM_HANDLE srkHandle;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME srkName, blobName;
	TPM2B_DIGEST data;
    TPM2B_PRIVATE outPrivate;

    cmdAuth.sessionHandle = TPM_RS_PW;
    cmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.hmac.t.size = 0;

    inSensitive.t.sensitive.userAuth.t.size = 0;
    inSensitive.t.sensitive.data.t.size = 0;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CBC;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( srkName );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_OWNER, &cmdAuthArray,
            &inSensitive, &inPublic, &outsideInfo, &creationPcr,
            &srkHandle, &outPublic, &creationData, &creationHash,
            &creationTicket, &srkName, 0 );
    CheckPassed( rval );

    cmdAuth.sessionHandle = TPM_RS_PW;

    inSensitive.t.sensitive.userAuth.t.size = 0;
    blobAuth.t.size = sizeof( passwordPCRTestPassword );
    memcpy( &blobAuth.t.buffer, passwordPCRTestPassword, sizeof( passwordPCRTestPassword ) );
    CopySizedByteBuffer( &(inSensitive.t.sensitive.userAuth.b ), &blobAuth.b );
    data.t.size = sizeof( dataBlob );
    memcpy( &data.t.buffer, dataBlob, sizeof( dataBlob ) );
    CopySizedByteBuffer( &(inSensitive.t.sensitive.data.b ), &data.b );

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 0;
    CopySizedByteBuffer( &( inPublic.t.publicArea.authPolicy.b), &( policyDigest->b ) );
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
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

TPM_RC AuthValueUnseal( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_SENSITIVE_DATA outData;
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    cmdAuth.sessionHandle = policySession->sessionHandle;
    cmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.sessionAttributes.continueSession = 1;
    cmdAuth.hmac.t.size = 0;

    // Now try to unseal the blob without setting the HMAC.
    // This test should fail.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckFailed( rval, TPM_RC_S + TPM_RC_1 + TPM_RC_AUTH_FAIL );

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
            TPM_HT_NO_HANDLE, &cmdAuthArray, 1 );
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

TPM_RC PasswordUnseal( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_SENSITIVE_DATA outData;
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    cmdAuth.sessionHandle = policySession->sessionHandle;
    cmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.sessionAttributes.continueSession = 1;
    cmdAuth.hmac.t.size = 0;

    // Now try to unseal the blob without setting the password.
    // This test should fail.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckFailed( rval, TPM_RC_S + TPM_RC_1 + TPM_RC_AUTH_FAIL );

    // Clear DA lockout.
    TestDictionaryAttackLockReset();

    // Now try to unseal the blob after setting the password.
    // This test should pass.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    cmdAuth.hmac.t.size = sizeof( passwordPCRTestPassword );
    memcpy( &cmdAuth.hmac.t.buffer, passwordPCRTestPassword, sizeof( passwordPCRTestPassword ) );
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
//    { "LOCALITY", 0, CreateNVIndex, TestLocality },
    { "PASSWORD", BuildPasswordPolicy, CreateDataBlob, PasswordUnseal },
    { "PASSWORD/PCR", BuildPasswordPcrPolicy, CreateDataBlob, PasswordUnseal },
    { "AUTHVALUE", BuildAuthValuePolicy, CreateDataBlob, AuthValueUnseal },
    // TBD...
};

void TestPolicy()
{
    UINT32 rval;
    unsigned int i, num;
    SESSION *policySession;

    printf( "\nPOLICY TESTS:\n" );

    num = sizeof( policyTestSetups ) / sizeof( POLICY_TEST_SETUP );
    if (tpmType == TPM_TYPE_PTT)
        num -= 1; //skip AUTHVALUE test

    for( i = 0; i < num; i++ )
    {
        TPM2B_DIGEST policyDigest;
        INIT_SIMPLE_TPM2B_SIZE( policyDigest );
        rval = TPM_RC_SUCCESS;

        printf( "Policy Test: %s\n", policyTestSetups[i].name );

        // Create trial policy session and run policy commands, in order to create policyDigest.
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, true );
            CheckPassed( rval );
        }
        // Create entity that will use that policyDigest as authPolicy.
        if( policyTestSetups[i].createObjectFn != 0 )
        {
            rval = ( *policyTestSetups[i].createObjectFn )( sysContext, &policySession, &policyDigest);
            CheckPassed( rval );
        }

        // Create real policy session and run policy commands; after this we're ready
        // to authorize actions on the entity.
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, false );
            CheckPassed( rval );
        }
        // Now do tests by authorizing actions on the entity.
        rval = ( *policyTestSetups[i].testPolicyFn)( sysContext, policySession );
        CheckPassed( rval );

        // Need to flush the session here.
        rval = Tss2_Sys_FlushContext( sysContext, policySession->sessionHandle );
        CheckPassed( rval );

        // And remove the session from test app session table.
        rval = EndAuthSession( policySession );
        CheckPassed( rval );
    }
}

#define MAX_TEST_SEQUENCES 10
void TestHash()
{
    UINT32 rval;
    TPM2B_AUTH      auth;
    TPMI_DH_OBJECT  sequenceHandle[MAX_TEST_SEQUENCES];
    TPMS_AUTH_COMMAND sessionData, sessionData1;
    TPMS_AUTH_RESPONSE sessionDataOut, sessionDataOut1;
    TSS2_SYS_CMD_AUTHS sessionsData;
    int i;
    TPM2B_MAX_BUFFER dataToHash;

    UINT8           memoryToHash[] =
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
          0xde, 0xad, 0xbe, 0xef
    };

    // Known good hash of above memory.
    UINT8           goodHashValue[] =
            { 0xB3, 0xFD, 0x6A, 0xD2, 0x9F, 0xD0, 0x13, 0x52, 0xBA, 0xFC,
              0x8B, 0x22, 0xC9, 0x6D, 0x88, 0x42, 0xA3, 0x3C, 0xB0, 0xC9 };

    // Hash to be calculated by TPM.
    TPM2B_DIGEST result;
    TPMT_TK_HASHCHECK validation;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[2];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[2];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;
    sessionDataArray[1] = &sessionData1;
    sessionDataOutArray[1] = &sessionDataOut1;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    printf( "\nHASH TESTS:\n" );

    auth.t.size = 2;
    auth.t.buffer[0] = 0;
    auth.t.buffer[1] = 0xff;
    rval = Tss2_Sys_HashSequenceStart ( sysContext, 0, &auth, TPM_ALG_SHA1, &sequenceHandle[0], 0 );
    CheckPassed( rval );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac = auth;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    dataToHash.t.size = MAX_DIGEST_BUFFER;
    memcpy( &dataToHash.t.buffer[0], &memoryToHash[0], dataToHash.t.size );

    rval = Tss2_Sys_SequenceUpdate ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash, &sessionsDataOut );
    CheckPassed( rval );

    // Now try starting a bunch of sequences to see what happens.
    // This checks that the resource manager properly saves and restores the context
    // of the interrupted original sequence.
    for( i = 1; i < 5; i++ )
    {
        rval = Tss2_Sys_HashSequenceStart ( sysContext, 0, &auth, TPM_ALG_SHA1, &sequenceHandle[i], 0 );
        CheckPassed( rval );
    }

    // Now end the created sequences.
    dataToHash.t.size = 0;
    for( i = 1; i < 5; i++ )
    {
        INIT_SIMPLE_TPM2B_SIZE( result );
        rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle[i], &sessionsData, &dataToHash,
                TPM_RH_PLATFORM, &result, &validation, &sessionsDataOut );
        CheckPassed( rval );
    }

    //  Now try to finish the interrupted sequence.
    rval = Tss2_Sys_SequenceUpdate ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash, &sessionsDataOut );
    CheckPassed( rval );

    dataToHash.t.size = sizeof( memoryToHash ) - MAX_DIGEST_BUFFER;
    memcpy( &dataToHash.t.buffer[0], &memoryToHash[MAX_DIGEST_BUFFER], dataToHash.t.size );
    INIT_SIMPLE_TPM2B_SIZE( result );
    rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash,
            TPM_RH_PLATFORM, &result, &validation, &sessionsDataOut );
    CheckPassed( rval );

    // Test the resulting hash.
    if( memcmp( (void *)&( result.t.buffer[0] ), (void *)&( goodHashValue[0] ), result.t.size ) )
    {
        printf( "ERROR!! resulting hash is incorrect.\n" );
        Cleanup();
    }

    // Now try starting a bunch of sequences to see what happens.
    // This stresses the resource manager.
    for( i = 0; i < MAX_TEST_SEQUENCES; i++ )
    {
        rval = Tss2_Sys_HashSequenceStart ( sysContext, 0, &auth, TPM_ALG_SHA1, &sequenceHandle[i], 0 );
        CheckPassed( rval );
    }

    // Now end them all
    dataToHash.t.size = 0;
    for( i = (MAX_TEST_SEQUENCES - 1); i >= 0; i-- )
//    for( i = 0; i < MAX_TEST_SEQUENCES; i++ )
    {
        INIT_SIMPLE_TPM2B_SIZE( result );
        rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle[i], &sessionsData, &dataToHash,
                TPM_RH_PLATFORM, &result, &validation, &sessionsDataOut );
        CheckPassed( rval );
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

    printf( "\nQUOTE CONTROL TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    qualifyingData.t.size = sizeof( qualDataString );
    memcpy( &( qualifyingData.t.buffer[0] ), qualDataString, sizeof( qualDataString ) );

    inScheme.scheme = TPM_ALG_NULL;

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM_ALG_SHA1;
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

    printf( "\nPROVISION OTHER NV INDICES:\n" );

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
    rval = Tss2_Sys_PolicyGetDigest( sysContext, otherIndicesPolicyAuthHandle, 0, &nvPolicyHash, 0 );
    CheckPassed( rval );

    // Now save the policy digest from the first OR branch.
    DEBUG_PRINT_BUFFER( NO_PREFIX, &( nvPolicyHash.t.buffer[0] ), nvPolicyHash.t.size );

    // 4.  CreateNvIndex
    otherIndicesSessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    otherIndicesSessionData.nonce.t.size = 0;

    // init hmac
    otherIndicesSessionData.hmac.t.size = 0;

    // init nvAuth
    nvAuth.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&otherIndicesSessionData.sessionAttributes ) ) = 0;

    publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = INDEX_LCP_SUP;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    // Following commented out for convenience during development.
    // publicInfo.t.nvPublic.attributes.TPMA_NV_POLICY_DELETE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_WRITEDEFINE = 1;
//    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;

    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = NV_PS_INDEX_SIZE;

    otherIndicesSessionsData.cmdAuthsCount = 1;
    otherIndicesSessionsData.cmdAuths[0] = &otherIndicesSessionData;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &otherIndicesSessionsData,
            &nvAuth, &publicInfo, &otherIndicesSessionsDataOut );
    CheckPassed( rval );

    publicInfo.t.nvPublic.nvIndex = INDEX_LCP_OWN;
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &otherIndicesSessionsData,
            &nvAuth, &publicInfo, &otherIndicesSessionsDataOut );
    CheckPassed( rval );

    // Now teardown session
    rval = Tss2_Sys_FlushContext( sysContext, otherIndicesPolicyAuthHandle );
    CheckPassed( rval );
}


TSS2_RC InitNvAuxPolicySession( TPMI_SH_AUTH_SESSION *nvAuxPolicySessionHandle )
{
    TPMA_LOCALITY locality;
    TPM_RC rval;

    rval = StartPolicySession( nvAuxPolicySessionHandle );
    CheckPassed( rval );

    // 2.  PolicyLocality(3)
    *(UINT8 *)((void *)&locality) = 0;
    locality.TPM_LOC_ONE = 1;
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

    printf( "\nPROVISION NV AUX:\n" );

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
    DEBUG_PRINT_BUFFER( NO_PREFIX, &( nvPolicyHash.t.buffer[0] ), nvPolicyHash.t.size );

    // 4.  CreateNvIndex
    nvAuxSessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    nvAuxSessionData.nonce.t.size = 0;

    // init hmac
    nvAuxSessionData.hmac.t.size = 0;

    // init nvAuth
    nvAuth.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&nvAuxSessionData.sessionAttributes ) ) = 0;

    nvAuxSessionsData.cmdAuthsCount = 1;
    nvAuxSessionsData.cmdAuths[0] = &nvAuxSessionData;

    publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = INDEX_AUX;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_POLICYWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    // Following commented out for convenience during development.
    // publicInfo.t.nvPublic.attributes.TPMA_NV_POLICY_DELETE = 1;

    publicInfo.t.nvPublic.authPolicy.t.size = GetDigestSize( TPM_ALG_SHA1 );
    memcpy( (UINT8 *)&( publicInfo.t.nvPublic.authPolicy.t.buffer ), (UINT8 *)&(nvPolicyHash.t.buffer[0]),
            nvPolicyHash.t.size );

    publicInfo.t.nvPublic.dataSize = NV_AUX_INDEX_SIZE;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &nvAuxSessionsData,
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
    nvWriteData.t.size = 4;
    for( i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = 0xff - i;

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
        CheckFailed( rval, TPM_RC_LOCALITY );

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

    printf( "TPM AUX READ/WRITE TEST\n" );

    nullSessionData.sessionAttributes.continueSession = 0;

    // Try writing it from all localities.  Only locality 3 should work.
    for( testLocality = 0; testLocality < 5; testLocality++ )
    {
        TpmAuxWrite( testLocality );
    }

    nullSessionData.sessionHandle = TPM_RS_PW;

    nullSessionsData.cmdAuths[0] = &nullSessionData;

    // Try reading it from all localities.  They all should work.
    for( testLocality = 0; testLocality < 5; testLocality++ )
    {
        rval = SetLocality( sysContext, testLocality );
        CheckPassed( rval );

        INIT_SIMPLE_TPM2B_SIZE( nvData );
        rval = Tss2_Sys_NV_Read( sysContext, INDEX_AUX, INDEX_AUX, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut );
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

    nullSessionData.sessionHandle = TPM_RS_PW;

    printf( "TPM OTHER READ/WRITE TEST\n" );

    nvWriteData.t.size = 4;
    for( i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = 0xff - i;

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

    printf( "\nNV INDEX PROTOTYPE TESTS:\n" );


    // AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer
    // PS index: Write and read are unrestricted until TPM2_WriteLock. After that content is write protected
    // PO index: Write is restricted by ownerAuth; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer

    // Now we need to configure NV indices
    ProvisionNvAux();

    ProvisionOtherIndices();

//    TpmAuxReadWriteTest();

    TpmOtherIndicesReadWriteTest();

    // Now undefine the aux index, so that subsequent test passes will work.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, INDEX_AUX, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );

    // Now undefine the other indices, so that subsequent test passes will work.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, INDEX_LCP_SUP, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, INDEX_LCP_OWN, &nullSessionsData, &nullSessionsDataOut );
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

    printf( "\nPCR ALLOCATE TEST  :\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    pcrSelection.count = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_PCR_Allocate( sysContext, TPM_RH_PLATFORM, &sessionsData, &pcrSelection,
            &allocationSuccess, &maxPcr, &sizeNeeded, &sizeAvailable, &sessionsDataOut);
    CheckPassed( rval );

    pcrSelection.count = /*3*/1;
    pcrSelection.pcrSelections[0].hash = TPM_ALG_SHA256;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[0] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[0], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_5 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_7 );
/*    pcrSelection.pcrSelections[1].hash = TPM_ALG_SHA384;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[1] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[1], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[1], PCR_5 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[1], PCR_8 );
    pcrSelection.pcrSelections[2].hash = TPM_ALG_SHA256;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[2] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[2], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[2], PCR_6 );*/

    rval = Tss2_Sys_PCR_Allocate( sysContext, TPM_RH_PLATFORM, &sessionsData, &pcrSelection,
            &allocationSuccess, &maxPcr, &sizeNeeded, &sizeAvailable, &sessionsDataOut);
    CheckPassed( rval );
}
/*
void UnsealCreateCase()
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
    TPM_HANDLE loadedObjectHandle;

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

//    printf( "\nUNSEAL TEST  :\n" );

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    inSensitive.t.sensitive.userAuth.t.size = sizeof( authStr ) - 1;
    memcpy( &( inSensitive.t.sensitive.userAuth.t.buffer[0] ), authStr, sizeof( authStr ) - 1 );
    inSensitive.t.sensitive.data.t.size = sizeof( sensitiveData ) - 1;
    memcpy( &( inSensitive.t.sensitive.data.t.buffer[0] ), sensitiveData, sizeof( sensitiveData ) - 1 );

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0]  = &sessionData;

    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );
}
void UnsealLoadExternal()
{
    UINT32 rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );
    CheckPassed( rval );
}
void UnsealFlushContext()
{
    UINT32 rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );
    CheckPassed( rval );
}
void UnsealLoad()
{
    UINT32 rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedObjectHandle, &name, &sessionsDataOut);
    CheckPassed( rval );
}
void UnsealUnseal()
{
    sessionData.hmac.t.size = sizeof( authStr ) - 1;
    memcpy( &( sessionData.hmac.t.buffer[0] ), authStr, sizeof( authStr ) - 1 );

    UINT32 rval = Tss2_Sys_Unseal( sysContext, loadedObjectHandle, &sessionsData, &outData, &sessionsDataOut );
    rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );
    CheckPassed( rval );
    CheckPassed( rval );
}*/
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
    TPM_HANDLE loadedObjectHandle;

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

    printf( "\nUNSEAL TEST  :\n" );

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    inSensitive.t.sensitive.userAuth.t.size = sizeof( authStr ) - 1;
    memcpy( &( inSensitive.t.sensitive.userAuth.t.buffer[0] ), authStr, sizeof( authStr ) - 1 );
    inSensitive.t.sensitive.data.t.size = sizeof( sensitiveData ) - 1;
    memcpy( &( inSensitive.t.sensitive.data.t.buffer[0] ), sensitiveData, sizeof( sensitiveData ) - 1 );

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0]  = &sessionData;

    outPublic.t.size = 0;
    creationData.t.size = 0;
    outsideInfo.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_LoadExternal ( sysContext, 0, 0, &outPublic,
            TPM_RH_OWNER, &loadedObjectHandle, &name, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedObjectHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    sessionData.hmac.t.size = sizeof( authStr ) - 1;
    memcpy( &( sessionData.hmac.t.buffer[0] ), authStr, sizeof( authStr ) - 1 );

    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, loadedObjectHandle, &sessionsData, &outData, &sessionsDataOut );

    rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle );
    CheckPassed( rval );

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

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsDataOut.rspAuthsCount = 1;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    nvAuth.t.size = strlen( password );
    for( i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = password[i];

	publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = nvIndex;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
//    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = 32;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM,
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

    printf( "\nPASSWORD TESTS:\n" );

    // Create an NV index that will use password
    // authorizations the password will be
    // "test password".
    CreatePasswordTestNV( TPM20_INDEX_PASSWORD_TEST, password );

    //
    // Initialize the command authorization area.
    //

    // Init sessionHandle, nonce, session
    // attributes, and hmac (password).
    sessionData.sessionHandle = TPM_RS_PW;
    // Set zero sized nonce.
    sessionData.nonce.t.size = 0;
    // sessionAttributes is a bit field.  To initialize
    // it to 0, cast to a pointer to UINT8 and
    // write 0 to that pointer.
    *( (UINT8 *)&sessionData.sessionAttributes ) = 0;

    // Init password (HMAC field in authorization structure).
    sessionData.hmac.t.size = strlen( password );
    memcpy( &( sessionData.hmac.t.buffer[0] ),
            &( password[0] ), sessionData.hmac.t.size );

    // Initialize write data.
    nvWriteData.t.size = 4;
    for( i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = 0xff - i;

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
    sessionData.hmac.t.buffer[4] = 0xff;
    rval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0,
            &sessionsDataOut );
    // Check that the function failed as expected,
    // since password was incorrect.  If wrong
    // response code received, exit.
    CheckFailed( rval,
            TPM_RC_S + TPM_RC_1 + TPM_RC_AUTH_FAIL );

    // Change hmac to null one, since null auth is
    // used to undefine the index.
    sessionData.hmac.t.size = 0;

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );
}


void SimplePolicyTest()
{
    UINT32 rval, sessionCmdRval;
    TPM2B_AUTH  nvAuth;
    SESSION *nvSession, *trialPolicySession;
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
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM_RS_PW, };
    TPMS_AUTH_COMMAND *nvCmdAuthArray[1] = { &nvCmdAuth };
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 1, &nvCmdAuthArray[0] };

    // Response authorization area.
    TPMS_AUTH_RESPONSE nvRspAuth;
    TPMS_AUTH_RESPONSE *nvRspAuthArray[1] = { &nvRspAuth };
    TSS2_SYS_RSP_AUTHS nvRspAuths = { 1, &nvRspAuthArray[0] };
    TPM_ALG_ID sessionAlg = TPM_ALG_SHA256;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    printf( "\nSIMPLE POLICY TEST:\n" );

    //
    // Create NV index.
    //

    // Setup the NV index's authorization value.
    nvAuth.t.size = 0;

    // Zero sized encrypted salt, since the session
    // is unsalted.
    encryptedSalt.t.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM_ALG_NULL;

    //
    // Create the NV index's authorization policy
    // using a trial policy session.
    //
    rval = StartAuthSessionWithParams( &trialPolicySession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM_SE_TRIAL,
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
    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            sessionAlg, nvAttributes, 32  );
    CheckPassed( rval );

    // Add index and associated authorization value to
    // entity table.  This helps when we need
    // to calculate HMACs.
    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    // Get the name of the NV index.
    rval = (*HandleToNameFunctionPtr)( TPM20_INDEX_PASSWORD_TEST,
            &nvName );
    CheckPassed( rval );

    //
    // Start real (non-trial) policy authorization session:
    // it's an unbound and unsalted session, no symmetric
    // encryption algorithm, and SHA256 is the session's
    // hash algorithm.
    //

    // Zero sized encrypted salt, since the session
    // is unsalted.
    encryptedSalt.t.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM_ALG_NULL;

    // Create the session.
    // Session state (session handle, nonces, etc.) gets
    // saved into nvSession structure for later use.
    rval = StartAuthSessionWithParams( &nvSession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY,
            &symmetric, sessionAlg, resMgrTctiContext );
    CheckPassed( rval );

    // Get the name of the session and save it in
    // the nvSession structure.
    rval = (*HandleToNameFunctionPtr)( nvSession->sessionHandle,
            &nvSession->name );
    CheckPassed( rval );

    // Initialize NV write data.
    nvWriteData.t.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.t.size; i++ )
    {
        nvWriteData.t.buffer[i] = dataToWrite[i];
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
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 1;
    nvCmdAuths.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
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
            TPM_RC_FAILURE );
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

    if( sessionCmdRval == TPM_RC_SUCCESS )
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
            TPM_RC_FAILURE );
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

    if( sessionCmdRval == TPM_RC_SUCCESS )
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
    if( memcmp( (void *)&nvReadData.t.buffer[0],
            (void *)&nvWriteData.t.buffer[0], nvReadData.t.size ) )
    {
        printf( "ERROR!! read data not equal to written data\n" );
        Cleanup();
    }

    //
    // Now cleanup:  undefine the NV index and delete
    // the NV index's entity table entry.
    //

    // Setup authorization for undefining the NV index.
    nvCmdAuths.cmdAuths[0]->sessionHandle = TPM_RS_PW;
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 0;
    nvCmdAuths.cmdAuths[0]->hmac.t.size = 0;

    // Undefine the NV index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext,
            TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
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
    SESSION *nvSession;
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
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM_RS_PW, };
    TPMS_AUTH_COMMAND *nvCmdAuthArray[1] = { &nvCmdAuth };
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 1, &nvCmdAuthArray[0] };

    // Response authorization area.
    TPMS_AUTH_RESPONSE nvRspAuth;
    TPMS_AUTH_RESPONSE *nvRspAuthArray[1] = { &nvRspAuth };
    TSS2_SYS_RSP_AUTHS nvRspAuths = { 1, &nvRspAuthArray[0] };
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    printf( "\nSIMPLE HMAC SESSION TEST:\n" );

    //
    // Create NV index.
    //

    // Setup the NV index's authorization value.
    nvAuth.t.size = strlen( sharedSecret );
    for( i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = sharedSecret[i];

    // Set NV index's authorization policy
    // to zero sized policy since we won't be
    // using policy to authorize.
    authPolicy.t.size = 0;

    // Now set the NV index's attributes:
    // policyRead, authWrite, and platormCreate.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_AUTHREAD = 1;
    nvAttributes.TPMA_NV_AUTHWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // Create the NV index.
    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            TPM_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    // Add index and associated authorization value to
    // entity table.  This helps when we need
    // to calculate HMACs.
    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    // Get the name of the NV index.
    rval = (*HandleToNameFunctionPtr)( TPM20_INDEX_PASSWORD_TEST,
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
    encryptedSalt.t.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM_ALG_NULL;

    // Create the session.
    // Session state (session handle, nonces, etc.) gets
    // saved into nvSession structure for later use.
    rval = StartAuthSessionWithParams( &nvSession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    // Get the name of the session and save it in
    // the nvSession structure.
    rval = (*HandleToNameFunctionPtr)( nvSession->sessionHandle,
            &nvSession->name );
    CheckPassed( rval );

    // Initialize NV write data.
    nvWriteData.t.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.t.size; i++ )
    {
        nvWriteData.t.buffer[i] = dataToWrite[i];
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
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 1;
    nvCmdAuths.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
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
            TPM_RC_FAILURE );
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

    if( sessionCmdRval == TPM_RC_SUCCESS )
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
            TPM_RC_FAILURE );
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

    if( sessionCmdRval == TPM_RC_SUCCESS )
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
    if( memcmp( (void *)&nvReadData.t.buffer[0],
            (void *)&nvWriteData.t.buffer[0], nvReadData.t.size ) )
    {
        printf( "ERROR!! read data not equal to written data\n" );
        Cleanup();
    }

    //
    // Now cleanup:  undefine the NV index and delete
    // the NV index's entity table entry.
    //

    // Setup authorization for undefining the NV index.
    nvCmdAuths.cmdAuths[0]->sessionHandle = TPM_RS_PW;
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 0;
    nvCmdAuths.cmdAuths[0]->hmac.t.size = 0;

    // Undefine the NV index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext,
            TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, 0 );
    CheckPassed( rval );

    // Delete the NV index's entry in the entity table.
    rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
    CheckPassed( rval );

    rval = EndAuthSession( nvSession );

    CheckPassed( rval );
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
    TPM_SE tpmSe;
    char *testString;
    char testStringHmac[] = "HMAC";
    char testStringPolicy[] = "POLICY";

    // Command authorization area: one password session.
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM_RS_PW, };
    TPMS_AUTH_COMMAND *nvCmdAuthArray[1] = { &nvCmdAuth };
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 1, &nvCmdAuthArray[0] };

    // Response authorization area.
    TPMS_AUTH_RESPONSE nvRspAuth;
    TPMS_AUTH_RESPONSE *nvRspAuthArray[1] = { &nvRspAuth };
    TSS2_SYS_RSP_AUTHS nvRspAuths = { 1, &nvRspAuthArray[0] };

    TSS2_SYS_CONTEXT *simpleTestContext;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    if( hmacTest )
        testString = testStringHmac;
    else
        testString = testStringPolicy;

    printf( "\nSIMPLE %s SESSION TEST:\n", testString );

    // Create sysContext structure.
    simpleTestContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( simpleTestContext == 0 )
    {
        InitSysContextFailure();
    }

    // Setup the NV index's authorization value.
    nvAuth.t.size = strlen( sharedSecret );
    for( i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = sharedSecret[i];

    //
    // Create NV index.
    //
    if( hmacTest )
    {
        // Setup the NV index's authorization value.
        nvAuth.t.size = strlen( sharedSecret );
        for( i = 0; i < nvAuth.t.size; i++ )
            nvAuth.t.buffer[i] = sharedSecret[i];

        // Set NV index's authorization policy
        // to zero sized policy since we won't be
        // using policy to authorize.

        authPolicy.t.size = 0;
    }
    else
    {
        // Zero sized encrypted salt, since the session
        // is unsalted.

        encryptedSalt.t.size = 0;

        // No symmetric algorithm.
        symmetric.algorithm = TPM_ALG_NULL;

        //
        // Create the NV index's authorization policy
        // using a trial policy session.
        //
        rval = StartAuthSessionWithParams( &trialPolicySession,
                TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt,
                TPM_SE_TRIAL,
                &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
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
    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            TPM_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    // Add index and associated authorization value to
    // entity table.  This helps when we need
    // to calculate HMACs.
    AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
    CheckPassed( rval );

    // Get the name of the NV index.
    rval = (*HandleToNameFunctionPtr)(
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
    encryptedSalt.t.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM_ALG_NULL;

    // Create the session, hmac or policy depending
    // on hmacTest.
    // Session state (session handle, nonces, etc.) gets
    // saved into nvSession structure for later use.
    if( hmacTest )
        tpmSe = TPM_SE_HMAC;
    else
        tpmSe = TPM_SE_POLICY;

    rval = StartAuthSessionWithParams( &nvSession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, tpmSe,
            &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    // Get the name of the session and save it in
    // the nvSession structure.
    rval = (*HandleToNameFunctionPtr)( nvSession->sessionHandle,
            &(nvSession->name) );
    CheckPassed( rval );

    // Initialize NV write data.
    nvWriteData.t.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.t.size; i++ )
    {
        nvWriteData.t.buffer[i] = dataToWrite[i];
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
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 1;
    nvCmdAuths.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
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
            TPM_RC_FAILURE );
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

    if( sessionCmdRval == TPM_RC_SUCCESS )
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
            TPM_RC_FAILURE );
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

    if( sessionCmdRval == TPM_RC_SUCCESS )
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
    if( memcmp( (void *)&nvReadData.t.buffer[0],
            (void *)&nvWriteData.t.buffer[0], nvReadData.t.size ) )
    {
        printf( "ERROR!! read data not equal to written data\n" );
        Cleanup();
    }

    //
    // Now cleanup:  undefine the NV index and delete
    // the NV index's entity table entry.
    //

    // Setup authorization for undefining the NV index.
    nvCmdAuths.cmdAuths[0]->sessionHandle = TPM_RS_PW;
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 0;
    nvCmdAuths.cmdAuths[0]->hmac.t.size = 0;

    // Undefine the NV index.
    rval = Tss2_Sys_NV_UndefineSpace( simpleTestContext,
            TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
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


typedef struct {
    TPMI_DH_OBJECT tpmKey;
    TPMI_DH_ENTITY bound;
    TPM2B_MAX_BUFFER *salt;
    char hmacTestDescription[50];
} HMAC_TEST_SETUP;

TPM2B_MAX_BUFFER nullSalt = { { 0, { 0xa4 } }, };
TPM2B_MAX_BUFFER nonNullSalt = { { 2, { 0xa5, 0 } } };

HMAC_TEST_SETUP hmacTestSetups[] =
{
    { TPM_RH_NULL, TPM_RH_NULL, &nullSalt, "UNBOUND/UNSALTED SESSION TEST" },
    { TPM_RH_NULL, TPM20_INDEX_PASSWORD_TEST, &nullSalt, "BOUND SESSION TEST" },
    { 0, TPM_RH_NULL, &nonNullSalt, "SALTED SESSION TEST" },
    { 0, TPM20_INDEX_PASSWORD_TEST, &nonNullSalt, "BOUND/SALTED SESSION TEST" },
};

#define PLAINTEXT_SESSION 0
#define DECRYPT_SESSION 1
#define ENCRYPT_SESSION 2

//UINT8 decryptEncryptSetups[] = { PLAINTEXT_SESSION, DECRYPT_SESSION, ENCRYPT_SESSION };
UINT8 decryptEncryptSetups[] = { PLAINTEXT_SESSION };

#define CFB_MODE 0
#define XOR_MODE 1

void HmacSessionTest()
{
    UINT32 rval;
    unsigned int i, j, k, decryptEncryptMode;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    UINT8 dataToWrite[] = { 0x00, 0xff, 0x55, 0xaa };
    TPM2B_NAME nvName;
    TPM_RC sessionCmdRval;

    SESSION *nvSession;
    TSS2_SYS_CONTEXT *rdSysContext;
    TSS2_SYS_CONTEXT *wrSysContext;
    TPM2B_AUTH  nvAuth;
    TPMT_SYM_DEF symmetric;
    TPM2B_NONCE nonceOlder;

    // Create two sysContext structures.
    rdSysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( rdSysContext == 0 )
    {
        InitSysContextFailure();
    }

    wrSysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( wrSysContext == 0 )
    {
        InitSysContextFailure();
    }

    char sharedSecret[] = "shared secret";

    char buffer1contents[] = "test";
    char buffer2contents[] = "string";

    TPM2B_MAX_BUFFER buffer1;
    TPM2B_MAX_BUFFER buffer2;

//    TPM2B_IV ivIn, ivOut;
    TPM2B_MAX_NV_BUFFER nvData;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;

    encryptedSalt.t.size = 0;
//    ivIn.t.size = 0;
//    ivOut.t.size = 0;

    buffer1.t.size = strlen( buffer1contents );
    memcpy (buffer1.t.buffer, buffer1contents, buffer1.t.size );
    buffer2.t.size = strlen( buffer2contents );
    memcpy (buffer2.t.buffer, buffer2contents, buffer2.t.size );


    for( j = 0; j < sizeof( hmacTestSetups ) / sizeof( HMAC_TEST_SETUP ); j++ )
    {
        if( hmacTestSetups[j].salt == &nonNullSalt )
        {
            hmacTestSetups[j].tpmKey = handle2048rsa;
        }
    }
    printf( "\nHMAC SESSION TESTS:\n" );

    for( j = 0; j < sizeof( hmacTestSetups ) / sizeof( HMAC_TEST_SETUP ); j++ )
    {
        // Iterate through variations of decrypt and encrypt sessions.
        for( k = 0; k < sizeof( decryptEncryptSetups ); k++ )
        {
            for( decryptEncryptMode = CFB_MODE; decryptEncryptMode < XOR_MODE; decryptEncryptMode++ )
            {
                TPMS_AUTH_COMMAND sessionData = { TPM_RS_PW, };
                TPMS_AUTH_RESPONSE sessionDataOut;
                TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
                TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
                TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
                TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };

                TPMT_RSA_DECRYPT  inScheme;
                TPM2B_DATA label;
                TPM2B_DIGEST authPolicy;
                TPMA_NV nvAttributes;

                printf( "\n\n%s:\n", hmacTestSetups[j].hmacTestDescription );

                if( hmacTestSetups[j].tpmKey != TPM_RH_NULL )
                {
                    sessionsData.cmdAuths[0]->hmac = loadedSha1KeyAuth;
                    sessionsData.cmdAuths[0]->sessionHandle = TPM_RS_PW;
                    sessionsData.cmdAuths[0]->nonce.t.size = 0;
                    *( (UINT8 *)(&sessionData.sessionAttributes ) ) = 0;

                    inScheme.scheme = TPM_ALG_OAEP;
                    inScheme.details.oaep.hashAlg = TPM_ALG_SHA1;
                    memcpy( &( label.b.buffer ), "SECRET", 1 + strlen( "SECRET" ) );
                    label.t.size = strlen( "SECRET" ) + 1;

                    // Encrypt salt with tpmKey.
                    INIT_SIMPLE_TPM2B_SIZE( encryptedSalt );
                    rval = Tss2_Sys_RSA_Encrypt( sysContext, handle2048rsa,
                            0, (TPM2B_PUBLIC_KEY_RSA *)( hmacTestSetups[j].salt ),
                            &inScheme, &label, (TPM2B_PUBLIC_KEY_RSA *)&encryptedSalt, 0 );
                    CheckPassed( rval );
                }

                // init hmac
                sessionData.hmac.t.size = 0;

                // NOW CREATE THE INDEX
                authPolicy.t.size = 0;

                nvAuth.t.size = strlen( sharedSecret );
                for( i = 0; i < nvAuth.t.size; i++ )
                    nvAuth.t.buffer[i] = sharedSecret[i];

                // Now set the attributes.
                *(UINT32 *)( &nvAttributes ) = 0;
                nvAttributes.TPMA_NV_AUTHREAD = 1;
                nvAttributes.TPMA_NV_AUTHWRITE = 1;
                nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

                rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW, &nvAuth, &authPolicy,
                        TPM20_INDEX_PASSWORD_TEST, TPM_ALG_SHA1, nvAttributes, 32  );
                CheckPassed( rval );

                AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth );
                CheckPassed( rval );

                // Get the name using TPM function.
                rval = (*HandleToNameFunctionPtr)( TPM20_INDEX_PASSWORD_TEST, &nvName );
                CheckPassed( rval );

                //
                // Start session
                //
                nonceOlder.t.size = GetDigestSize( TPM_ALG_SHA1 );
                for( i = 0; i < nonceOlder.t.size; i++ )
                    nonceOlder.t.buffer[i] = 0;

                if( decryptEncryptSetups[k] == PLAINTEXT_SESSION )
                {
                    symmetric.algorithm = TPM_ALG_NULL;
                }
                else if( decryptEncryptSetups[k] == DECRYPT_SESSION || decryptEncryptSetups[k] == ENCRYPT_SESSION )
                {
                    if( decryptEncryptMode == CFB_MODE )
                    {
                        symmetric.algorithm = TPM_ALG_AES;
                        symmetric.keyBits.aes = 128;
                        symmetric.mode.aes = TPM_ALG_CFB;
                    }
                    else if( decryptEncryptMode == XOR_MODE )
                    {
                        symmetric.algorithm = TPM_ALG_XOR;
                        symmetric.keyBits.exclusiveOr = TPM_ALG_SHA256;
                    }
                }

                rval = StartAuthSessionWithParams( &nvSession, hmacTestSetups[j].tpmKey,
                        hmacTestSetups[j].salt, hmacTestSetups[j].bound, &nvAuth, &nonceOlder, &encryptedSalt,
                        TPM_SE_HMAC, &symmetric, TPM_ALG_SHA1, resMgrTctiContext );
                CheckPassed( rval );

                // Get and print name of the session.
                rval = (*HandleToNameFunctionPtr)( nvSession->sessionHandle, &nvSession->name );
                CheckPassed( rval );
                printf( "Name of authSession: " );
                PrintSizedBuffer( (TPM2B *)&nvSession->name );

                // Init write data.
                nvWriteData.t.size = sizeof( dataToWrite );

                for( i = 0; i < nvWriteData.t.size; i++ )
                {
                    nvWriteData.t.buffer[i] = dataToWrite[i];
                }

                if( decryptEncryptSetups[k] == DECRYPT_SESSION )
                {
                    if( decryptEncryptMode == CFB_MODE )
                    {
//                        rval = EncryptCFB( &nvSession, &( nvWriteData.b ) );
                    }
                    else if( decryptEncryptMode == XOR_MODE )
                    {
//                        rval = EncryptXOR( &nvSession, &( nvWriteData.b ) );
                    }
                    sessionsData.cmdAuths[0]->sessionAttributes.decrypt = 1;
                }
                else
                {
                    sessionsData.cmdAuths[0]->sessionAttributes.decrypt = 0;
                }
                sessionsData.cmdAuths[0]->sessionAttributes.encrypt = 0;

                CheckPassed( rval );

                sessionsData.cmdAuths[0]->sessionHandle = nvSession->sessionHandle;
                sessionsData.cmdAuths[0]->nonce.t.size = 1;
                sessionsData.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;

                // Roll nonces for command
                RollNonces( nvSession, &sessionsData.cmdAuths[0]->nonce );

                // Now try writing with bad HMAC.
                rval = Tss2_Sys_NV_Write_Prepare( wrSysContext, TPM20_INDEX_PASSWORD_TEST,
                        TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
                CheckPassed( rval );

                rval = ComputeCommandHmacs( wrSysContext,
                        TPM20_INDEX_PASSWORD_TEST,
                        TPM20_INDEX_PASSWORD_TEST, &sessionsData, TPM_RC_FAILURE );
                CheckPassed( rval );

                // Diddle with HMAC to force failure
                sessionsData.cmdAuths[0]->hmac.t.buffer[0] =
                        ~( sessionsData.cmdAuths[0]->hmac.t.buffer[0] );

                sessionCmdRval = Tss2_Sys_NV_Write( wrSysContext, TPM20_INDEX_PASSWORD_TEST,
                        TPM20_INDEX_PASSWORD_TEST,
                        &sessionsData, &nvWriteData, 0, &sessionsDataOut );
                CheckFailed( sessionCmdRval, TPM_RC_S + TPM_RC_1 + TPM_RC_AUTH_FAIL );

                // Since command failed, no need to roll nonces.

                TestDictionaryAttackLockReset();

                // Now try writing with good HMAC.

                // Do stage 1 of NVRead, followed by stage 1 and 2 of NVWrite, followed by
                // stage 2 of NVRead.  This tests that the staged processing is thread-safe.
                sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 0;
                rval = Tss2_Sys_NV_Read_Prepare( rdSysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, sizeof( dataToWrite ), 0 );
                CheckPassed( rval );

                sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 1;
                rval = Tss2_Sys_NV_Write_Prepare( wrSysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST,
                        &nvWriteData, 0 );
                CheckPassed( rval );

                rval = ComputeCommandHmacs( wrSysContext, TPM20_INDEX_PASSWORD_TEST,
                        TPM20_INDEX_PASSWORD_TEST, &sessionsData, sessionCmdRval );
                CheckPassed( rval );

                sessionCmdRval = Tss2_Sys_NV_Write( wrSysContext,
                        TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
                CheckPassed( sessionCmdRval );
                if( sessionCmdRval == TPM_RC_SUCCESS )
                {
                    // Roll nonces for response
                    RollNonces( nvSession, &sessionsDataOut.rspAuths[0]->nonce );

                    rval = CheckResponseHMACs( wrSysContext, sessionCmdRval,
                            &sessionsData, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsDataOut );
                    CheckPassed( rval );
                }

                // Roll nonces for command
                RollNonces( nvSession, &sessionsData.cmdAuths[0]->nonce );

                sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 0;
                rval = ComputeCommandHmacs( rdSysContext, TPM20_INDEX_PASSWORD_TEST,
                       TPM20_INDEX_PASSWORD_TEST, &sessionsData, sessionCmdRval );
                CheckPassed( rval );

                if( decryptEncryptSetups[k] == ENCRYPT_SESSION )
                {
                    sessionsData.cmdAuths[0]->sessionAttributes.encrypt = 1;
                }
                else
                {
                    sessionsData.cmdAuths[0]->sessionAttributes.encrypt = 0;
                }
                sessionsData.cmdAuths[0]->sessionAttributes.decrypt = 0;

                INIT_SIMPLE_TPM2B_SIZE( nvData );
                sessionCmdRval = Tss2_Sys_NV_Read( rdSysContext, TPM20_INDEX_PASSWORD_TEST,
                        TPM20_INDEX_PASSWORD_TEST, &sessionsData, sizeof( dataToWrite ), 0, &nvData, &sessionsDataOut );
                CheckPassed( sessionCmdRval );
                if( sessionCmdRval == TPM_RC_SUCCESS )
                {
                    // Roll nonces for response
                    RollNonces( nvSession, &sessionsDataOut.rspAuths[0]->nonce );

                    rval = CheckResponseHMACs( rdSysContext, sessionCmdRval,
                            &sessionsData, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsDataOut );
                    CheckPassed( rval );

                    if( decryptEncryptSetups[k] == ENCRYPT_SESSION )
                    {
                        if( decryptEncryptMode == CFB_MODE )
                        {
//                            rval = EncryptCFB( nvSession, &( nvData.b ) );
                        }
                        else if( decryptEncryptMode == XOR_MODE )
                        {
//                            rval = EncryptXOR( nvSession, &( nvData.b ) );
                        }
                        CheckPassed( rval );
                    }

                    // Check that write actually worked.
                    rval = CompareTPM2B( &(nvWriteData.b), &(nvData.b) );
                    CheckPassed( rval );
                }

                //
                // NOTE:  When running against version of the simulator for TPM spec versions later
                // than version 0.98, in order for the session to act as a bound session when accessing
                // the bind entity, we will need to restart the session here since the name of the bound
                // entity changed.
                //
                if( hmacTestSetups[j].bound != TPM_RH_NULL )
                {
                    rval = EndAuthSession( nvSession );
                    CheckPassed( rval );

                    //
                    // Start session
                    //
                    nonceOlder.t.size = GetDigestSize( TPM_ALG_SHA1 );
                    for( i = 0; i < nonceOlder.t.size; i++ )
                        nonceOlder.t.buffer[i] = 0;

                    symmetric.algorithm = TPM_ALG_AES;
                    symmetric.keyBits.aes = 128;
                    symmetric.mode.aes = TPM_ALG_CFB;

                    rval = StartAuthSessionWithParams( &nvSession, hmacTestSetups[j].tpmKey,  hmacTestSetups[j].salt, hmacTestSetups[j].bound, &nvAuth, &nonceOlder, &encryptedSalt, TPM_SE_HMAC, &symmetric, TPM_ALG_SHA1, resMgrTctiContext );
                    CheckPassed( rval );

                    CopySizedByteBuffer( &( nvSession->authValueBind.b ), &( nvAuth.b ) );

                    // Now try writing with good HMAC.
                    sessionsData.cmdAuths[0]->sessionHandle = nvSession->sessionHandle;
                    sessionsData.cmdAuths[0]->nonce.t.size = 1;
                    sessionsData.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
                    sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 1;
                    sessionsData.cmdAuths[0]->sessionAttributes.decrypt = 1;

                    // TBD:  Need to encrypt data before sending.

                    rval = Tss2_Sys_NV_Write_Prepare( wrSysContext, TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
                    CheckPassed( rval );

                    // Roll nonces for command
                    RollNonces( nvSession, &sessionsData.cmdAuths[0]->nonce );

                    rval = ComputeCommandHmacs( wrSysContext, TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST, &sessionsData, TPM_RC_FAILURE );
                    CheckPassed( rval );

                    sessionCmdRval = Tss2_Sys_NV_Write( wrSysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
                    sessionsData.cmdAuths[0]->sessionAttributes.decrypt = 0;
                    CheckPassed( sessionCmdRval );
                    if( sessionCmdRval == TPM_RC_SUCCESS )
                    {
                        // Roll nonces for response
                        RollNonces( nvSession, &sessionsDataOut.rspAuths[0]->nonce );

                        rval = CheckResponseHMACs( wrSysContext, sessionCmdRval,
                                &sessionsData, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsDataOut );
                        CheckPassed( rval );
                    }

                    // Need to do GetSessionAuditDigest to check that audit digest changed.

                    sessionsData.cmdAuths[0]->sessionAttributes.continueSession = 0;
                    sessionsData.cmdAuths[0]->sessionAttributes.encrypt = 1;
                    sessionsData.cmdAuths[0]->sessionAttributes.audit = 1;

                    rval = Tss2_Sys_NV_Read_Prepare( rdSysContext, TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST, sizeof( dataToWrite ), 0 );
                    CheckPassed( rval );

                    // Roll nonces for command
                    RollNonces( nvSession, &sessionsData.cmdAuths[0]->nonce );

                    rval = ComputeCommandHmacs( rdSysContext, TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST, &sessionsData, sessionCmdRval );
                    CheckPassed( rval );

                    INIT_SIMPLE_TPM2B_SIZE( nvData );
                    sessionCmdRval = Tss2_Sys_NV_Read( rdSysContext, TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST, &sessionsData, sizeof( dataToWrite ), 0, &nvData, &sessionsDataOut );
                    sessionsData.cmdAuths[0]->sessionAttributes.encrypt = 0;
                    sessionsData.cmdAuths[0]->sessionAttributes.audit = 0;
                    if( sessionCmdRval == TPM_RC_SUCCESS )
                    {
                        // Roll nonces for response
                        RollNonces( nvSession, &sessionsDataOut.rspAuths[0]->nonce );

                        rval = CheckResponseHMACs( rdSysContext, sessionCmdRval,
                                &sessionsData, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsDataOut );
                        CheckPassed( rval );
                    }

                    // TBD:  Need to decrypt response data.

                    CheckPassed( rval );
                    // TBD:  Need to do GetSessionAuditDigest to check that audit digest changed.
                }

                // Removed comparison for now until we figure out how to properly
                // encrypt data before writing to NV index.
                //        rval = CompareTPM2B( &(nvWriteData.b), &(nvData.b) );
                //        CheckPassed( rval );

                sessionsData.cmdAuths[0]->sessionHandle = TPM_RS_PW;
                sessionsData.cmdAuths[0]->nonce.t.size = 0;
                sessionsData.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
                sessionData.hmac.t.size = 0;
                // Now undefine the index.
                rval = Tss2_Sys_NV_UndefineSpace( wrSysContext, TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
                CheckPassed( rval );
                rval = DeleteEntity( TPM20_INDEX_PASSWORD_TEST );
                CheckPassed( rval );
                rval = EndAuthSession( nvSession );
                CheckPassed( rval );
            }
        }
    }

    TeardownSysContext( &wrSysContext );
    TeardownSysContext( &rdSysContext );

}

UINT32 writeDataString = 0xdeadbeef;

void TestEncryptDecryptSession()
{
    TSS2_RC             rval = TSS2_RC_SUCCESS;
    SESSION             *encryptDecryptSession;
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

    nonceCaller.t.size = 0;

    // Authorization structure for undefine command.
    TPMS_AUTH_COMMAND nvUndefineAuth;

    // Create and init authorization area for undefine command:
    // only 1 authorization area.
    TPMS_AUTH_COMMAND *nvUndefineAuthArray[1] = { &nvUndefineAuth };

    // Authorization array for command (only has one auth structure).
    TSS2_SYS_CMD_AUTHS nvUndefineAuths = { 1, &nvUndefineAuthArray[0] };

    printf( "\n\nDECRYPT/ENCRYPT SESSION TESTS:\n" );

    writeData.t.size = sizeof( writeDataString );
    memcpy( (void *)&writeData.t.buffer, (void *)&writeDataString,
            sizeof( writeDataString ) );


    // Create NV index with empty auth value.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_AUTHREAD = 1;
    nvAttributes.TPMA_NV_AUTHWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // No authorization required.
    authPolicy.t.size = 0;
    nvAuth.t.size = 0;
    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_TEST1,
            TPM_ALG_SHA1, nvAttributes,
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
            symmetric.algorithm = TPM_ALG_AES;
            symmetric.keyBits.aes = 128;
            symmetric.mode.aes = TPM_ALG_CFB;
        }
        else
        {
            // XOR encryption/decryption.
            symmetric.algorithm = TPM_ALG_XOR;
            symmetric.keyBits.exclusiveOr = TPM_ALG_SHA256;
        }

        // Start policy session for decrypt/encrypt session.
        rval = StartAuthSessionWithParams( &encryptDecryptSession,
                TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, 0, TPM_SE_POLICY,
                &symmetric, TPM_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        //
        // Write TPM index with encrypted parameter used
        // as the data to write.  Set session for encrypt.
        // Use asyncronous APIs to do this.
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
        nvRdWrCmdAuth.sessionHandle = TPM_RS_PW;
        nvRdWrCmdAuth.nonce.t.size = 0;
        *( (UINT8 *)((void *)&nvRdWrCmdAuth.sessionAttributes ) ) = 0;
        nvRdWrCmdAuth.hmac.t.size = nvAuth.t.size;
        memcpy( (void *)&nvRdWrCmdAuth.hmac.t.buffer[0],
                (void *)&nvAuth.t.buffer[0],
                nvRdWrCmdAuth.hmac.t.size );

        // Set up encrypt/decrypt session structure.
        decryptEncryptSessionCmdAuth.sessionHandle =
                encryptDecryptSession->sessionHandle;
        decryptEncryptSessionCmdAuth.nonce.t.size = 0;
        *( (UINT8 *)((void *)&sessionAttributes ) ) = 0;
        decryptEncryptSessionCmdAuth.sessionAttributes =
                sessionAttributes;
        decryptEncryptSessionCmdAuth.sessionAttributes.continueSession
                = 1;
        decryptEncryptSessionCmdAuth.sessionAttributes.decrypt = 1;
        decryptEncryptSessionCmdAuth.hmac.t.size = 0;

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
                printf( "ERROR!! decryptParamSize != 0\n" );
                Cleanup();
            }
        }

        // Roll nonces for command.
        RollNonces( encryptDecryptSession,
                &decryptEncryptSessionCmdAuth.nonce );

        // Encrypt write data.
        rval = EncryptCommandParam( encryptDecryptSession,
                (TPM2B_MAX_BUFFER *)&encryptedWriteData,
                (TPM2B_MAX_BUFFER *)&writeData, &nvAuth );
        CheckPassed( rval );

        // Now set decrypt parameter.
        rval = Tss2_Sys_SetDecryptParam( sysContext,
                (uint8_t )encryptedWriteData.t.size,
                (uint8_t *)&encryptedWriteData.t.buffer[0] );
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
        if( memcmp( (void *)&readData.t.buffer[0],
                (void *)&writeData.t.buffer[0], readData.t.size ) )
        {
            printf( "ERROR!! read data not equal to written data\n" );
            Cleanup();
        }

        //
        // Read TPM index with encrypt session; use
        // syncronous APIs to do this.
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
        encryptedReadData.t.size = encryptParamSize;
        INIT_SIMPLE_TPM2B_SIZE( decryptedReadData );
        memcpy( (void *)&encryptedReadData.t.buffer[0],
                (void *)encryptParamBuffer, encryptParamSize );
        rval = DecryptResponseParam( encryptDecryptSession,
                (TPM2B_MAX_BUFFER *)&decryptedReadData,
                (TPM2B_MAX_BUFFER *)&encryptedReadData, &nvAuth );
        CheckPassed( rval );

        // Roll the nonces.
        RollNonces( encryptDecryptSession,
                &nvRdWrRspAuths.rspAuths[1]->nonce );

        rval = Tss2_Sys_SetEncryptParam( sysContext,
                (uint8_t)decryptedReadData.t.size,
                (uint8_t *)&decryptedReadData.t.buffer[0] );
        CheckPassed( rval );

        // Get the command results, in this case the read data.
        INIT_SIMPLE_TPM2B_SIZE( readData );
        rval = Tss2_Sys_NV_Read_Complete( sysContext, &readData );
        CheckPassed( rval );

        printf( "Decrypted read data = " );
        DEBUG_PRINT_BUFFER( NO_PREFIX, &readData.t.buffer[0], (UINT32 )readData.t.size );

        // Check that write and read data are equal.
        if( memcmp( (void *)&readData.t.buffer[0],
                (void *)&writeData.t.buffer[0], readData.t.size ) )
        {
            printf( "ERROR!! read data not equal to written data\n" );
            Cleanup();
        }

        rval = Tss2_Sys_FlushContext( sysContext,
                encryptDecryptSession->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( encryptDecryptSession );
        CheckPassed( rval );
    }

    // Set authorization for NV undefine command.
    nvUndefineAuth.sessionHandle = TPM_RS_PW;
    nvUndefineAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&nvUndefineAuth.sessionAttributes ) ) = 0;
    nvUndefineAuth.hmac.t.size = 0;

    // Undefine NV index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext,
            TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &nvUndefineAuths, 0 );
    CheckPassed( rval );
}


void TestRsaEncryptDecrypt()
{
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
    TPM_RC                  rval;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME rsaKeyName;

    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };

    TSS2_SYS_CMD_AUTHS sessionsData = { 1,  &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };

    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    // Create public/private key pair.
    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    *(UINT32 *)( (void *)&( inPublic.t.publicArea.objectAttributes ) ) = 0;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CTR;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );

    CheckPassed( rval );

    // Load private key into TPM
    INIT_SIMPLE_TPM2B_SIZE( rsaKeyName );
    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, 0, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &rsaKeyName, &sessionsDataOut);
    CheckPassed( rval );



    // Encrypt message with public key

    // Print encrypted message.

    // Decrypt message with private key.

    // Print decrypted message.

}


void GetSetDecryptParamTests()
{
    TPM2B_MAX_NV_BUFFER nvWriteData = { { 4, { 0xde, 0xad, 0xbe, 0xef, } } };
    TPM2B_MAX_NV_BUFFER nvWriteData1 = { { 4, { 0x01, 0x01, 0x02, 0x03, } } };
    const uint8_t *decryptParamBuffer;
    size_t decryptParamSize;
    size_t cpBufferUsedSize1, cpBufferUsedSize2;
    const uint8_t *cpBuffer1, *cpBuffer2;
    TSS2_RC rval;
    int i;
    TSS2_SYS_CONTEXT *decryptParamTestSysContext;

    printf( "\nGET/SET DECRYPT PARAM TESTS:\n" );

    // Create two sysContext structures.
    decryptParamTestSysContext = InitSysContext( MAX_NV_BUFFER_SIZE, resMgrTctiContext, &abiVersion );
    if( decryptParamTestSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // Test for bad sequence
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    // Do Prepare.
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData1, 0x55aa );
    CheckPassed( rval );

    // Test for bad reference
    rval = Tss2_Sys_GetDecryptParam( 0, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, 0, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_SetDecryptParam( 0, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    // Test for bad size.
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 5, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 3, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    // Test for good size.
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.t.buffer[0] ) );
    CheckPassed( rval );

    // Make sure that the set operation really did the right thing.
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );
    for( i = 0; i < 4; i++ )
    {
        if( decryptParamBuffer[i] != nvWriteData.t.buffer[i] )
        {
            printf( "ERROR!!  decryptParamBuffer[%d] s/b: %2.2x, was: %2.2x\n", i, nvWriteData.t.buffer[i], decryptParamBuffer[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize1, &cpBuffer1 );
    CheckPassed( rval );
#ifdef DEBUG
    printf( "cpBuffer = ");
#endif
    DEBUG_PRINT_BUFFER( NO_PREFIX, (UINT8 *)cpBuffer1, cpBufferUsedSize1 );

    // Test for no decrypt param.
    rval = Tss2_Sys_NV_Read_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, sizeof( nvWriteData ) - 2, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_NO_DECRYPT_PARAM );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.t.buffer[0] ) );
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
        printf( "ERROR!!  decryptParamSize s/b: 0, was: %u\n", (unsigned int)decryptParamSize );
        Cleanup();
    }

    // Test for insufficient size.
    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize2, &cpBuffer2 );
    CheckPassed( rval );
    nvWriteData.t.size = MAX_NV_BUFFER_SIZE -
            CHANGE_ENDIAN_DWORD( ( (TPM20_Header_In *)( ( (_TSS2_SYS_CONTEXT_BLOB *)decryptParamTestSysContext )->tpmInBuffPtr ) )->commandSize ) +
            1;
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, nvWriteData.t.size, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT );

    // Test that one less will work.  This tests that we're checking the correct corner case.
    nvWriteData.t.size -= 1;
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, nvWriteData.t.size, &( nvWriteData.t.buffer[0] ) );
    CheckPassed( rval );


    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, 0, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.t.buffer[0] ) );
    CheckPassed( rval );

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize2, &cpBuffer2 );
    CheckPassed( rval );
#ifdef DEBUG
    printf( "cpBuffer = ");
#endif
    DEBUG_PRINT_BUFFER( NO_PREFIX, (UINT8 *)cpBuffer2, cpBufferUsedSize2 );

    if( cpBufferUsedSize1 != cpBufferUsedSize2 )
    {
        printf( "ERROR!!  cpBufferUsedSize1(%x) != cpBufferUsedSize2(%x)\n", (UINT32)cpBufferUsedSize1, (UINT32)cpBufferUsedSize2 );
        Cleanup();
    }
    for( i = 0; i < (int)cpBufferUsedSize1; i++ )
    {
        if( cpBuffer1[i] != cpBuffer2[i] )
        {
            printf( "ERROR!! cpBufferUsedSize1[%d] s/b: %2.2x, was: %2.2x\n", i, cpBuffer1[i], cpBuffer2[i] );
            Cleanup();
        }
    }

    // Test case of zero sized decrypt param, another case of bad size.
    nvWriteData1.t.size = 0;
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData1, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 1, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    TeardownSysContext( &decryptParamTestSysContext );
}

void GetSetEncryptParamTests()
{
    TPM2B_MAX_NV_BUFFER nvWriteData = { { 4, { 0xde, 0xad, 0xbe, 0xef, } } };
    const uint8_t *encryptParamBuffer;
    const uint8_t encryptParamBuffer1[4] = { 01, 02, 03, 04 };
    size_t encryptParamSize;
    TSS2_RC rval;
    int i;
    TPM2B_DIGEST authPolicy;
    TPMA_NV nvAttributes;
    TPM2B_AUTH  nvAuth;

    TPMS_AUTH_COMMAND sessionData = { TPM_RS_PW, };
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };

    TPM2B_MAX_NV_BUFFER nvReadData;

    printf( "\nGET/SET ENCRYPT PARAM TESTS:\n" );

    // Do Prepare.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval );

    // Test for bad sequence
    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    // Create NV index

    // Set empty policy and auth value.
    authPolicy.t.size = 0;
    nvAuth.t.size = 0;

    // Now set the attributes.
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_AUTHREAD = 1;
    nvAttributes.TPMA_NV_AUTHWRITE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW, &nvAuth, &authPolicy,
            TPM20_INDEX_PASSWORD_TEST, TPM_ALG_SHA1, nvAttributes, 32  );
    CheckPassed( rval );

    // Write the index.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_NO_ENCRYPT_PARAM );

    // Now read it and do tests on get/set encrypt functions
    rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, 4, 0 );
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 4, 0, &nvReadData, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckPassed( rval );

    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckPassed( rval );

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckPassed( rval );

    // Test that encryptParamBuffer is the same as encryptParamBuffer1
    for( i = 0; i < 4; i++ )
    {
        if( encryptParamBuffer[i] != encryptParamBuffer1[i] )
        {
            printf( "ERROR!! encryptParamBuffer[%d] s/b: %2.2x, was: %2.2x\n", i, encryptParamBuffer[i], encryptParamBuffer1[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );


    // Test for bad reference
    rval = Tss2_Sys_GetEncryptParam( 0, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetEncryptParam( sysContext, 0, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_SetEncryptParam( 0, 4, encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );
}
#if 0
void TestRM()
{
    TSS2_TCTI_CONTEXT *otherResMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *otherSysContext;
        TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TSS2_RC rval = TSS2_RC_SUCCESS;

    TPMS_CONTEXT context;
    TSS2_TCTI_CONTEXT *tctiContext;

    TPMI_DH_CONTEXT loadedHandle, newHandle;

    printf( "\nRM TESTS:\n" );

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = InitTctiResMgrContext( driverConfig, &otherResMgrTctiContext );
    if( rval != TSS2_RC_SUCCESS )
    {
        printf( "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resMgrTctiDriverInfo.shortName, rval );
        Cleanup();
        return;
    }

    otherSysContext = InitSysContext( 0, otherResMgrTctiContext, &abiVersion );
    if( otherSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // TEST OWNERSHIP

    // Try to access a key created by the first TCTI context.
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;

    // This one should fail, because a different context is trying to use the primary object.
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( otherSysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckFailed( rval, TSS2_RESMGR_UNOWNED_HANDLE );

    // This one should pass, because the same context is allowed to save the context.
    rval = Tss2_Sys_ContextSave( sysContext, handle2048rsa, &context );
    CheckPassed( rval );

    // This one should pass, since we saved the context first.
    rval = Tss2_Sys_ContextLoad( otherSysContext, &context, &loadedHandle );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( otherSysContext, loadedHandle );
    CheckPassed( rval );

    // NOW, DO SOME LOCALITY TESTS

    // Test with null tctiContext ptr.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)( 0, 0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)( otherResMgrTctiContext, 0 );
    CheckPassed( rval );

    // Now try changing localities between send and receive.
    rval = Tss2_Sys_ContextLoad( otherSysContext, &context, &loadedHandle );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext_Prepare( otherSysContext, loadedHandle );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( otherSysContext );
    CheckPassed( rval );

    // This should fail because locality is changing between send and receive.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)( otherResMgrTctiContext, 1 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_ExecuteFinish( otherSysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval );

    // NOW, DO SOME CANCEL TESTS

    rval = Tss2_Sys_GetTctiContext( sysContext, &tctiContext );
    CheckPassed( rval );

    // Try cancel with null tctiContext ptr.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)( 0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE );

    // Try cancel when no commands are pending.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)( otherResMgrTctiContext );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE );

    // Then try cancel with a pending command:  send cancel before blocking _Finish call.
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    rval = Tss2_Sys_CreatePrimary_Prepare( sysContext, TPM_RH_PLATFORM, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR );
    CheckPassed( rval );

    //
    // NOTE: there are race conditions in tests that use cancel and
    // are expecting to receive the CANCEL response code.  The tests
    // typically run, but may occasionally fail on the order of
    // 1 out of 500 or so test passes.
    //
    // The OS could delay the test app long enough for the TPM to
    // complete the CreatePrimary before the test app gets to run
    // again.  To make these tests robust would require some way to
    // create a critical section in the test app.
    //
    sessionData.hmac.t.size = 0;
    sessionData.nonce.t.size = 0;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel)( tctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TPM_RC_CANCELED );

     // Then try cancel with a pending command:  send cancel after non-blocking _Finish call.
    rval = Tss2_Sys_CreatePrimary_Prepare( sysContext, TPM_RH_PLATFORM, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR );
    CheckPassed( rval );

    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteFinish( sysContext, 0 );
    CheckFailed( rval, TSS2_TCTI_RC_TRY_AGAIN );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel)( tctiContext );
    CheckPassed( rval );

	rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TPM_RC_CANCELED );

    // Then try cancel from a different connection:  it should just get a sequence error.
    rval = Tss2_Sys_CreatePrimary_Prepare( sysContext, TPM_RH_PLATFORM, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR );
    CheckPassed( rval );

    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)( otherResMgrTctiContext );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval );

    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_CreatePrimary_Complete( sysContext, &newHandle, &outPublic, &creationData,
            &creationHash, &creationTicket, &name );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, newHandle );
    CheckPassed( rval );

}
#endif

void TestRM()
{
    TSS2_TCTI_CONTEXT *otherResMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *otherSysContext;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TSS2_RC rval = TSS2_RC_SUCCESS;

    TPMS_CONTEXT context;
    TSS2_TCTI_CONTEXT *tctiContext;

    TPMI_DH_CONTEXT loadedHandle, newHandle, newNewHandle, newHandleDummy;
    TPMS_CONTEXT    newContext;
    char otherResMgrInterfaceName[] = "Test RM Resource Manager";

    DebugPrintf( NO_PREFIX, "\nRM TESTS:\n" );

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = InitTctiResMgrContext( &rmInterfaceConfig, &otherResMgrTctiContext, &otherResMgrInterfaceName[0] );
    if( rval != TSS2_RC_SUCCESS )
    {
        DebugPrintf( NO_PREFIX, "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resMgrInterfaceName, rval );
        Cleanup();
        return;
    }
    else
    {
        (( TSS2_TCTI_CONTEXT_INTEL *)otherResMgrTctiContext )->status.debugMsgEnabled = debugLevel;
    }

    otherSysContext = InitSysContext( 0, otherResMgrTctiContext, &abiVersion );
    if( otherSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // TEST OWNERSHIP

    // Try to access a key created by the first TCTI context.
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;

    // This one should fail, because a different context is trying to use the primary object.
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_Create( otherSysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckFailed( rval, TSS2_RESMGR_UNOWNED_HANDLE );

    // This one should pass, because the same context is allowed to save the context.
    rval = Tss2_Sys_ContextSave( sysContext, handle2048rsa, &context );
    CheckPassed( rval );

    // This one should pass, since we saved the context first.
    rval = Tss2_Sys_ContextLoad( otherSysContext, &context, &loadedHandle );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( otherSysContext, loadedHandle );
    CheckPassed( rval );

    // NOW, DO SOME LOCALITY TESTS

    // Test with null tctiContext ptr.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)( 0, 0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)( otherResMgrTctiContext, 0 );
    CheckPassed( rval );

    // Now try changing localities between send and receive.
    rval = Tss2_Sys_ContextLoad( otherSysContext, &context, &loadedHandle );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext_Prepare( otherSysContext, loadedHandle );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( otherSysContext );
    CheckPassed( rval );

    // This should fail because locality is changing between send and receive.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)( otherResMgrTctiContext, 1 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_ExecuteFinish( otherSysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval );

    // NOW, DO SOME CANCEL TESTS

    rval = Tss2_Sys_GetTctiContext( sysContext, &tctiContext );
    CheckPassed( rval );

    // Try cancel with null tctiContext ptr.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)( 0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE );

    // Try cancel when no commands are pending.
    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)( otherResMgrTctiContext );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE );

    // Then try cancel with a pending command:  send cancel before blocking _Finish call.
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    rval = Tss2_Sys_CreatePrimary_Prepare( sysContext, TPM_RH_PLATFORM, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR );
    CheckPassed( rval );

    //
    // NOTE: there are race conditions in tests that use cancel and
    // are expecting to receive the CANCEL response code.  The tests
    // typically pass, but may occasionally fail on the order of
    // 1 out of 500 or so test passes.
    //
    // The OS could delay the test app long enough for the TPM to
    // complete the CreatePrimary before the test app gets to run
    // again.  To make these tests robust would require some way to
    // create a critical section in the test app.
    //
    sessionData.hmac.t.size = 0;
    sessionData.nonce.t.size = 0;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel)( tctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TPM_RC_CANCELED );

     // Then try cancel with a pending command:  send cancel after non-blocking _Finish call.
    rval = Tss2_Sys_CreatePrimary_Prepare( sysContext, TPM_RH_PLATFORM, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR );
    CheckPassed( rval );

    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteFinish( sysContext, 0 );
    CheckFailed( rval, TSS2_TCTI_RC_TRY_AGAIN );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel)( tctiContext );
    CheckPassed( rval );

	rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TPM_RC_CANCELED );

    // Then try cancel from a different connection:  it should just get a sequence error.
    rval = Tss2_Sys_CreatePrimary_Prepare( sysContext, TPM_RH_PLATFORM, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR );
    CheckPassed( rval );

    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval );

    rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)( otherResMgrTctiContext );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval );

    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( name );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_CreatePrimary_Complete( sysContext, &newHandle, &outPublic, &creationData,
            &creationHash, &creationTicket, &name );
    CheckPassed( rval );

    //
    // Now try saving context for object and loading it using a different connection.
    //

    // First save context.
    rval = Tss2_Sys_ContextSave( sysContext, newHandle, &newContext );
    CheckPassed( rval );

    //
    // Now create an object with different hierarchy.  This will make sure that
    // RM is getting correct hierarchy in it's table.
    // NOTE:  this test can only be verified by looking at RM output.
    //
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( name );
    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_ENDORSEMENT, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &newHandleDummy, &outPublic, &creationData, &creationHash,
			&creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    // Now try loading the context using a different connection.
    rval = Tss2_Sys_ContextLoad( otherSysContext, &newContext, &newNewHandle );
    CheckPassed( rval );

    // Flush original connection's object.
    rval = Tss2_Sys_FlushContext( sysContext, newHandle );
    CheckPassed( rval );

    // Now try flushing new object from wrong connection.  Shouldn't be able to.
    rval = Tss2_Sys_FlushContext( sysContext, newNewHandle );
    CheckFailed( rval, TSS2_RESMGR_UNOWNED_HANDLE );

    // Now flush new object from other connection.  Should work.
    rval = Tss2_Sys_FlushContext( otherSysContext, newNewHandle );
    CheckPassed( rval );

    // Now flush dummy object.
    rval = Tss2_Sys_FlushContext( sysContext, newHandleDummy );
    CheckPassed( rval );

    rval = TeardownTctiResMgrContext( otherResMgrTctiContext );
    CheckPassed( rval );

    TeardownSysContext( &otherSysContext );
}

void EcEphemeralTest()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_ECC_POINT Q;
    UINT16 counter;

    printf( "\nEC Ephemeral TESTS:\n" );

    // Test SAPI for case of Q size field not being set to 0.
    Q.t.size = 0xff;
    rval = Tss2_Sys_EC_Ephemeral( sysContext, 0, TPM_ECC_BN_P256, &Q, &counter, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    Q.t.size = 0;
    rval = Tss2_Sys_EC_Ephemeral( sysContext, 0, TPM_ECC_BN_P256, &Q, &counter, 0 );
    CheckPassed( rval );
}


#ifdef __cplusplus
extern "C" {
#endif

extern int dummy_test();

#ifdef __cplusplus
}
#endif

// Test the interface of Tss2_Sys_NV_UndefineSpaceSpecial
// Note: the policy used to undefine NV can't be used to read and write;
// The attribute of TPMA_NV_POLICY_DELETE can't be set together with TPMA_NV_POLICYREAD and TPMA_NV_POLICYWRITE
void TestNVUndefineSpaceSpecial()
{
    UINT32 rval;
    TPM2B_AUTH  nvAuth;
    SESSION *nvSession, *trialSession;
    TPMA_NV nvAttributes;
    TPM2B_DIGEST authPolicy;

    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPMT_SYM_DEF symmetric;
    TPMA_SESSION sessionAttributes;

    // Command authorization area: one password session.
    TPMS_AUTH_COMMAND nvCmdAuth = { TPM_RS_PW, };
    TPMS_AUTH_COMMAND nvCmdAuth1 = { TPM_RS_PW, };

    TPMS_AUTH_COMMAND *nvCmdAuthArray[2] = { &nvCmdAuth, &nvCmdAuth1 };
    TSS2_SYS_CMD_AUTHS nvCmdAuths = { 2, &nvCmdAuthArray[0] };
    TPM_ALG_ID sessionAlg = TPM_ALG_SHA1;
    TPM2B_NONCE nonceCaller;

    printf( "\nNV INDEX UNDEFINESPACE_SPECIAL TEST:\n" );

    // Setup the NV index's authorization value.
    nvAuth.t.size = 0;
    encryptedSalt.t.size = 0;

    // No symmetric algorithm.
    symmetric.algorithm = TPM_ALG_NULL;

    nonceCaller.t.size = 0;

    // Create the NV index's authorization policy
    // using a trial policy session to calculate the policyDigest (using either SW or a trial policy session)
    // Copy it to the authPolicy value
    // Create the index
    rval = StartAuthSessionWithParams( &trialSession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM_SE_TRIAL,
            &symmetric, sessionAlg, resMgrTctiContext );
    CheckPassed( rval );

    // At this place, don't use the command Tss2_Sys_PolicyAuthValue after session create.
    rval = Tss2_Sys_PolicyCommandCode ( sysContext, trialSession->sessionHandle, 0, TPM_CC_NV_UndefineSpaceSpecial, 0 );
    CheckPassed( rval );

    // Get policy digest.
    rval = Tss2_Sys_PolicyGetDigest( sysContext, trialSession->sessionHandle,
            0, &authPolicy, 0 );
    CheckPassed( rval );

    // End the trial session by flushing it.
    rval = Tss2_Sys_FlushContext( sysContext, trialSession->sessionHandle );
    CheckPassed( rval );
    // And remove the trial policy session from sessions table.
    rval = EndAuthSession( trialSession );
    CheckPassed( rval );

    // POLICY_DELETE can't be used together with POLICYREAD and POLICYWRITE
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes.TPMA_NV_PPREAD = 1;
    nvAttributes.TPMA_NV_PPWRITE = 1;
    nvAttributes.TPMA_NV_POLICY_DELETE = 1;
    nvAttributes.TPMA_NV_PLATFORMCREATE = 1;

    // Create the NV index.
    rval = DefineNvIndex( TPM_RH_PLATFORM, TPM_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            sessionAlg, nvAttributes, 32  );
    CheckPassed( rval );

    // Begin to undefine the NV Index space with policy session
    rval = StartAuthSessionWithParams( &nvSession, TPM_RH_NULL,
            0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY,
            &symmetric, sessionAlg, resMgrTctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_PolicyCommandCode ( sysContext, nvSession->sessionHandle, 0, TPM_CC_NV_UndefineSpaceSpecial, 0 );
    CheckPassed( rval );

    nvCmdAuths.cmdAuths[0]->sessionHandle = nvSession->sessionHandle;
    nvCmdAuths.cmdAuths[0]->nonce.t.size = 0;
    *( (UINT8 *)((void *)&sessionAttributes ) ) = 0;
    nvCmdAuths.cmdAuths[0]->sessionAttributes = sessionAttributes;
    nvCmdAuths.cmdAuths[1]->nonce.t.size = 0;
    nvCmdAuths.cmdAuths[1]->sessionAttributes = sessionAttributes;

    rval = Tss2_Sys_NV_UndefineSpaceSpecial( sysContext,
            TPM20_INDEX_PASSWORD_TEST, TPM_RH_PLATFORM,
            &nvCmdAuths, 0 );
    CheckPassed( rval );
}

UINT32 TestNVIndexUndefine(TPMI_RH_PROVISION authHandle, TPMI_RH_NV_INDEX nvIndex)
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionData.sessionHandle = TPM_RS_PW;
    // Init nonce.
    sessionData.nonce.t.size = 0;
    // init hmac
    sessionData.hmac.t.size = 0;
    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, authHandle, nvIndex, &sessionsData, 0 );
//    CheckPassed( rval );
    printf("\nThe result of releasing NV %x: %x\n", nvIndex, rval);
    return rval;
}

void ClearNVIndexList(TPMI_RH_PROVISION authHandle)
{
    UINT32 rval;
    printf( "\nNV INDEX LIST CLEAR:\n" );
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    // list the NV index
    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_HANDLES, CHANGE_ENDIAN_DWORD(TPM_HT_NV_INDEX),
                                   TPM_PT_NV_INDEX_MAX, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    printf( "\tThe count of defined NV Index: %d\n", capabilityData.data.handles.count);
    for( UINT32 i=0; i < capabilityData.data.handles.count; i++ )
    {
        printf("\n\tNV Index: %x\n", capabilityData.data.handles.handle[i]);
        if( TestNVIndexUndefine(authHandle, capabilityData.data.handles.handle[i]) )
            TestNVIndexUndefine(capabilityData.data.handles.handle[i], capabilityData.data.handles.handle[i]);
    }
}

void symmetricEncryptDecryptTest()
{
    UINT32 rval;
    TPMS_CONTEXT context;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo= { { 0, } };
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name= { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_PRIVATE outPrivate = { { sizeof(TPM2B_PRIVATE)-2, } };
    TPM2B_PUBLIC outPublic= { { 0, } };
    TPM2B_CREATION_DATA creationData= { { 0, } };
    TPM2B_DIGEST creationHash = { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, };
    TPM_HANDLE loadedSymKeyHandle;
    TPMI_DH_OBJECT symHandle;


    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    printf( "\nSYMMETRIC ENCRYPT/DECRYPT & HASH TESTS:\n" );

    inSensitive.t.size =0;
    inSensitive.t.sensitive.userAuth.t.size = 0;
    inSensitive.t.sensitive.data.t.size = 0;

    //inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    //inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    //inSensitive.t.sensitive.data.t.size = 0;
    //inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;
    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    outPublic.t.size = 0;
    creationData.t.size = 0;
    creationPCR.count = 0;
    //outPublic.t.publicArea.authPolicy.t.size = sizeof( TPM2B_DIGEST ) - 2;
    //outPublic.t.publicArea.unique.keyedHash.t.size = sizeof( TPM2B_DIGEST ) - 2;
    //INIT_SIMPLE_TPM2B_SIZE( creationHash );
    //INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_NULL, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nNew key successfully created (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );

    rval = Tss2_Sys_ContextSave(sysContext, handle2048rsa, &context);
    CheckPassed(rval);

    rval = Tss2_Sys_ContextLoad(sysContext, &context, &symHandle);
    CheckPassed(rval);

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    inSensitive.t.size = 0;// inSensitive.t.sensitive.userAuth.b.size +2;
    inSensitive.t.sensitive.userAuth.t.size = 0;
    inSensitive.t.sensitive.data.t.size = 0;
    inPublic.t.publicArea.type = TPM_ALG_SYMCIPHER;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.sign = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
    inPublic.t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
 
    inPublic.t.publicArea.unique.sym.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    creationPCR.count = 0; 
    rval = Tss2_Sys_Create( sysContext, symHandle, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    //INIT_SIMPLE_TPM2B_SIZE( name );
    rval = Tss2_Sys_Load ( sysContext, symHandle, &sessionsData, &outPrivate, &outPublic,
            &loadedSymKeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );
    printf( "\nLoaded key handle:  %8.8x\n", loadedSymKeyHandle );

    const char msg[] = "message";
    
    TPMI_YES_NO decryptVal = NO;
    TPM2B_MAX_BUFFER inData = { { sizeof(TPM2B_MAX_BUFFER)-2, } };
    // Inputs
    TPMI_ALG_SYM_MODE mode;
    TPM2B_IV ivIn = { { sizeof(TPM2B_IV)-2, } };
        // Outputs
    TPM2B_MAX_BUFFER outData = { { sizeof(TPM2B_MAX_BUFFER)-2, } };
    TPM2B_IV ivOut = { { sizeof(TPM2B_IV)-2, } };

    mode = TPM_ALG_NULL;
    ivIn.t.size = MAX_SYM_BLOCK_SIZE;
    memset(ivIn.t.buffer, 0, MAX_SYM_BLOCK_SIZE);

    inData.t.size = sizeof(msg);
    memcpy(inData.t.buffer, msg, inData.t.size);

    printf("\nENCRYPTDECRYPT TESTS: ENCRYPT\n");
    
    sessionData.sessionHandle = TPM_RS_PW;
    // Init nonce.
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
	
    rval = Tss2_Sys_EncryptDecrypt(sysContext, loadedSymKeyHandle, &sessionsData, decryptVal, mode, &ivIn, &inData, &outData, &ivOut, &sessionsDataOut);
    if(rval == TPM_RC_SUCCESS)
	{
        printf("\nEncrypted.\n");
		CheckPassed(rval);
    }
	else
        CheckFailed(rval, TPM_RC_COMMAND_CODE);

    decryptVal = YES;
    // Outputs
    TPM2B_MAX_BUFFER outDeData = { { sizeof(TPM2B_MAX_BUFFER)-2, } };
    TPM2B_IV ivDeOut = { { sizeof(TPM2B_IV)-2, } };

    ivOut.t.size = MAX_SYM_BLOCK_SIZE;
    memset(ivOut.t.buffer, 0, MAX_SYM_BLOCK_SIZE);

    printf("\nENCRYPTDECRYPT TESTS: DECRYPT\n");

    TPM2B_DIGEST outHash1 = { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPM2B_DIGEST outHash2 = { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPMT_TK_HASHCHECK validation;
    TPMI_ALG_HASH  halg = TPM_ALG_SHA256;

	if (rval == TPM_RC_SUCCESS)
	{
        rval = Tss2_Sys_EncryptDecrypt(sysContext, loadedSymKeyHandle, &sessionsData, decryptVal, mode, &ivOut, &outData, &outDeData, &ivDeOut, &sessionsDataOut);
        if(rval == TPM_RC_SUCCESS)
		{
            printf("\nDecrypted.\n");
	    CheckPassed(rval);
		}
        else
            CheckFailed(rval, TPM_RC_COMMAND_CODE);

	printf("\nHASH TESTS: HASH Comparison\n");

        rval = Tss2_Sys_Hash(sysContext, 0, &outDeData, halg, TPM_RH_OWNER, &outHash1, &validation, 0);
        CheckPassed(rval);

	rval = Tss2_Sys_Hash(sysContext, 0, &inData, halg, TPM_RH_OWNER, &outHash2, &validation, 0);
	CheckPassed(rval);
	printf( "Hash value before encrypt: " );
        PrintSizedBuffer( (TPM2B *)&outHash1 );
        printf( "Hash value after decrypt: " );
        PrintSizedBuffer( (TPM2B *)&outHash2 );
	//rval = CompareTPM2B( (TPM2B *)&outHash1, (TPM2B *)&outHash2 );
	//CheckPassed( rval );
	}
}

void asymmetricEncryptDecryptTest()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo= { { 0, } };
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name= { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic= { { 0, } };
    TPM2B_CREATION_DATA creationData= { { 0, } };
    TPM2B_DIGEST creationHash = { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, };

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    printf( "\nASYMMETRIC ENCRYPT/DECRYPT & HASH TESTS:\n" );
    //inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    //inSensitive.t.sensitive.data.t.size = 0;
    //inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;


    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_OWNER, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nNew key successfully created in owner hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );
    printf( "Name of created primary key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    outPublic.t.size = 0;
    creationData.t.size = 0;

    sessionData.hmac.t.size = 0;

    // First clear attributes bit field.
    *(UINT32 *)&(inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.sign = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );
    printf( "Name of created key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    printf( "Name of loading key: " );
    PrintSizedBuffer( (TPM2B *)&name );
    
    printf( "\nLoaded key handle:  %8.8x\n", loadedSha1KeyHandle );

    char buffer1contents[] = "test";
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_PUBLIC_KEY_RSA message = { { sizeof(TPM2B_PUBLIC_KEY_RSA)-2, } };
    TPM2B_PUBLIC_KEY_RSA messageOut = { { sizeof(TPM2B_PUBLIC_KEY_RSA)-2, } };
    TPM2B_PUBLIC_KEY_RSA outData = { { sizeof(TPM2B_PUBLIC_KEY_RSA)-2, } };
    TPM2B_MAX_BUFFER inData1, inData2;
    TPM2B_DIGEST outHash1 = { { sizeof( TPM2B_DIGEST ) - 2,} }; 
    TPM2B_DIGEST outHash2 = { { sizeof( TPM2B_DIGEST ) - 2,} };
    TPMT_TK_HASHCHECK validation;
    TPMI_ALG_HASH  halg = TPM_ALG_SHA256;

    message.t.size = strlen(buffer1contents);
    memcpy(message.t.buffer, buffer1contents, message.t.size);

    inScheme.scheme = TPM_ALG_RSAES;
    outsideInfo.t.size = 0;
    rval = Tss2_Sys_RSA_Encrypt(sysContext, loadedSha1KeyHandle, 0, &message, &inScheme, &outsideInfo, &outData, 0);
    CheckPassed(rval);
    printf( "Encrypted data: " );
    PrintSizedBuffer( (TPM2B *)&outData );

	if (rval == TPM_RC_SUCCESS)
	{
	    rval = Tss2_Sys_RSA_Decrypt(sysContext, loadedSha1KeyHandle, &sessionsData, &outData, &inScheme, &outsideInfo, &messageOut, &sessionsDataOut);
	    CheckPassed(rval);
	    printf( "Decypted data: " );
	    PrintSizedBuffer( (TPM2B *)&messageOut );

	    printf("\nHASH TESTS: HASH Comparison\n");

            inData1.t.size = message.t.size;
	    memcpy(inData1.t.buffer, message.t.buffer, inData1.t.size);
            rval = Tss2_Sys_Hash(sysContext, 0, &inData1, halg, TPM_RH_OWNER, &outHash1, &validation, 0);
            CheckPassed(rval);

	    inData2.t.size = messageOut.t.size;
	    memcpy(inData2.t.buffer, messageOut.t.buffer, inData2.t.size);
	    rval = Tss2_Sys_Hash(sysContext, 0, &inData2, halg, TPM_RH_OWNER, &outHash2, &validation, 0);
	    CheckPassed(rval);

	    printf( "Hash value before encrypt: " );
    	    PrintSizedBuffer( (TPM2B *)&outHash1 );
	    printf( "Hash value after decrypt: " );
            PrintSizedBuffer( (TPM2B *)&outHash2 );
	}
}

void verifySignatureExternalTest()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;

    TSS2_SYS_CMD_AUTHS sessionsData;

    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    TPM2B_NAME name = { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_NAME nameExt = { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_PRIVATE outPrivate = { { sizeof( TPM2B_PRIVATE ) - 2, } };
    TPM2B_PUBLIC outPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };
    TPM2B_CREATION_DATA creationData  =  { { sizeof( TPM2B_CREATION_DATA ) - 2, } };
    TPM2B_DIGEST creationHash= { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, 0, { { sizeof( TPM2B_DIGEST ) - 2, } } };
    TPM_HANDLE loadedObjectHandle;
    TPM2B_DIGEST msgHash;
    TPMT_SIGNATURE signature;
    TPMT_TK_VERIFIED validation;
    TPMT_TK_HASHCHECK hashCheck;
    TPMT_SIG_SCHEME inScheme;
    
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    printf( "\nVERIFICATION on PUBLIC LOADED KEY TESTS:\n" );

    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_OWNER, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nNew key successfully created in owner hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );
    printf( "Name of created primary key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    outPublic.t.size = 0;
    creationData.t.size = sizeof( TPM2B_CREATION_DATA ) - 2;
    outPublic.t.publicArea.authPolicy.t.size = sizeof( TPM2B_DIGEST ) - 2;
    outPublic.t.publicArea.unique.keyedHash.t.size = sizeof( TPM2B_DIGEST ) - 2;
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.sign = 1;

    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );
    printf( "Name of created key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    printf( "Name of loading key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    inScheme.scheme = TPM_ALG_RSASSA;
    inScheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
    hashCheck.tag = TPM_ST_HASHCHECK;
    hashCheck.hierarchy = TPM_RH_NULL;
    hashCheck.digest.t.size = 0;

    char SignMsg[]= "try to get sign with this msg!";
    UINT16 length = sizeof(SignMsg);
    BYTE *buffer = NULL;
    UINT8 numBuffers = 0;
    UINT16 cpLength = 0;

    buffer = (BYTE*)malloc(length*sizeof(BYTE));
    memset(buffer, 0, length*sizeof(BYTE));
    memcpy (buffer, SignMsg, length);
    
    if(length%(MAX_DIGEST_BUFFER) != 0)
        numBuffers = length/(MAX_DIGEST_BUFFER) + 1;
    else
        numBuffers = length/(MAX_DIGEST_BUFFER);

    TPM2B_DIGEST *bufferList[numBuffers];
    for(UINT8 i = 0; i < numBuffers; i++)
    {
        (bufferList)[i] = (TPM2B_DIGEST *)calloc(1,sizeof(TPM2B_DIGEST));
        if(i < numBuffers-1)
        {
            for( UINT16 m = 0; m < MAX_DIGEST_BUFFER; m++)
            {
                bufferList[i]->t.buffer[m] = buffer[m + cpLength];
            }
            cpLength = i * MAX_DIGEST_BUFFER;
        }
        if(i == numBuffers-1 )
        {
            for(UINT16 j= 0; j < (length-cpLength); j++)
            {
                bufferList[i]->t.buffer[j] = buffer[cpLength + j];
            }
        }
    }
    if(numBuffers == 1)
    {
        rval = TpmHash(TPM_ALG_SHA1, length, buffer, &msgHash);
        printf("tpmhash");
        CheckPassed(rval);
    }
    else
    {
        TpmHashSequence(TPM_ALG_SHA1, numBuffers, bufferList[0], &msgHash);
        printf("tpmhashsequence");
    }

    rval = Tss2_Sys_Sign(sysContext, loadedSha1KeyHandle, &sessionsData, &msgHash, &inScheme, &hashCheck, &signature, &sessionsDataOut);
    CheckPassed(rval);

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 0;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;

    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    rval = Tss2_Sys_LoadExternal ( sysContext, 0, 0, &outPublic, TPM_RH_OWNER, &loadedObjectHandle, &nameExt, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nLoaded key handle:  %8.8x\n", loadedObjectHandle );

    rval = Tss2_Sys_VerifySignature(sysContext, /*loadedSha1KeyHandle*/loadedObjectHandle, NULL/*&sessionsData*/, &msgHash, &signature, &validation, &sessionsDataOut);
    CheckPassed( rval );
}

void verifySignatureCreatedTest()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;

    TSS2_SYS_CMD_AUTHS sessionsData;

    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    TPM2B_NAME name = { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_PRIVATE outPrivate = { { sizeof( TPM2B_PRIVATE ) - 2, } };
    TPM2B_PUBLIC outPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };
    TPM2B_CREATION_DATA creationData =  { { sizeof( TPM2B_CREATION_DATA ) - 2, } };
    TPM2B_DIGEST creationHash = { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, 0, { { sizeof( TPM2B_DIGEST ) - 2, } } };
    TPM2B_DIGEST msgHash;
    TPMT_SIGNATURE signature;
    TPMT_TK_VERIFIED validation;
    TPMT_TK_HASHCHECK hashCheck;
    TPMT_SIG_SCHEME inScheme;
    
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;

    inPublic.t.publicArea.unique.rsa.t.size = 0;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    printf( "\nVERIFICATION on CREATED KEY TESTS:\n" );

    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_OWNER, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nNew key successfully created in owner hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );
    printf( "Name of created primary key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    outPublic.t.size = 0;
    creationData.t.size = sizeof( TPM2B_CREATION_DATA ) - 2;
    outPublic.t.publicArea.authPolicy.t.size = sizeof( TPM2B_DIGEST ) - 2;
    outPublic.t.publicArea.unique.keyedHash.t.size = sizeof( TPM2B_DIGEST ) - 2;
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.sign = 1;

    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );
    printf( "Name of created key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    printf( "Name of loading key: " );
    PrintSizedBuffer( (TPM2B *)&name );

    inScheme.scheme = TPM_ALG_RSASSA;
    inScheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
    hashCheck.tag = TPM_ST_HASHCHECK;
    hashCheck.hierarchy = TPM_RH_NULL;
    hashCheck.digest.t.size = 0;

    char SignMsg[]= "try to get sign with this msg!";
    UINT16 length = sizeof(SignMsg);
    BYTE *buffer = NULL;
    UINT8 numBuffers = 0;
    UINT16 cpLength = 0;

    buffer = (BYTE*)malloc(length*sizeof(BYTE));
    memset(buffer, 0, length*sizeof(BYTE));
    memcpy (buffer, SignMsg, length);
    if(length%(MAX_DIGEST_BUFFER) != 0)
        numBuffers = length/(MAX_DIGEST_BUFFER) + 1;
    else
        numBuffers = length/(MAX_DIGEST_BUFFER);

    TPM2B_DIGEST *bufferList[numBuffers];
    for(UINT8 i = 0; i < numBuffers; i++)
    {
        (bufferList)[i] = (TPM2B_DIGEST *)calloc(1,sizeof(TPM2B_DIGEST));
        if(i < numBuffers-1)
        {
            for( UINT16 m = 0; m < MAX_DIGEST_BUFFER; m++)
            {
                bufferList[i]->t.buffer[m] = buffer[m + cpLength];
            }
            cpLength = i * MAX_DIGEST_BUFFER;
        }
        if(i == numBuffers-1 )
        {
            for(UINT16 j= 0; j < (length-cpLength); j++)
            {
                bufferList[i]->t.buffer[j] = buffer[cpLength + j];
            }
        }
    }
    if(numBuffers == 1)
    {
        rval = TpmHash(TPM_ALG_SHA1, length, buffer, &msgHash);
        printf("tpmhash");
        CheckPassed(rval);
    }
    else
    {
        TpmHashSequence(TPM_ALG_SHA1, numBuffers, bufferList[0], &msgHash);
        printf("tpmhashsequence");
    }

    printf("\ndigest(hex type):\n ");
    for(UINT16 i = 0; i < msgHash.t.size; i++)
    {
         printf("%02x ", msgHash.t.buffer[i]);
    }
    printf("\n");

    rval = Tss2_Sys_Sign(sysContext, loadedSha1KeyHandle, &sessionsData, &msgHash, &inScheme, &hashCheck, &signature, &sessionsDataOut);
    CheckPassed(rval);

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    *(UINT32 *)&( inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 0;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.objectAttributes.restricted = 0;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

//    rval = Tss2_Sys_LoadExternal ( sysContext, 0, 0, &outPublic, TPM_RH_OWNER, &loadedObjectHandle, &nameExt, &sessionsDataOut );
//    CheckPassed( rval );
//    printf( "\nLoaded key handle:  %8.8x\n", loadedObjectHandle );


    rval = Tss2_Sys_VerifySignature(sysContext, loadedSha1KeyHandle/*loadedObjectHandle*/, NULL/*&sessionsData*/, &msgHash, &signature, &validation, &sessionsDataOut);
    if (rval == TPM_RC_SUCCESS)
        CheckPassed( rval );
    else
        CheckFailed(rval, TPM_RC_SIGNATURE);
}

void nvExtensionTest()
{
    UINT32 rval;
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    TPM2B_PUBLIC outPublic;
    TPM_HANDLE loadedObjectHandle;
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
    TPM2B_NAME nvName1;
    TPM2B_NAME nvName2;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    outPublic.t.size =0;
    outPublic.t.publicArea.type = TPM_ALG_KEYEDHASH; //TPM_ALG_RSA;
    outPublic.t.publicArea.nameAlg = TPM_ALG_SHA1; //TPM_ALG_SHA256;
    *( UINT32 *)&( outPublic.t.publicArea.objectAttributes )= 0;
    outPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    outPublic.t.publicArea.authPolicy.t.size = 0;
    outPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL; //TPM_ALG_RSASSA;
    outPublic.t.publicArea.unique.keyedHash.t.size = 0;

    printf( "\nNV EXTENSION TESTS:\n" );

    // list the NV index
    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_HANDLES, CHANGE_ENDIAN_DWORD(TPM_HT_NV_INDEX),
                                   TPM_PT_NV_INDEX_MAX, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    printf( "\tThe count of defined NV Index: %d\n", capabilityData.data.handles.count);
    for( UINT32 i=0; i < capabilityData.data.handles.count; i++ )
    {
        printf("\n\tNV Index: %x\n", capabilityData.data.handles.handle[i]);
    }
    INIT_SIMPLE_TPM2B_SIZE( nvName );
    rval = Tss2_Sys_LoadExternal ( sysContext, 0, 0/*&inPrivate*/, &outPublic, TPM_RH_OWNER, &loadedObjectHandle, &nvName, 0 );
    if (rval == TPM_RC_SUCCESS)
        CheckPassed( rval );
    else
        CheckFailed(rval, TPM_RC_COMMAND_CODE);

    rval = (*HandleToNameFunctionPtr)(loadedObjectHandle, &nvName1);
    CheckPassed(rval);
    printf( "Name of loaded key: " );
    PrintSizedBuffer( (TPM2B *)&nvName1 );

    rval = CompareTPM2B( &nvName.b, &nvName1.b );
    CheckPassed( rval );

    printf( "\nLoaded key handle:  %8.8x\n", loadedObjectHandle );

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    nvAuth.t.size = nvName1.t.size-2;
    for( i = 0; i < nvAuth.t.size; i++ )
        nvAuth.t.buffer[i] = nvName1.t.name[i];

    publicInfo.t.size = sizeof( TPMI_RH_NV_INDEX ) +
            sizeof( TPMI_ALG_HASH ) + sizeof( TPMA_NV ) + sizeof( UINT16) +
            sizeof( UINT16 );
    publicInfo.t.nvPublic.nvIndex = TPM20_INDEX_PASSWORD_TEST;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;

    // First zero out attributes.
    *(UINT32 *)&( publicInfo.t.nvPublic.attributes ) = 0;

    // Now set the attributes.
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = 32;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );
  
    printf("TPM 2.0 Test 1 Index:%x", publicInfo.t.nvPublic.nvIndex);

    nvPublic.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( nvName2 );
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_PASSWORD_TEST, 0, &nvPublic, &nvName2, 0 );
    CheckPassed( rval );
    printf( "Name of Public Key for NV: " );
    PrintSizedBuffer( (TPM2B *)&nvName2 );

    INIT_SIMPLE_TPM2B_SIZE(nvData);
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_OWNER, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 20, 0, &nvData, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_NV_UNINITIALIZED );

    // Should fail since index is already defined.
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_NV_DEFINED );

    nvWriteData.t.size = nvName1.t.size-2;
    for( i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = nvName1.t.name[i];

    rval = Tss2_Sys_NV_Write( sysContext, TPM_RH_OWNER, TPM20_INDEX_PASSWORD_TEST, &sessionsData, &nvWriteData, 0, &sessionsDataOut ); 
    if (rval == TPM_RC_SUCCESS)
        CheckPassed( rval );
    else
        CheckFailed(rval, TPM_RC_NV_AUTHORIZATION);
    
    INIT_SIMPLE_TPM2B_SIZE( nvData);
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_OWNER, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 20, 0, &nvData, &sessionsDataOut );
    CheckPassed( rval );
    printf("\nName of NV data: ");
    for (int i=0; i<nvData.t.size; i++)
    {
        printf(" %2.2x ", nvData.t.buffer[i]);
    }
    printf("\n");

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_OWNER, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_OWNER, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );
}

void pcrExtendedTest()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    UINT16 i, digestSize;
    TPML_PCR_SELECTION  pcrSelection;
    UINT32 pcrUpdateCounterBeforeExtend;
    UINT32 pcrUpdateCounterAfterExtend;
    UINT8 pcrBeforeExtend[20];
    TPM2B_EVENT eventData;
    TPML_DIGEST pcrValues;
    TPML_DIGEST_VALUES digests;
    TPML_PCR_SELECTION pcrSelectionOut;
    
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];

    printf( "\nPCR EXTENSION TESTS:\n" );

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_PCR_PROPERTIES, TPM_PT_PCR_COUNT,
                                   1, &moreData, &capabilityData, 0 );
    CheckPassed(rval);
    printf("The Number of PCR implemented:%x\n",capabilityData.data.pcrProperties.pcrProperty[0].pcrSelect[0]);

    // Init digests
    digests.count = 1;
    digests.digests[0].hashAlg = TPM_ALG_SHA1;
    digestSize = GetDigestSize( digests.digests[0].hashAlg );

    for( i = 0; i < digestSize; i++ )
    {
        digests.digests[0].digest.sha1[i] = (UINT8)(i % 256);
    }

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM_ALG_SHA1;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;

    // Clear out PCR select bit field
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[PCR_8 / 8] = 1 << (PCR_8 % 8);

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterBeforeExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );
    printf( "Name of PCR Values Before Extend: " );
    for(int i = 0; i < pcrValues.digests[0].t.size; i++)
        printf("%02x ", pcrValues.digests[0].t.buffer[i]);
    printf("\n");

    memcpy( &( pcrBeforeExtend[0] ), &( pcrValues.digests[0].t.buffer[0] ), pcrValues.digests[0].t.size );

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    rval = Tss2_Sys_PCR_Extend( sysContext, PCR_8, &sessionsData, &digests, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    printf( "Name of PCR Values After Extended: " );
    for(int i = 0; i < pcrValues.digests[0].t.size; i++)
        printf("%02x ", pcrValues.digests[0].t.buffer[i]);
    printf("\n");

    memcpy( &( pcrAfterExtend[0] ), &( pcrValues.digests[0].t.buffer[0] ), pcrValues.digests[0].t.size );

    if( pcrUpdateCounterBeforeExtend == pcrUpdateCounterAfterExtend )
    {
        printf( "ERROR!! pcrUpdateCounter didn't change value\n" );
        Cleanup();
    }

    if( 0 == memcmp( &( pcrBeforeExtend[0] ), &( pcrAfterExtend[0] ), 20 ) )
    {
        printf( "ERROR!! PCR didn't change value\n" );
        Cleanup();
    }
    pcrSelection.pcrSelections[0].sizeofSelect = 4;

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, 0, 0, 0 );
    CheckFailed( rval, TPM_RC_1 + TPM_RC_P + TPM_RC_VALUE );

    eventData.t.size = 4;
    eventData.t.buffer[0] = 0;
    eventData.t.buffer[1] = 0xff;
    eventData.t.buffer[2] = 0x55;
    eventData.t.buffer[3] = 0xaa;

    rval = Tss2_Sys_PCR_Event( sysContext, PCR_10, &sessionsData, &eventData, &digests, 0  );
    CheckPassed( rval );
    printf( "Name of PCR Event Digests: " );
    for(UINT16 i = 0; i < digestSize; i++)
        printf("%02x ", digests.digests[0].digest.sha1[i]);
    printf("\n");
}

void TestClockTime()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
    // Here we need to note the sessionsData.cmdAuthsCount value to be set 1,
    // otherwise Tss2_Sys_SetCmdAuths will return error 0x8000b(TSS2_SYS_RC_BAD_VALUE).
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };

    sessionsData.cmdAuthsCount = 1;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    TPMS_TIME_INFO currentTime;

    printf("\nCLOCK/TIME TEST:\n");
    rval = Tss2_Sys_ReadClock(sysContext, &currentTime);
    CheckPassed( rval );
    printf("\nCurrent Time:%lu, Current Clock Info:%lu\n", currentTime.time, currentTime.clockInfo.clock );
    // current value of Clock < newTime < 0xFFFF000000000000ULL,otherwise failed.
    //UINT64 newTime = 0xFFFF000000000001;//16 numbers
    UINT64 newTime = 0xFFF111111111;
    rval = Tss2_Sys_ClockSet(sysContext, TPM_RH_OWNER, &sessionsData, newTime, &sessionsDataOut);
    //CheckFailed( rval, TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 );
    CheckPassed(rval);

    rval = Tss2_Sys_ReadClock(sysContext, &currentTime);
    CheckPassed(rval);
    printf("\nCurrent Time:%lu, Current Clock Info:%lu\n", currentTime.time, currentTime.clockInfo.clock);

    TPM_CLOCK_ADJUST rateAdjust = 0;
    rval = Tss2_Sys_ClockRateAdjust(sysContext, TPM_RH_OWNER, &sessionsData, rateAdjust, &sessionsDataOut);
    CheckPassed( rval );

    rateAdjust = TPM_CLOCK_COARSE_SLOWER;
    rval = Tss2_Sys_ClockRateAdjust(sysContext, TPM_RH_OWNER, &sessionsData, rateAdjust, &sessionsDataOut);

    CheckPassed(rval);

    rateAdjust = TPM_CLOCK_COARSE_FASTER;
    rval = Tss2_Sys_ClockRateAdjust(sysContext, TPM_RH_OWNER, &sessionsData, rateAdjust, &sessionsDataOut);

    CheckPassed(rval);
}

void TpmTest()
{
    UINT32 i;
    TSS2_RC rval = TSS2_RC_SUCCESS;

    TestTpmStartup();

    GetTpmVersion();

    TestTpmSelftest();

    TestSapiApis();

    TestDictionaryAttackLockReset();

    TestCreate();

    if( startAuthSessionTestOnly == 1 )
    {
        if( nullPlatformAuth )
            TestStartAuthSession();
        goto endtests;
    }

    if( nullPlatformAuth )
        TestHierarchyControl();

    if( tpmType != TPM_TYPE_PTT && nullPlatformAuth )
        NvIndexProto();

    if( nullPlatformAuth )
        GetSetEncryptParamTests();

    if( tpmType != TPM_TYPE_PTT && nullPlatformAuth )
    {
        TestEncryptDecryptSession();

        SimpleHmacOrPolicyTest( true );

        SimpleHmacOrPolicyTest( false );
    }

    for( i = 0; i < (UINT32)passCount; i++ )
    {
        printf( "\n****** pass #: %d ******\n\n", i );

        TestTpmGetCapability();

        TestPcrExtend();

        TestHash();

        TestPolicy();

        if( nullPlatformAuth )
            TestTpmClear();

        if( nullPlatformAuth )
            TestChangeEps();

        if( tpmType != TPM_TYPE_PTT && nullPlatformAuth )
            TestChangePps();

        if( nullPlatformAuth )
            TestHierarchyChangeAuth();

        TestGetRandom();

        if( i < 1 )
            TestShutdown();

        if( nullPlatformAuth )
            TestNV();

        TestCreate();

        if( tpmType != TPM_TYPE_PTT && nullPlatformAuth )
            NvIndexProto();

        if( nullPlatformAuth )
            PasswordTest();

        if( tpmType != TPM_TYPE_PTT && nullPlatformAuth )
            HmacSessionTest();

        TestQuote();

        TestDictionaryAttackLockReset();

//        testpcrallocate();

        TestUnseal();

//        testrm();// not support cancel command

        if( tpmType != TPM_TYPE_PTT )
            EcEphemeralTest();

#if 0
        testrsaencryptdecrypt();
#endif
    }

	symmetricEncryptDecryptTest();
        asymmetricEncryptDecryptTest();
        verifySignatureExternalTest();
        verifySignatureCreatedTest();
        nvExtensionTest();
        pcrExtendedTest();
        TestClockTime();
	
    // clear out rm entries for objects.
    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );
    rval = Tss2_Sys_FlushContext( sysContext, loadedSha1KeyHandle );
    CheckPassed( rval );

endtests:
    if( tpmType == TPM_TYPE_SIMULATOR )
    {
        PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    }
    return;
}

void SimpleHmacSessionTest()
{
    SimpleHmacOrPolicyTest( true );
}

void SimplePolicySessionTest()
{
    SimpleHmacOrPolicyTest( false );
}

void PrintHelp();
void PrintStartupTestDescription()
{
/*    if( simulatorTest )
    {
        printf("  First do TPM reset:\n\tTpmReset:Passed\n"
           "  TPM initialization:\n\tTss2_Sys_Startup(TPM_SU_CLEAR):Passed(rval != TPM_RC_INITIALIZE)\n\tTss2_Sys_Startup(TPM_SU_CLEAR):Failed(0x100)\n"
           "  Cycle power using simulator interface:\n\tPlatformCommand( MS_SIM_POWER_OFF ):Passed\n\tPlatformCommand( MS_SIM_POWER_ON ):Passed\n"
           "  Test the syncronous, non-one-call interface:\n\tTss2_Sys_Startup_Prepare(TPM_SU_CLEAR):Passed\n\tTss2_Sys_Execute\n"
           "  Cycle power using simulator interface:\n\tPlatformCommand( MS_SIM_POWER_OFF ):Passed\n\tPlatformCommand( MS_SIM_POWER_ON ):Passed\n"
           "  Test the asyncronous, non-one-call interface:\n\tTss2_Sys_Startup_Prepare(TPM_SU_CLEAR):Passed\n\tTss2_Sys_ExecuteAsync:Passed\n\t"
              "Tss2_Sys_ExecuteFinish(TSS2_TCTI_TIMEOUT_BLOCK):Failed(if( startupAlreadyDone == 1) )/Passed\n");
    }
    else
*/
    {
        printf("  First do TPM reset:\n\tTpmReset:Passed\n"
           "  TPM initialization:\n\tTss2_Sys_Startup(TPM_SU_CLEAR):Passed(rval != TPM_RC_INITIALIZE)\n\tTss2_Sys_Startup(TPM_SU_CLEAR):Failed(0x100)\n"
           "  Test the syncronous, non-one-call interface:\n\tTss2_Sys_Startup_Prepare(TPM_SU_CLEAR):Passed\n\tTss2_Sys_Execute\n"
           "  Test the asyncronous, non-one-call interface:\n\tTss2_Sys_Startup_Prepare(TPM_SU_CLEAR):Passed\n\tTss2_Sys_ExecuteAsync:Passed\n\t"
              "Tss2_Sys_ExecuteFinish(TSS2_TCTI_TIMEOUT_BLOCK):Failed(if( startupAlreadyDone == 1) )/Passed\n");
    }
}
void PrintCreateTestDescription()
{
    printf("  CreatePrimary Case(primaryHandle:TPM_RH_PLATFORM,authArray:{1,{sessionHandle:TPM_RS_PW}},outPublic.t.size:0xff,creationData.t.size:0):Failed(0x8000b)\n"
           "  CreatePrimary Case(primaryHandle:TPM_RH_PLATFORM,authArray:{1,{sessionHandle:TPM_RS_PW}},outPublic.t.size:0,creationData.t.size:0xff):Failed(0x8000b)\n"
           "  CreatePrimary Case(primaryHandle:TPM_RH_PLATFORM,authArray:{1,{sessionHandle:TPM_RS_PW}},outPublic.t.size:0,creationData.t.size:0):Passed\n"
           "  Create Case(parentHandle:handle2048rsa,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{2,{0x00,0xff}}}}):Passed\n"
           "  Load Case(parentHandle:handle2048rsa,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{2,{0x00,0xff}}}},&outPrivate, &outPublic):Passed\n"
           "  HandleToNameFunctionPtr Case(loadedSha1KeyHandle,name1):Passed\n"
           "  CompareTPM2B Case(name.b,name1.b):Passed\n");
}
void PrintNVTestDescription()
{
    printf("  NV_Read Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015,Size:32,authArray:{1,{TPM_RS_PW}}):Failed(0x28B)\n"
           "  NV_DefineSpace Case(authHandle:TPM_RH_PLATFORM,nvAuth:{20,{0,...19}},publicInfo:{nvIndex:0x1500015,"
               "authPolicy:{0},attribute:0x40014001}):Passed\n"
           "  NV_ReadPublic Case(nvIndex:0x1500015,nvPublic:0):Passed\n"
           "  NV_Read Case(auHandle:TPM_RH_PLATFORM,nvIndex:0x1500015,dataSize:32):Failed(0x14A)\n"
           "  NV_DefineSpace Case(authHandle:TPM_RH_PLATFORM,nvAuth:{20,{0,...19}},publicInfo:{nvIndex:0x1500015,"
               "authPolicy:{0},attribute:0x40014001}):Failed(0x14C)\n"
           "  NV_Write Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015):Passed\n"
           "  NV_Read Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015,dataSize:32):Passed\n");
    if (tpmType != TPM_TYPE_PTT)
        printf("  NV_WriteLock Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015):Passed\n"
               "  NV_Write Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015):Failed(0x148)\n");
    printf("  NV_UndefineSpace Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015):Passed\n"
           "  NV_DefineSpace Case(authHandle:TPM_RH_PLATFORM,nvAuth:{20,{0,...19}},publicInfo:{nvIndex:0x1500015,"
               "authPolicy:{0},attribute:0x40014001}):Passed\n"
           "  NV_UndefineSpace Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500015):Passed\n"
           "  NV_DefineSpace Case(authHandle:TPM_RH_OWNER,nvAuth:{20,{0,...19}},publicInfo:{nvIndex:0x1500016,"
               "authPolicy:{0},attribute:0x24002}):Passed\n"
           "  NV_ReadPublic Case(nvIndex:0x1500016,nvPublic:{0}):Passed\n"
           "  NV_Read Case(authHandle:TPM_RH_PLATFORM,nvIndex:0x1500016,size:32,offset:0):Failed(0x149)\n"
           "  NV_UndefineSpace Case(authHandle:TPM_RH_OWNER,nvIndex:0x1500016):Passed\n"
           "  NV_DefineSpace Case(authHandle:TPM_RH_OWNER,nvAuth:{20,{0,...19}},publicInfo:{nvIndex:0x1500016,"
               "authPolicy:{0},attribute:0x24002}):Passed\n"
           "  NV_UndefineSpace Case(authHandle:TPM_RH_OWNER,nvIndex:0x1500016):Passed\n");
}
void PrintDALRTestDescription()
{
    printf("  DictionaryAttackLockReset Case(lockHandle:0x4000000A,authArray{1,{TPM_RS_PW,}}):Passed\n");
}
void PrintGetSetDecryptParamTest()
{
    printf("  Tss2_Sys_GetDecryptParam:Failed(TSS2_SYS_RC_BAD_SEQUENCE)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:4,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Failed(TSS2_SYS_RC_BAD_SEQUENCE)\n"
           "  Tss2_Sys_NV_Write_Prepare(authHandle:TPM20_INDEX_PASSWORD_TEST,nvIndex:TPM20_INDEX_PASSWORD_TEST,data:{{4,{0x01,0x01,0x02,0x03,}}},offset:0x55aa):Passed\n"
           "  Tss2_Sys_GetDecryptParam(sysContext:0):Failed(TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_GetDecryptParam(decryptParamSize:0):Failed(TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_GetDecryptParam(decryptParamBuffer:0):Failed(TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:4,decryptParamBuffer:0):Failed(TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_SetDecryptParam(sysContext:0,decryptParamSize:4,decryptParamBuffer:0):Failed(TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:5,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Failed(TSS2_SYS_RC_BAD_SIZE)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:3,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Failed(TSS2_SYS_RC_BAD_SIZE)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:4,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Passed\n"
           "  Tss2_Sys_GetDecryptParam:Passed\n"
           "  Tss2_Sys_GetCpBuffer:Passed\n"
           "  Tss2_Sys_NV_Read_Prepare(authHandle:TPM20_INDEX_PASSWORD_TEST,nvIndex:TPM20_INDEX_PASSWORD_TEST,size:sizeof(nvWriteData)-2,offset:0):Passed\n"
           "  Tss2_Sys_GetDecryptParam:Failed(TSS2_SYS_RC_NO_DECRYPT_PARAM)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:4,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Failed(TSS2_SYS_RC_NO_DECRYPT_PARAM)\n"
           "  Tss2_Sys_NV_Write_Prepare(authHandle:TPM20_INDEX_PASSWORD_TEST,nvIndex:TPM20_INDEX_PASSWORD_TEST,data:0,offset:0x55aa):Passed\n"
           "  Tss2_Sys_GetDecryptParam:Passed\n"
           "  Tss2_Sys_GetCpBuffer:Passed\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:1003,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Failed(TSS2_SYS_RC_INSUFFICIENT_CONTEXT)\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:1002,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Passed\n"
           "  Tss2_Sys_NV_Write_Prepare(authHandle:TPM20_INDEX_PASSWORD_TEST,nvIndex:TPM20_INDEX_PASSWORD_TEST,data:0,offset:0x55aa):Passed\n"
           "  Tss2_Sys_GetDecryptParam:Passed\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:4,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Passed\n"
           "  Tss2_Sys_GetCpBuffer:Passed\n"
           "  Tss2_Sys_NV_Write_Prepare(authHandle:TPM20_INDEX_PASSWORD_TEST,nvIndex:TPM20_INDEX_PASSWORD_TEST,data:0,offset:0x55aa):Passed\n"
           "  Tss2_Sys_SetDecryptParam(decryptParamSize:1,decryptParamBuffer:{0xde,0xad,0xbe,0xef}):Failed(TSS2_SYS_RC_BAD_SIZE)\n");
}
void PrintGetVersionTestDescription()
{
    printf("  GetCapability Case(capability:TPM_CAP_TPM_PROPERTIES,property:TPM_PT_REVISION,propertyCount:1):Passed\n");
}
void PrintSelfTestDescription()
{
    printf("  SelfTest Case(fullTest:YES):Passed\n"
           "  SelfTest Case(fullTest:NO):Passed\n"
           "  SelfTest Case(fullTest:YES):Passed\n");
}
void PrintSapiTestDescription()
{
    printf("  Test the one-call interface:\n\tTss2_Sys_GetTestResult:Passed\n"
           "  Test the syncronous,non-one-call interface:\n\tTss2_Sys_GetTestResult_Prepare:Passed\n\t"
           "Tss2_Sys_Execute:Passed\n\tTss2_Sys_GetTestResult_Complete:Passed\n"
           "  Test the asyncronous,non-one-call interface:\n\tTss2_Sys_GetTestResult_Prepare:Passed\n\t"
           "Tss2_Sys_ExecuteAsync:Passed\n\tTss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Passed\n\tTss2_Sys_GetTestResult_Complete:Passed\n"
           "  TpmReset Case:Passed\n"
           "  Check case of ExecuteFinish receving TPM error code:\n\tTss2_Sys_GetCapability_Prepare(capability:TPM_CAP_TPM_PROPERTIES,property:TPM_PT_ACTIVE_SESSIONS_MAX,propertyCount:1):Passed\n\t"
           "Tss2_Sys_ExecuteAsync:Passed\n\tTss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Failed(0x100)\n\t"
           "Tss2_Sys_GetCapability_Complete:Failed(TSS2_SYS_RC_BAD_SEQUENCE)\n"
           "  TPMS_Startup(TPM_SU_CLEAR):Passed\n");
}
void PrintStartAuthSessionTest()
{
//    if( simulatorTest == 1 )
    {
        printf("  StartAuthSessionWithParams(sessionType:TPM_SE_POLICY):Passed\n"
           "  Tss2_Sys_FlushContext:Passed\n"
           "  StartAuthSessionWithParams(sessionType:0xff):Failed(TPM_RC_VALUE + TPM_RC_P + TPM_RC_3)\n"
           "  Try starting a bunch to see if resource manager handles this correctly:"
              "i from 0 to debugMaxActiveSessions*3:\n\tStartAuthSessionWithParams(session:sessions[i],sessionType:TPM_SE_POLICY):Passed\n\t"
              "if( i == 0 ):Tss2_Sys_ContextSave(saveHandle:sessions[i]->sessionHandle):Passed\n"
           "  Tss2_Sys_ContextLoad:Failed( TPM_RC_HANDLE + TPM_RC_P + ( 1 << 8 ) )\n"
           "  Tss2_Sys_PolicyLocality:Failed( TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_HANDLE + ( 1 << 8 ) )\n"
           "  Tss2_Sys_PolicyLocality:Failed( TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_VALUE + TPM_RC_S + ( 1 << 8 ) )\n"
           "  Clean up the sessions:i from 0 to debugMaxActiveSessions(32)*3:\n\t"
              "Tss2_Sys_FlushContext(flushHandle:sessions[i].sessionHandle)\n\t"
              "EndAuthSession(session:sessions[i])\n"
           "  StartAuthSessionWithParams(session:sessions[0],sessionType:TPM_SE_POLICY):Passed\n"
           "  i from 1 to 300:\n\tStartAuthSessionWithParams(session:sessions[i],sessionType:TPM_SE_POLICY):Passed\n\t"
              "Tss2_Sys_FlushContext(flushHandle:sessions[i].sessionHandle):Passed\n\tEndAuthSession(session:sessions[i]):Passed\n"
           "  StartAuthSessionWithParams(session:sessions[8],sessionType:TPM_SE_POLICY):Passed\n"
           "  i from 9 to DEBUG_GAP_MAX(255):\n\tStartAuthSessionWithParams(session:sessions[i],sessionType:TPM_SE_POLICY):Passed\n\t"
              "Tss2_Sys_FlushContext:Passed\n\tEndAuthSession:Passed\n"
           "  i from 0 to 5:\n\tStartAuthSessionWithParams(session:sessions[i+16],sessionType:TPM_SE_POLICY):Passed\n"
           "  i from 0 to 5:\n\tTss2_Sys_FlushContext(flushHandle:sessions[i+16].sessionHandle):Passed\n\tEndAuthSession(session:sessions[i+16]):Passed\n"
           "  Tss2_Sys_FlushContext(flushHandle:sessions[0].sessionHandle):Passed\n"
           "  EndAuthSession(session:sessions[0]):Passed\n"
           "  Tss2_Sys_FlushContext(flushHandle:sessions[8].sessionHandle):Passed\n"
           "  EndAuthSession(session:sessions[8]):Passed\n");
    }
//    else
//        printf("The StartAuthSessionTest Cases can't be passed right now.\n");
}
void PrintHierarchyControlTest()
{
//    if( simulatorTest == 1 )
    {
        printf("  NV_DefineSpace Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},auth:{20,{0,...19}},publicInfo:{index:0x1500015,nameAlg:TPM_ALG_SHA1,dataSize:32,attributes:0x40014001):Passed\n"
           "  NV_ReadPublic Case(nvIndex:0x1500015,nvPublic.t.size:0xff):Failed(0x8000b)\n"
           "  NV_ReadPublic Case(nvIndex:0x1500015,nvPublic.t.size:0x00):Passed\n"
           "  NV_Read Case(authHandle:0x4000000C, nvIndex:0x1500015):Failed(0x14a)\n"
           "  HierarchyControl Case(authHandle:0x4000000C,hierarchy:0x4000000C,state:NO):Passed\n"
           "  NV_Read Case(authHandle:0x4000000C, nvIndex:0x1500015):Failed(0x185)\n"
           "  HierarchyControl Case(authHandle:0x4000000C,hierarchy:0x4000000C,state:YES):Failed(0x185)\n"
           "  TpmReset Case:Passed\n"
           "  TPM2_Startup(TPM_SU_CLEAR):Passed\n"
           "  HierarchyControl Case(authHandle:0x4000000C,hierarchy:0x4000000C,state:YES):Passed\n"
           "  NV Undefine Case(authHandle:0x4000000C,nvIndex:0x1500015):Passed\n");
    }
/*    else
    {
        printf("  NV_DefineSpace Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},auth:{20,{0,...19}},publicInfo:{index:0x1500015,nameAlg:TPM_ALG_SHA1,dataSize:32,attributes:0x40014001):Passed\n"
           "  NV_ReadPublic Case(nvIndex:0x1500015,nvPublic.t.size:0xff):Failed(0x8000b)\n"
           "  NV_ReadPublic Case(nvIndex:0x1500015,nvPublic.t.size:0x00):Passed\n"
           "  NV_Read Case(authHandle:0x4000000C, nvIndex:0x1500015):Failed(0x14a)\n"
           "  NV Undefine Case(authHandle:0x4000000C,nvIndex:0x1500015):Passed\n");
    }
*/
}
void PrintNvIndexProtoTest()
{
    printf("  ProvisionNvAux Cases\n"
           "  ProvisionOtherIndices Cases\n"
           "  TpmAuxReadWriteTest Cases\n"
           "  TpmOtherIndicesReadWriteTest Cases\n"
           "  NV_UndefineSpace Case(authHandle:0x4000000C,nvIndex:0x1800003):Passed\n"
           "  NV_UndefineSpace Case(authHandle:0x4000000C,nvIndex:0x1800001):Passed\n"
           "  NV_UndefineSpace Case(authHandle:0x4000000C,nvIndex:0x1400001):Passed\n");
}
void PrintGetSetEncryptParamTest()
{
    printf("  Tss2_Sys_NV_Write_Prepare(authHandle:0x1500020,nvIndex:0x1500020,data:{{4,{0xde,0xad,0xbe,0xef,}}},offset:0):Passed\n"
           "  Tss2_Sys_GetEncryptParam:Failed(0x80007/TSS2_SYS_RC_BAD_SEQUENCE)\n"
           "  Tss2_Sys_SetEncryptParam(encryptParamSize:4,encryptParamBuffer:{0xde,0xad,0xbe,0xef,}):Failed(0x80007/TSS2_SYS_RC_BAD_SEQUENCE)\n"
           "  NV_DefineSpace Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},auth:0,publicInfo:{index:0x1500020,dataSize:32,attributes:0x44040004):Passed\n"
           "  Tss2_Sys_NV_Write_Prepare(authHandle:0x1500020,nvIndex:0x1500020,data:{{4,{0xde,0xad,0xbe,0xef,}}},offset:0):Passed\n"
           "  NV_Write Case(authHandle:0x1500020,nvIndex:0x1500020,data:{{4,{0xde,0xad,0xbe,0xef,}}},offset:0):Passed\n"
           "  Tss2_Sys_GetEncryptParam:Failed(0x8000f/TSS2_SYS_RC_NO_ENCRYPT_PARAM)\n"
           "  Tss2_Sys_NV_Read_Prepare(authHandle:0x1500020,nvIndex:0x1500020,size:4,offset:0}:Passed\n"
           "  NV_Read Case(authHandle:0x1500020,nvIndex:0x1500020,size:4,offset:0):Passed\n"
           "  Tss2_Sys_GetEncryptParam:Passed\n"
           "  Tss2_Sys_SetEncryptParam(encryptParamSize:4,encryptParamBuffer:{01,02,03,04}):Passed\n"
           "  Tss2_Sys_GetEncryptParam:Passed\n"
           "  NV_UndefineSpace Case(authHandle:0x4000000C,nvIndex:0x1500020):Passed\n"
           "  Tss2_Sys_GetEncryptParam(sysContext:0):Failed(0x80005/TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_GetEncryptParam(encryptParamSize:0):Failed(0x80005/TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_GetEncryptParam(encryptParamBuffer:0):Failed(0x80005/TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_SetEncryptParam(encryptParamSize:4,encryptParamBuffer:0):Failed(0x80005/TSS2_SYS_RC_BAD_REFERENCE)\n"
           "  Tss2_Sys_SetEncryptParam(sysContext:0):Failed(0x80005/TSS2_SYS_RC_BAD_REFERENCE)\n");
}
void PrintEncryptDecryptSessionTest()
{
    printf("  NV_DefineSpace Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},publicInfo:{index:TPM20_INDEX_TEST1,dataSize:32,attributes:0x44040004):Passed\n"
           "  CFB mode:i=0,symmetric.algorithm = TPM_ALG_AES:\n\t"
           "StartAuthSessionWithParams(sessionType:TPM_SE_POLICY,algId:TPM_ALG_SHA256):Passed\n\t"
           "Tss2_Sys_NV_Write_Prepare(authHandle:TPM20_INDEX_TEST1,nvIndex:TPM20_INDEX_TEST1,data:0,offset:0):Passed\n\t"
           "Tss2_Sys_SetCmdAuths(authsArray:{2,{{0,},{0,}}}):Passed\n\t"
           "Tss2_Sys_GetDecryptParam:Passed\n\t"
           "EncryptCommandParam(session:encryptDecryptSession,clearData:{{4,{0xef,0xbe,0xad,0xde}}}):Passed\n\t"
           "Tss2_Sys_SetDecryptParam(decryptParamSize:4,decryptParamBuffer:{0x32,0x9a,0x1f,0xd3}):Passed\n\t"
           "Tss2_Sys_ExecuteAsync:Passed\n\t"
           "Tss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Passed\n\t"
           "Tss2_Sys_GetRspAuths:Passed\n\t"
           "Tss2_Sys_NV_Read(authHandle:TPM20_INDEX_TEST1,nvIndex:TPM20_INDEX_TEST1):Passed\n\t"
           "Tss2_Sys_NV_Read_Prepare(authHandle:TPM20_INDEX_TEST1,nvIndex:TPM20_INDEX_TEST1):Passed\n\t"
           "Tss2_Sys_SetCmdAuths:Passed\n\t"
           "Tss2_Sys_Execute:Passed\n\t"
           "Tss2_Sys_GetEncryptParam:Passed\n\t"
           "Tss2_Sys_GetRspAuths:Passed\n\t"
           "DecryptResponseParam(session:encryptDecryptSession):Passed\n\t"
           "Tss2_Sys_SetEncryptParam:Passed\n\t"
           "Tss2_Sys_NV_Read_Complete:Passed\n\t"
           "Tss2_Sys_FlushContext(flushHandle:encryptDecryptSession->sessionHandle):Passed\n\t"
           "EndAuthSession(session:encryptDecryptSession):Passed\n\n"
        "  XOR mode:i=1,symmetric.algorithm = TPM_ALG_XOR:\n\t"
           "StartAuthSessionWithParams(sessionType:TPM_SE_POLICY,algId:TPM_ALG_SHA256):Passed\n\t"
           "Tss2_Sys_NV_Write_Prepare(authHandle:TPM20_INDEX_TEST1,nvIndex:TPM20_INDEX_TEST1,data:0,offset:0):Passed\n\t"
           "Tss2_Sys_SetCmdAuths(authsArray:{2,{{0,},{0,}}}):Passed\n\t"
           "Tss2_Sys_GetDecryptParam:Passed\n\t"
           "EncryptCommandParam:Passed\n\t"
           "Tss2_Sys_SetDecryptParam:Passed\n\t"
           "Tss2_Sys_ExecuteAsync:Passed\n\t"
           "Tss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Passed\n\t"
           "Tss2_Sys_GetRspAuths:Passed\n\t"
           "Tss2_Sys_NV_Read(authHandle:TPM20_INDEX_TEST1,nvIndex:TPM20_INDEX_TEST1):Passed\n\t"
           "Tss2_Sys_NV_Read_Prepare(authHandle:TPM20_INDEX_TEST1,nvIndex:TPM20_INDEX_TEST1):Passed\n\t"
           "Tss2_Sys_SetCmdAuths:Passed\n\t"
           "Tss2_Sys_Execute:Passed\n\t"
           "Tss2_Sys_GetEncryptParam:Passed\n\t"
           "Tss2_Sys_GetRspAuths:Passed\n\t"
           "DecryptResponseParam:Passed\n\t"
           "Tss2_Sys_SetEncryptParam:Passed\n\t"
           "Tss2_Sys_NV_Read_Complete:Passed\n\t"
           "Tss2_Sys_FlushContext:Passed\n\t"
           "EndAuthSession(session:encryptDecryptSession):Passed\n\n"
        "  Tss2_Sys_NV_UndefineSpace(nvIndex:TPM20_INDEX_TEST1):Passed\n");
}
void PrintGetCapabilityTestDescription()
{
    printf("  GetCapability Case(capability:TPM_CAP_TPM_PROPERTIES,property:TPM_PT_MANUFACTURER,propertyCount:1):Passed\n"
           "  GetCapability Case(capability:TPM_CAP_TPM_PROPERTIES,property:TPM_PT_MAX_COMMAND_SIZE,propertyCount:1):Passed\n"
           "  GetCapability Case(capability:TPM_CAP_TPM_PROPERTIES,property:TPM_PT_MAX_COMMAND_SIZE,propertyCount:40):Passed\n"
           "  GetCapability Case(capability:TPM_CAP_TPM_PROPERTIES,property:TPM_PT_MAX_RESPONSE_SIZE,propertyCount:1):Passed\n");
//         "  GetCapability Case(capability:0xff,property:TPM_PT_MANUFACTURER,propertyCount:1):Passed Case\n"
}
void PrintPcrExtendTestDescription()
{
    printf("  PCR_Read Case(pcrSelectionIn:{1,{TPM_ALG_SHA1,3,{128,0,0}}}):Passed\n"
           "  PCR_Extend Case(pcrHandle:PCR_7,authArray:{1,{TPM_RS_PW,0}},digests:{1,{hashAlg:4,digest:{sha1:{0,...35},...}}}):Passed\n"
           "  PCR_Read Case(pcrSelectionIn:{1,{TPM_ALG_SHA1,3,{128,0,0}}}):Passed\n"
           "  PCR_Read Case(pcrSelectionIn:{1,{TPM_ALG_SHA1,4,{128,0,0}}}):Failed(0x1c4)\n"
           "  PCR_Event Case(pcrHandle:PCR_8,eventData:{{4,{0,0xff,0x55,0xaa}}}):Passed\n");
}
void PrintHashTestDescription()
{
    printf("  Tss2_Sys_HashSequenceStart(auth:{{2,{0,0xff}}},hashAlg:TPM_ALG_SHA1):Passed\n"
           "  Tss2_Sys_SequenceUpdate(sequenceHandle:sequenceHandle[0],dataToHash:{{1024,{0x00,...,0xef}}}):Passed\n"
           "  Try starting a bunch of sequences:\n\tTss2_Sys_HashSequenceStart(i=0,auth:{{2,{0,0xff}}}):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=1,auth:{{2,{0,0xff}}}):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=2,auth:{{2,{0,0xff}}}):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=3,auth:{{2,{0,0xff}}}):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=4,auth:{{2,{0,0xff}}}):Passed\n"
           "  End the created sequences:\n\tTss2_Sys_SequenceComplete(i=0,dataToHash.t.size:0):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=1,dataToHash.t.size:0):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=2,dataToHash.t.size:0):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=3,dataToHash.t.size:0):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=4,dataToHash.t.size:0):Passed\n"
           "  Try to finish the interrupted sequence:\n\tTss2_Sys_SequenceUpdate:Passed\n\tTss2_Sys_SequenceComplete:Passed\n"
           "  Try starting a bunch of sequences:\n\t"
           "Tss2_Sys_HashSequenceStart(i=0):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=1):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=2):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=3):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=4):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=5):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=6):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=7):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=8):Passed\n\t"
           "Tss2_Sys_HashSequenceStart(i=9):Passed\n"
           "  End the created sequences:\n\t"
           "Tss2_Sys_SequenceComplete(i=9):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=8):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=7):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=6):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=5):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=4):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=3):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=2):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=1):Passed\n\t"
           "Tss2_Sys_SequenceComplete(i=0):Passed\n");
}
void PrintPolicyTestDescription()
{
    printf("  PASSWORD:\n\tPolicyPassword Case:Passed\n\t"
                       "PolicyGetDigest Case:Passed\n\t"
                       "FlushContext Case:Passed\n\t"
                       "EndAuthSession:Passed\n\t"
                       "CreatePrimary Case:Passed\n\t"
                       "Create Case:Passed\n\t"
                       "Tss2_Sys_Load:Passed\n\t"
                       "PolicyPassword Case:Passed\n\t"
                       "PolicyGetDigest Case:Passed\n\t"
                       "Tss2_Sys_Unseal:Failed(0x98E)\n\t"
                       "Tss2_Sys_DictionaryAttackLockReset:Passed\n\t"
                       "Tss2_Sys_Unseal:Passed\n\t"
                       "Tss2_Sys_FlushContext:Passed\n\t"
                       "Tss2_Sys_FlushContext:Passed\n\t"
                       "EndAuthSession:Passed\n"
           "  PASSWORD/PCR:\n\tTss2_Sys_PolicyPassword:Passed\n\t"
                       "Tss2_Sys_PCR_Read:Passed\n\t"
                       "Tss2_Sys_PolicyPCR:Passed\n\t"
                       "PolicyGetDigest Case:Passed\n\t"
                       "FlushContext Case:Passed\n\t"
                       "EndAuthSession:Passed\n\t"
                       "CreatePrimary Case:Passed\n\t"
                       "Create Case:Passed\n\t"
                       "Tss2_Sys_Load:Passed\n\t"
                       "Tss2_Sys_PolicyPassword:Passed\n\tTss2_Sys_PCR_Read:Passed\n\t"
                       "Tss2_Sys_PolicyPCR:Passed\n\tPolicyGetDigest Case:Passed\n\t"
                       "Tss2_Sys_Unseal:Failed(0x98E)\n\tTss2_Sys_DictionaryAttackLockReset:Passed\n\t"
                       "Tss2_Sys_Unseal:Passed\n\tTss2_Sys_FlushContext:Passed\n\t"
                       "Tss2_Sys_FlushContext:Passed\n\tEndAuthSession:Passed\n");
    if (tpmType != TPM_TYPE_PTT)
        printf("  AUTHVALUE:\n\tTss2_Sys_PolicyAuthValue:Passed\n\tPolicyGetDigest Case:Passed\n\t"
                       "FlushContext Case:Passed\n\tEndAuthSession:Passed\n\t"
                       "CreatePrimary Case:Passed\n\tCreate Case:Passed\n\t"
                       "Tss2_Sys_Load:Passed\n\tTss2_Sys_PolicyAuthValue:Passed\n\t"
                       "PolicyGetDigest Case:Passed\n\t"
                       "Tss2_Sys_Unseal:Failed(0x98E)\n\tTss2_Sys_DictionaryAttackLockReset:Passed\n\t"
                       "Tss2_Sys_Unseal_Prepare:Passed\n\tAddEntity:Passed\n\t"
                       "ComputeCommandHmacs:Passed\n\tTss2_Sys_Unseal:Passed\n\tDeleteEntity:Passed\n\t"
                       "Tss2_Sys_FlushContext:Passed\n\tTss2_Sys_FlushContext:Passed\n\tEndAuthSession\n");
}
void PrintClearTestDescription()
{
    printf("  Clear Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW}}):Passed\n"
           "  ClearControl Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW}},disable:YES):Passed\n"
           "  Clear Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW}}):Failed(0x120)\n"
           "  ClearControl Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW}},disable:NO):Passed\n"
           "  Clear Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW,sessionAttributes:0xFF}}):Failed(0x9A1)\n"
           "  ClearControl Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW,sessionAttributes:0xFF}},disable:NO):Failed(0x9A1)\n");
}
void PrintChangeEpsTestDescription()
{
    printf("  ChangeEps Case(authHandle:0x4000000C,authArray:{1,{sessionAttributes:0,sessionHandle:TPM_RS_PW,hmac.t.size:0}}):Passed\n"
           "  ChangeEps Case(authHandle:0x4000000C,authArray:{1,{sessionAttributes:0,sessionHandle:TPM_RS_PW,hmac.t.size:0x10}}):Failed(0x9A2)\n");
}
void PrintChangePpsTestDescription()
{
    printf("  ChangePps Case(authHandle:0x4000000C,authArray:{1,{sessionAttributes:0,sessionHandle:TPM_RS_PW,hmac.t.size:0}}):Passed\n"
           "  ChangePps Case(authHandle:0x4000000C,authArray:{1,{sessionAttributes:0,sessionHandle:TPM_RS_PW,hmac.t.size:0x10}}):Failed(0x9A2)\n");
}
void PrintHierarchyChangeAuthDescription()
{
    printf("  HierarchyChangeAuth Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW}},newAuth:{0}):Passed\n"
           "  HierarchyChangeAuth Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW}},newAuth:{size=20,buffer:{0,...19}}):Passed\n"
           "  HierarchyChangeAuth Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{size=20,buffer:{0,...19}}}},newAuth:{size=20,buffer:{0,...19}}):Passed\n"
           "  HierarchyChangeAuth Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{size=20,buffer:{0,...19}}}},newAuth:{0}):Passed\n"
           "  HierarchyChangeAuth Case(authHandle:0x4000000C,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{size=20,buffer:{0,...19}}}},newAuth:{0}):Failed(0x9A2)\n"
           "  HierarchyChangeAuth Case(authHandle:0,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{size=20,buffer:{0,...19}}}},NewAuth:{0}):Failed(0x184)\n");
}
void PrintGetRandomTestDescription()
{
    printf("  GetRandom Case(authArray:0,bytesRequested:20):Passed\n"
           "  GetRandom Case(authArray:0,bytesRequested:20):Passed\n");
}
void PrintShutdownTestDescription()
{
    printf("  Shutdown Case(shutdownType:TPM_SU_STATE):Passed\n"
           "  Shutdown Case(shutdownType:TPM_SU_CLEAR):Passed\n");
//           "Shutdown Case(AuthArray:{0},shutdownType:0xff):Failed Case(0x84)\n"
}
void PrintPasswordTestDescription()
{
    printf("  NV_DefineSpace Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},Auth:{{'test password'}},publicInfo:{index:0x1500020,nameAlg:TPM_ALG_SHA1,dataSize:32,attributes:0x40040004}):Passed\n"
           "  NV_Write Case(authHandle:0x1500020,nvIndex:0x1500020,authArray:{1,{TPM_RS_PW,right password}}):Passed\n"
           "  NV_Write Case(authHandle:0x1500020,nvIndex:0x1500020,authArray:{1,{TPM_RS_PW,wrong password}}):Failed(0x148)\n"
           "  NV_UndefineSpace Case(authHandle:0x4000000C,nvIndex:0x1500020):Passed\n");
}
void PrintHmacSessionTestDescription()
{
    printf("  Tss2_Sys_RSA_Encrypt:Passed\n"
           "  Tss2_Sys_NV_DefineSpace:Passed\n"
           "  AddEntity( TPM20_INDEX_PASSWORD_TEST, &nvAuth ):Passed\n"
           "  HandleToNameFunctionPtr:Passed\n"
           "  StartAuthSessionWithParams(sessionType:TPM_SE_HMAC):Passed\n"
           "  HandleToNameFunctionPtr:Passed\n"
           "  Tss2_Sys_NV_Write_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Write:Failed(TPM_RC_S + TPM_RC_1 + TPM_RC_AUTH_FAIL)\n"
           "  Tss2_Sys_DictionaryAttackLockReset:Passed\n"
           "  Tss2_Sys_NV_Read_Prepare:Passed\n"
           "  Tss2_Sys_NV_Write_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Write:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Read:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  CompareTPM2B:Passed\n"
           "  if( hmacTestSetups[j].bound != TPM_RH_NULL )EndAuthSession:Passed\n"
           "  StartAuthSessionWithParams:Passed\n"
           "  Tss2_Sys_NV_Write_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Write:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  Tss2_Sys_NV_Read_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Read:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  Tss2_Sys_NV_UndefineSpace:Passed\n"
           "  DeleteEntity(entityHandle:TPM20_INDEX_PASSWORD_TEST):Passed\nEndAuthSession:Passed\n");
}
void PrintQuoteTestDescription()
{
    printf("  Quote Case(signHandle:loadedSha1KeyHandle,authArray{1,{sessionHandle:TPM_RS_PW,hmac:{2,{0x00,0xff}}}},\n\t"
              "qualifyingData:{4,{0x00,0xff,0x55,0xaa}},pcrSelection:{1,{TPM_ALG_SHA1,3,{0,0,4}}}):Passed\n");
}
void PrintPcrAllocateTestDescription()
{
    printf("  PCR_Allocate Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},pcrSelection:{count:0}):Passed\n"
           "  PCR_Allocate Case(authHandle:0x4000000C,authArray:{1,{TPM_RS_PW}},pcrSelection:{count:1,{hash:TPM_ALG_SHA256,{160,0,0}}}):Passed\n");

}
void PrintUnsealTestDescription()
{
    printf("  Tss2_Sys_Create(parentHandle:handle2048rsa,authArray:{1,{sessionHandle:TPM_RS_PW,hmac:{2,{0x00,0xff}}}},inSensitive):Passed\n"
           "  Tss2_Sys_LoadExternal(hierarchy:0x4000000C):Passed\n"
           "  Tss2_Sys_FlushContext(flushHandle:loadedObjectHandle):Passed\n"
           "  Tss2_Sys_Load(parentHandle:handle2048rsa):Passed\n"
           "  Tss2_Sys_Unseal(itemHandle:loadedObjectHandle,authsArray{1,{sessionHandle:TPM_RS_PW,hmac:{{4,{'test'}}}})\n"
           "  Tss2_Sys_FlushContext(flushHandle:loadedObjectHandle):Passed\n");
}
void PrintRMTestDescription()
{
//    if( simulatorTest == 1 )
    {
        printf("  Tss2_Sys_Create(parentHandle:handle2048rsa):Failed(TSS2_RESMGR_UNOWNED_HANDLE)\n"
           "  Tss2_Sys_ContextSave(saveHandle:handle2048rsa):Passed\n"
           "  Tss2_Sys_ContextLoad:Passed\n"
           "  Tss2_Sys_FlushContext:Passed\n"
           "  LOCALITY TESTS:\n\tsetLocality(0,0):Failed(TSS2_TCTI_RC_BAD_REFERENCE)\n\t"
                                "setLocality(otherResMgrTctiContext,0):Passed\n"
           "  Tss2_Sys_ContextLoad:Passed\n"
           "  Tss2_Sys_FlushContext_Prepare:Passed\n"
           "  Tss2_Sys_ExecuteAsync:Passed\n"
           "  setLocality(otherResMgrTctiContext,1):Failed(TSS2_TCTI_RC_BAD_SEQUENCE)\n"
           "  Tss2_Sys_ExecuteFinish:Passed\n"
           "  Tss2_Sys_GetTctiContext:Passed\n"
           "  cancel(0):Failed(TSS2_TCTI_RC_BAD_REFERENCE)\n"
           "  cancel(otherResMgrTctiContext):Failed(TSS2_TCTI_RC_BAD_SEQUENCE)\n"
           "  Tss2_Sys_CreatePrimary_Prepare:Passed\n"
           "  Tss2_Sys_SetCmdAuths(authArray:{1,{TPM_RS_PW}}):Passed\n"
           "  Tss2_Sys_ExecuteAsync:Passed\n"
           "  cancel(tctiContext):Passed\n"
           "  Tss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Failed(TPM_RC_CANCELED)\n"
           "  Tss2_Sys_CreatePrimary_Prepare:Passed\n"
           "  Tss2_Sys_SetCmdAuths:Passed\n"
           "  Tss2_Sys_ExecuteAsync:Passed\n"
           "  Tss2_Sys_ExecuteFinish(timeout:0):Failed(TSS2_TCTI_RC_TRY_AGAIN)\n"
           "  cancel( tctiContext ):Passed\n"
           "  Tss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Failed(TPM_RC_CANCELED)\n"
           "  Tss2_Sys_CreatePrimary_Prepare:Passed\n"
           "  Tss2_Sys_SetCmdAuths:Passed\n"
           "  Tss2_Sys_ExecuteAsync:Passed\n"
           "  cancel( otherResMgrTctiContext ):Failed(TSS2_TCTI_RC_BAD_SEQUENCE)\n"
           "  Tss2_Sys_ExecuteFinish(timeout:TSS2_TCTI_TIMEOUT_BLOCK):Passed\n"
           "  Tss2_Sys_CreatePrimary_Complete:Passed\n"
           "  Tss2_Sys_FlushContext(flushHandle:newHandle:Passed\n");
    }
//    else
    {
//        printf("\n The RM Test Cases can't be passed right now.\n");
    }
}
void PrintEcEphemeralTestDescription()
{
    printf("  EC_Ephemeral Case(Auth:0,curveID:0x0010,Q.t.size:0xff):Failed(TSS2_SYS_RC_BAD_VALUE)\n"
           "  EC_Ephemeral Case(Auth:0,curveID:0x0010,Q.t.size:0):Passed\n");
}
void PrintSimpleHmacSessionTest()
{
    printf("  Tss2_Sys_NV_DefineSpace(nvIndex:0x1500020):Passed\n"
           "  AddEntity( TPM20_INDEX_PASSWORD_TEST ):Passed\n"
           "  HandleToNameFunctionPtr():Passed\n"
           "  StartAuthSessionWithParams:Passed\n"
           "  HandleToNameFunctionPtr:Passed\n"
           "  Tss2_Sys_NV_Write_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Write:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  Tss2_Sys_NV_Read_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Read:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  Tss2_Sys_NV_UndefineSpace:Passed\n"
           "  DeleteEntity( TPM20_INDEX_PASSWORD_TEST ):Passed\n"
           "  EndAuthSession:Passed\n");
}
void PrintSimplePolicySessionTest()
{
    printf("  StartAuthSessionWithParams:Passed\n"
           "  Tss2_Sys_PolicyAuthValue:Passed\n"
           "  Tss2_Sys_PolicyGetDigest:Passed\n"
           "  Tss2_Sys_FlushContext:Passed\n"
           "  EndAuthSession:Passed\n"
           "  Tss2_Sys_NV_DefineSpace(nvIndex:0x1500020):Passed\n"
           "  AddEntity( TPM20_INDEX_PASSWORD_TEST ):Passed\n"
           "  HandleToNameFunctionPtr():Passed\n"
           "  StartAuthSessionWithParams:Passed\n"
           "  HandleToNameFunctionPtr:Passed\n"
           "  Tss2_Sys_PolicyAuthValue:Passed\n"
           "  Tss2_Sys_NV_Write_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Write:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  Tss2_Sys_PolicyAuthValue:Passed\n"
           "  Tss2_Sys_NV_Read_Prepare:Passed\n"
           "  ComputeCommandHmacs:Passed\n"
           "  Tss2_Sys_NV_Read:Passed\n"
           "  CheckResponseHMACs:Passed\n"
           "  Tss2_Sys_NV_UndefineSpace:Passed\n"
           "  DeleteEntity( TPM20_INDEX_PASSWORD_TEST ):Passed\n"
           "  EndAuthSession:Passed\n");
}
void PrintSymmetricEncryptDecryptTest()
{
    printf("  create primary:   PASSED!\n"
           "  New key successfully created in owner hierarchy (RSA 2048).  Handle: 0x8000000d\n"
           "  Name of created primary key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  create key:   PASSED!\n"
           "  Name of created key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  load key:   PASSED!\n"
           "  Name of loading key: 00 04 60 df d7 7a f7 fd 2c c8 2d 61 04 52 4c cc 6a 2d dc 18 ca 98\n"
           "  encrypt:   PASSED!\n"
           "  decrypt:   PASSED!\n"
           "  HASH TESTS: HASH Comparison\n"
           "  hashing on original message:   PASSED!\n"
           "  hashing on the decyprted message:   PASSED!\n"
           "  Hash value before encrypt: 9f 86 d0 81 88 4c 7d 65 9a 2f ea a0 c5 5a d0 15\n"
           "    a3 bf 4f 1b 2b 0b 82 2c d1 5d 6c 15 b0 f0 0a 08\n"
           "  Hash value after decrypt: 9f 86 d0 81 88 4c 7d 65 9a 2f ea a0 c5 5a d0 15\n"
           "    a3 bf 4f 1b 2b 0b 82 2c d1 5d 6c 15 b0 f0 0a 08\n");

}
void PrintAsymmetricEncryptDecryptTest()
{
    printf("  create primary:   PASSED!\n"
           "  New key successfully created in owner hierarchy (RSA 2048).  Handle: 0x8000000d\n"
           "  Name of created primary key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  create key:   PASSED!\n"
           "  Name of created key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  load key:   PASSED!\n"
           "  Name of loading key: 00 04 60 df d7 7a f7 fd 2c c8 2d 61 04 52 4c cc 6a 2d dc 18 ca 98\n"
	   "  rsa encrypt:   PASSED!\n"
	   "  Encrypted data: f0 7f fd c3 c6 dd 9e 98 6d 71 05 c7 ad 9a 8e 74\n"
	   "	19 0a 47 cb dd ca c4 6a c1 55 d3 8b d6 76 b7 93\n"
	   "	77 ca 05 3e 0e 90 8d bd 2d 1d 6d e8 7e bf fe 35\n"
	   " 	3c 80 cf 3d 59 c0 0a a5 58 44 4f 93 9d 72 15 41\n"
	   "	c2 6c 91 2d c8 ec 15 4a d8 1e be c6 04 c2 c9 8e\n"
	   " 	2d 1b 0c c3 13 2d b7 5c 20 91 6c 65 bb 19 89 23\n"
	   "	48 ab 29 cc 03 20 7f 06 7f a5 48 d7 58 f9 1a 39\n"
	   "	89 c7 5b 3f d2 ff ad f4 32 13 2f 31 af 3a d3 bd\n"
	   "	d2 ab 2e 1a aa 7a 65 b9 20 a7 25 d5 12 67 f8 23\n"
	   "	fa 8c 6c 65 72 75 a6 57 21 94 df 25 a9 e7 c4 54\n"
	   "	ca 0c fb ae 37 c9 6b 58 5e 9b 9f 58 31 f8 94 a6\n"
	   "	0d bf 0a 78 a7 53 96 81 cf 90 45 0b 31 6c da e0\n"
	   "	00 b3 7c 98 35 fa 6d 14 e6 0a 0c 1c 45 f7 3f 00\n"
	   "	bd c8 fc 8e 83 55 b4 1e f8 a2 cb c5 cb bd 67 16\n"
	   "	f9 e7 9b 8d 7b 32 bf 7b 67 3f d4 9c 35 33 6d 0e\n"
	   "	ec e4 19 f4 bc 16 61 92 b3 9b 2b 8b b5 14 25 2b\n"
           "  rsa decrypt:   PASSED!\n"
	   "  Decypted data: 74 65 73 74\n"
	   "  HASH TESTS: HASH Comparison\n"
           "  hashing on original message:   PASSED!\n"
           "  hashing on the decyprted message:   PASSED!\n"
	   "  Hash value before encrypt: 9f 86 d0 81 88 4c 7d 65 9a 2f ea a0 c5 5a d0 15\n"
	   "	a3 bf 4f 1b 2b 0b 82 2c d1 5d 6c 15 b0 f0 0a 08\n"
	   "  Hash value after decrypt: 9f 86 d0 81 88 4c 7d 65 9a 2f ea a0 c5 5a d0 15\n"
	   "	a3 bf 4f 1b 2b 0b 82 2c d1 5d 6c 15 b0 f0 0a 08\n");
}
void PrintVerifySignatureExternalTest()
{
    printf("  create primary:   PASSED!\n"
           "  New key successfully created in owner hierarchy (RSA 2048).  Handle: 0x8000000d\n"
           "  Name of created primary key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  create key:   PASSED!\n"
           "  Name of created key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  load key:   PASSED!\n"
           "  Name of loading key: 00 04 60 df d7 7a f7 fd 2c c8 2d 61 04 52 4c cc 6a 2d dc 18 ca 98\n"
           "  tpm performing hash :   PASSED!\n"
           "  digest(hex type):fe be a2 ef 8c ba 2e d7 6a 6e d4 40 31 fb a5 b1 26 a2 35 63\n"
           "  sign the message:   PASSED!\n"	
           "  verify signature using loaded key:   PASSED!\n");
}
void PrintVerifySignatureCreatedTest()
{
    printf("  create primary:   PASSED!\n"
	   "  New key successfully created in owner hierarchy (RSA 2048).  Handle: 0x8000000d\n"
  	   "  Name of created primary key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  create key:   PASSED!\n"
	   "  Name of created key: 00 04 ed 89 58 53 b7 51 74 88 f8 d2 7c de b5 89 55 28 46 dd f8 35\n"
           "  load key:   PASSED!\n"
	   "  Name of loading key: 00 04 60 df d7 7a f7 fd 2c c8 2d 61 04 52 4c cc 6a 2d dc 18 ca 98\n"
	   "  tpm performing hash :   PASSED!\n"
	   "  digest(hex type):fe be a2 ef 8c ba 2e d7 6a 6e d4 40 31 fb a5 b1 26 a2 35 63\n"
           "  sign the message:   PASSED!\n"
           "  load external public key:   PASSED!\n"
	   "  Loaded key handle:  8000000f\n"
           "  verify signature using loaded key:   PASSED!\n");
}
void PrintNvExtensionTest()
{
    printf("   List the NV defined List:   PASSED!\n"
           "   The count of defined NV Index: 0\n"
           "   Load external key:   PASSED!\n"
           "   Name of loaded key: 00 04 aa 6f 4a 8b 97 3a f7 3f d7 b4 e4 a4 fa 56 6c 96 79 b9 5d c8\n"
           "   Loaded key handle:  80000009\n"
	   "   Define NV space:   PASSED!\n"
	   "   TPM 2.0 Test 1 Index:1500020\n"    
	   "   Failed to read NV because uninitialized:   PASSED!\n"
           "   Failed to define space because it is already defined:   PASSED!\n"
           "   Write into NV:   PASSED!\n"
           "   Read from NV:   PASSED!\n"
	   "   Name of NV data:  00  04  aa  6f  4a  8b  97  3a  f7  3f  d7  b4  e4  a4  fa  56  6c  96  79  b9\n"
           "   Undefine the NV index:      PASSED!\n"
           "   Define NV space:   PASSED!\n"
           "   Undefine the NV index:   PASSED!\n");
}
void PrintPcrExtendedTest()
{
    printf("  Get the number of PCR:   PASSED!\n"
           "  The Number of PCR implemented:7f\n"
           "  Read PCR values:   PASSED!\n"
           "  Name of PCR Values Before Extend: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
           "  Extend PCR values:   PASSED!\n"
           "  Read PCR Values:   PASSED!\n"
           "  Name of PCR Values After Extended: f8 7c fc 25 e0 47 ab 7f a1 c1 d2 cc a2 c7 ff aa 70 6c d2 3a\n" 
           "  Failed to read the PCR value because no PCR selection:   PASSED!\n"
           "  PCR Event:   PASSED!\n"
           "  Name of PCR Event Digests: 2d dd 5b 98 e2 09 56 cd d5 88 1f a8 0f df 7c 2a a7 da 72 78\n");
}
void PrintClockTimeTest()
{
    printf(" Tss2_sys_ReadClock:PASSED\n"
           " Tss2_Sys_ClockSet:PASSED\n"
           " Tss2_sys_ReadClock:PASSED\n"
           " Tss2_Sys_ClockRateAdjust:passing case:PASSED\n"
           " Tss2_Sys_ClockRateAdjust:passing case:PASSED\n"
	   " Tss2_Sys_ClockRateAdjust:passing case:PASSED\n");
}

typedef struct {
    const char *index;
    const char *name;
    void (*testFn)();
    int disabled;
}SUB_MENUS_SETUP;

typedef struct {
    const char *index;
    const char *name;
    void (*testFn)();
    SUB_MENUS_SETUP* subMenus;
    int disabled;
}MENUS_SETUP;


SUB_MENUS_SETUP startupTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintStartupTestDescription, },
    { "0", "RUN ALL TEST CASES", TestTpmStartup, },
    { NULL, NULL, 0, },
};

SUB_MENUS_SETUP createTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintCreateTestDescription, },
    { "0", "RUN ALL TEST CASES", TestCreate, },
    { "1", "CreatePrimary Case", TPM2CreatePrimary, },
    { "2", "Create Case", TPM2Create, },
    { NULL, NULL, 0, },
};

SUB_MENUS_SETUP nvTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintNVTestDescription, },
    { "0", "RUN ALL TEST CASES", TestNV, },
    { "1", "NV Define Case", TestNVDefineCase, },
    { "2", "NV Write Case", TestNVWriteCase, },
    { "3", "NV Read Case", TestNVReadCase, },
    { "4", "NV ReadPublic Case", TestNVReadPublicCase, },
    { "5", "NV UndefineSpace Case", TestNVUndefineCase, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP getSetDecryptParamMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintGetSetDecryptParamTest, },
    { "0", "RUN ALL TEST CASES", GetSetDecryptParamTests, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP getVersionTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintGetVersionTestDescription, },
    { "0", "RUN ALL TEST CASES", GetTpmVersion, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP selfTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintSelfTestDescription, },
    { "0", "RUN ALL TEST CASES", TestTpmSelftest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP sapiTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintSapiTestDescription, },
    { "0", "RUN ALL TEST CASES", TestSapiApis, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP DALRTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintDALRTestDescription, },
    { "0", "RUN ALL TEST CASES", TestDictionaryAttackLockReset, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP startAuthSessionMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintStartAuthSessionTest, },
    { "0", "RUN ALL TEST CASES", TestStartAuthSession, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP hierarchyControlMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintHierarchyControlTest, },
    { "0", "RUN ALL TEST CASES", TestHierarchyControl, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP nvIndexProtoTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintNvIndexProtoTest, },
    { "0", "RUN ALL TEST CASES", NvIndexProto, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP getSetEncryptParamMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintGetSetEncryptParamTest, },
    { "0", "RUN ALL TEST CASES", GetSetEncryptParamTests, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP encryptDecryptSessionTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintEncryptDecryptSessionTest, },
    { "0", "RUN ALL TEST CASES", TestEncryptDecryptSession, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP getCapabilityTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintGetCapabilityTestDescription, },
    { "0", "RUN ALL TEST CASES", TestTpmGetCapability, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP pcrExtendTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintPcrExtendTestDescription, },
    { "0", "RUN ALL TEST CASES", TestPcrExtend, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP hashTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintHashTestDescription, },
    { "0", "RUN ALL TEST CASES", TestHash, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP policyTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintPolicyTestDescription, },
    { "0", "RUN ALL TEST CASES", TestPolicy, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP clearTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintClearTestDescription, },
    { "0", "RUN ALL TEST CASES", TestTpmClear, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP changeEpsTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintChangeEpsTestDescription, },
    { "0", "RUN ALL TEST CASES", TestChangeEps, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP changePpsTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintChangePpsTestDescription, },
    { "0", "RUN ALL TEST CASES", TestChangePps, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP hierarchyChangeAuthMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintHierarchyChangeAuthDescription, },
    { "0", "RUN ALL TEST CASES", TestHierarchyChangeAuth, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP getRandomTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintGetRandomTestDescription, },
    { "0", "RUN ALL TEST CASES", TestGetRandom, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP shutdownTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintShutdownTestDescription, },
    { "0", "RUN ALL TEST CASES", TestShutdown, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP passwordTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintPasswordTestDescription, },
    { "0", "RUN ALL TEST CASES", PasswordTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP hmacSessionTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintHmacSessionTestDescription, },
    { "0", "RUN ALL TEST CASES", HmacSessionTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP quoteTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintQuoteTestDescription, },
    { "0", "RUN ALL TEST CASES", TestQuote, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP pcrAllocateTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintPcrAllocateTestDescription, },
    { "0", "RUN ALL TEST CASES", TestPcrAllocate, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP unsealTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintUnsealTestDescription, },
    { "0", "RUN ALL TEST CASES", TestUnseal, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP rmTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintRMTestDescription, },
    { "0", "RUN ALL TEST CASES", TestRM, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP ecEphemeralTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintEcEphemeralTestDescription, },
    { "0", "RUN ALL TEST CASES", EcEphemeralTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP simpleHmacSessionMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintSimpleHmacSessionTest, },
    { "0", "RUN ALL TEST CASES", SimpleHmacSessionTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP simplePolicySessionMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintSimplePolicySessionTest, },
    { "0", "RUN ALL TEST CASES", SimplePolicySessionTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP symmetricEncryptDecryptTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintSymmetricEncryptDecryptTest, },
    { "0", "RUN ALL TEST CASES", symmetricEncryptDecryptTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP asymmetricEncryptDecryptTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintAsymmetricEncryptDecryptTest, },
    { "0", "RUN ALL TEST CASES", asymmetricEncryptDecryptTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP verifySignatureExternalTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintVerifySignatureExternalTest, },
    { "0", "RUN ALL TEST CASES", verifySignatureExternalTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP verifySignatureCreatedTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintVerifySignatureCreatedTest, },
    { "0", "RUN ALL TEST CASES", verifySignatureCreatedTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP nvExtensionTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintNvExtensionTest, },
    { "0", "RUN ALL TEST CASES", nvExtensionTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP pcrExtendedTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintPcrExtendedTest, },
    { "0", "RUN ALL TEST CASES", pcrExtendedTest, },
    { NULL, NULL, 0, },
};
SUB_MENUS_SETUP clockTimeTestMenus[] =
{
    { "Q", "QUIT THIS TEST GROUP", 0, },
    { "D", "PRINT DESCRIPTION ON ALL CASES IN THIS GROUP", PrintClockTimeTest, },
    { "0", "RUN ALL TEST CASES", TestClockTime, },
    { NULL, NULL, 0, },
};

MENUS_SETUP firstLevelMenus[] =
{
    { "Q", "QUIT THE PROGRAM", 0, NULL, },
    { "D", "PRINT DESCRIPTION ON ALL CASES", PrintHelp, NULL, },
    { "0", "RUN ALL TEST CASES", TpmTest, NULL, },

    { "1", "GET/SET DECRYPT PARAM TESTS", 0, getSetDecryptParamMenus, },
    { "2", "STARTUP TESTS", 0, startupTestMenus, },
    { "3", "CREATE, CREATE PRIMARY, and LOAD TESTS", 0, createTestMenus, },
    { "4", "NV INDEX TESTS", 0, nvTestMenus, },
    { "5", "UNSEAL TEST", 0, unsealTestMenus, },
    { "6", "TPM Version TESTS", 0, getVersionTestMenus, },
    { "7", "SELFTEST TESTS", 0, selfTestMenus, },
    { "8", "GET TEST RESULT TESTS", 0, sapiTestMenus, },
    { "9", "DICTIONARY ATTACK LOCK RESET TEST", 0, DALRTestMenus, },
    { "10", "START_AUTH_SESSION TESTS", 0, startAuthSessionMenus, },
    { "11", "HIERARCHY CONTROL TESTS", 0, hierarchyControlMenus, },
    { "12", "GET/SET ENCRYPT PARAM TESTS", 0, getSetEncryptParamMenus, },
    { "13", "GET_CAPABILITY TESTS", 0, getCapabilityTestMenus, },
    { "14", "PCR_EXTEND, PCR_EVENT, PCR_ALLOCATE, and PCR_READ TESTS", 0, pcrExtendTestMenus, },
    { "15", "HASH TESTS", 0, hashTestMenus, },
    { "16", "POLICY TESTS", 0, policyTestMenus, },
    { "17", "CLEAR and CLEAR CONTROL TESTS", 0, clearTestMenus, },
    { "18", "CHANGE_EPS TESTS", 0, changeEpsTestMenus, },
    { "19", "HIERARCHY_CHANGE_AUTH TESTS", 0, hierarchyChangeAuthMenus, },
    { "20", "GET_RANDOM TESTS", 0, getRandomTestMenus, },
    { "21", "SHUTDOWN TESTS", 0, shutdownTestMenus, },
    { "22", "PASSWORD TESTS", 0, passwordTestMenus, },
    { "23", "HMAC SESSION TESTS", 0, hmacSessionTestMenus, },
    { "24", "QUOTE CONTROL TESTS", 0, quoteTestMenus, },
    { "25", "PCR ALLOCATE TEST", 0, pcrAllocateTestMenus, },
    { "26", "RM TESTS", 0, rmTestMenus, },

    { "27", "NV INDEX PROTOTYPE TESTS", 0, nvIndexProtoTestMenus, },
    { "28", "DECRYPT/ENCRYPT SESSION TESTS", 0, encryptDecryptSessionTestMenus, },
    { "29", "SIMPLE HMAC SESSION TEST", 0, simpleHmacSessionMenus, },
    { "30", "SIMPLE POLICY SESSION TEST", 0, simplePolicySessionMenus, },
    { "31", "CHANGE_PPS TESTS", 0, changePpsTestMenus, },
    { "32", "EC Ephemeral TESTS", 0, ecEphemeralTestMenus, },

	{ "33", "SYMMETRIC ENCRYPT/DECRYPT TESTS", 0, symmetricEncryptDecryptTestMenus, },
    { "34", "ASYMMETRIC ENCRYPT/DECRYPT TESTS", 0, asymmetricEncryptDecryptTestMenus, },
    { "35", "VERIFY SIGNATURE WITH EXTERNAL KEY TEST", 0, verifySignatureExternalTestMenus, },
    { "36", "VERIFY SIGNATURE WITH CREATED KEY TEST", 0, verifySignatureCreatedTestMenus, },
    { "37", "NV EXTENSION TEST", 0, nvExtensionTestMenus, },
    { "38", "PCR EXTENDED TEST", 0, pcrExtendedTestMenus, },
    { "39", "CLOCK/TIME TEST", 0, clockTimeTestMenus, },
	
    { NULL, NULL, 0, },
};

template <typename T>
int getchoice(const T *choices)
{
	int scanfCnt = 0;
	int chosen = 0;
    int selected = 0;
    char strSelect[50];
    const T *option = NULL;


    do {
        option = choices;

        while (option->index != NULL)
        {
            if (!option->disabled)
                printf("%s - %s\n", option->index, option->name);
            option++;
        }

        printf("Please select an action:");
        scanfCnt = scanf("%s", &strSelect[0]);
        if(scanfCnt != 0)
            scanfCnt = 0;
        selected = atoi(strSelect);

        option = choices;
        while (option->index != NULL)
        {
            if( strcmp(strSelect, "q") == 0 )
            {
                chosen = 1;
                selected = 0;
                break;
            }
            else if( strcmp(strSelect, "d") == 0 )
            {
                chosen = 1;
                selected = 1;
                break;
            }
            else if( !option->disabled && strcmp(strSelect, option->index) == 0 )
            {
                chosen = 1;
                if( strcmp(strSelect, "D") == 0 )
                    selected = 1;
                else if( strcmp(strSelect, "Q") == 0 )
                    selected = 0;
                else
                    selected += 2;
                break;
            }
            option++;
        }

        if (!chosen)
        {
            printf("Incorrect choice,select again!\n\n");
        }
    } while (!chosen);

    return selected;
}

void DisableMenuItems(int startIndex, int num)
{
    for( ; num > 0; num--, startIndex++ )
        firstLevelMenus[startIndex].disabled = 1;
}

void CheckTpmType()
{
    UINT32 rval;
    char manuID[5] = "    ";
    char *manuIDPtr = &manuID[0];
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );

    printf( "\nCheck TPM type: " );

    *( (UINT32 *)manuIDPtr ) = CHANGE_ENDIAN_DWORD( capabilityData.data.tpmProperties.tpmProperty[0].value );
    if( 0 == strcmp(manuID, "MSFT") || 0 == strcmp(manuID, "IBM ") )
    {
        tpmType = TPM_TYPE_SIMULATOR;
        printf( "simulator (%s)\n", manuID );
    }
    else if ( 0 == strcmp(manuID, "INTC") )
    {
        tpmType = TPM_TYPE_PTT;
        printf( "Intel PTT (INTC)\n" );
    }
    else
    {
        tpmType = TPM_TYPE_DTPM;
        printf( "discrete TPM (%s)\n", manuID );
    }
}

void CheckHierarchy()
{
    UINT32 rval;
    TPM2B_AUTH      newAuth;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;

    sessionsData.cmdAuths = &sessionDataArray[0];

    // Init authHandle
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    newAuth.t.size = 0;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    if( rval == TPM_RC_SUCCESS )
        nullPlatformAuth = 1;
    else
        nullPlatformAuth = 0;
}

void InitTpmTest()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    nullSessionsDataOut.rspAuthsCount = 1;
    nullSessionsDataOut.rspAuths[0]->nonce = nullSessionNonceOut;
    nullSessionsDataOut.rspAuths[0]->hmac = nullSessionHmac;
    nullSessionNonceOut.t.size = 0;
    nullSessionNonce.t.size = 0;

    loadedSha1KeyAuth.t.size = 2;
    loadedSha1KeyAuth.t.buffer[0] = 0x00;
    loadedSha1KeyAuth.t.buffer[1] = 0xff;

    InitEntities();

    InitNullSession( &nullSessionData);

    GetSetDecryptParamTests();

    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    PlatformCommand(  resMgrTctiContext, MS_SIM_NV_ON );
    Tss2_Sys_Startup ( sysContext, TPM_SU_CLEAR );
    CheckTpmType();
    CheckHierarchy();
    if( nullPlatformAuth )
        ClearNVIndexList(TPM_RH_PLATFORM);
    else
    {
        printf("Warning - Non-Null PlatformAuth.\n");
        ClearNVIndexList(TPM_RH_OWNER);
    }
    Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_CLEAR, NULL );
    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );

    if( tpmType == TPM_TYPE_SIMULATOR )
    {
        rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
        if( rval == TSS2_RC_SUCCESS )
        {
            rval = (TSS2_RC)PlatformCommand(  resMgrTctiContext, MS_SIM_NV_ON );
        }
        CheckPassed( rval );
    }

    TpmReset();

    if( tpmType == TPM_TYPE_PTT )
        DisableMenuItems(29, 6);
    if( !nullPlatformAuth )
    {
        DisableMenuItems(6,1);
        DisableMenuItems(12,3);
        DisableMenuItems(19,3);
        DisableMenuItems(24,2);
        DisableMenuItems(29,5);
    }
}

char version[] = "0.90";

void PrintHelp()
{
    printf(
            "TPM client test app, Version %s\nUsage:  tpmclient [-host hostname|ip_addr] [-port port] [-type type] [-passes passNum] [-demoDelay delay] [-dbg dbgLevel] [-startAuthSessionTest]\n"
            "\n"
            "where:\n"
            "\n"
            "-host specifies the host IP address for resource mgr(default: %s)\n"
            "-port specifies the port number for resource mgr(default: %d)\n"
            "-passes specifies the number of test passes (default: 1)\n"
            "-demoDelay specifies a delay in units of loops, not time (default:  0)\n"
            "-dbgLevel specifies level of debug messages:\n"
            "   0 (high level test results)\n"
            "   1 (test app send/receive byte streams)\n"
            "   2 (resource manager send/receive byte streams)\n"
            "   3 (resource manager tables)\n"
            "-startAuthSessionTest enables some special tests of the resource manager for starting sessions\n"
            , version, DEFAULT_HOSTNAME, DEFAULT_RESMGR_TPM_PORT );
}

#if 0
typedef TSS2_RC (*TSS2_TCTI_INITIALIZE_FUNC) (
    // Buffer allocated by caller to contain
    // common part of context information.
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    // If tctiContext==NULL writes required size
    // to this variable. Otherwise expects the
    // size allocated for context.
    //
    // Pass NULL to retrieve required size
    // as return value.
    size_t *contextSize,            // IN/OUT
    // String that determines the configuration
    // to operate in (e.g. device-path,
    // remote-server-address, config-file-path).
    const char *config              // IN
    );
#endif

int main(int argc, char* argv[])
{
    int count;
    TSS2_RC rval;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);
    if( argc > 8 )
    {
        PrintHelp();
        return 1;
    }
    else
    {
        for( count = 1; count < argc; count++ )
        {
            if( 0 == strcmp( argv[count], "-host" ) )
            {
                count++;
                rmInterfaceConfig.hostname = argv[count];
                if( count >= argc)
                {
                    PrintHelp();
                    return 1;
                }
            }
            else if( 0 == strcmp( argv[count], "-port" ) )
            {
                count++;
                rmInterfaceConfig.port = strtoul(argv[count], NULL, 10);
                if( count >= argc)
                {
                    PrintHelp();
                    return 1;
                }
            }
            else if( 0 == strcmp( argv[count], "-passes" ) )
            {
                count++;
                if( 1 != sscanf( argv[count], "%d", &passCount ) )
                {
                    PrintHelp();
                    return 1;
                }
            }
            else if( 0 == strcmp( argv[count], "-demoDelay" ) )
            {
                count++;
                if( 1 != sscanf( argv[count], "%x", &demoDelay ) )
                {
                    PrintHelp();
                    return 1;
                }
            }
            else if( 0 == strcmp( argv[count], "-dbg" ) )
            {
                count++;
                if( 1 != sscanf( argv[count], "%d", &debugLevel ) )
                {
                    PrintHelp();
                    return 1;
                }
            }
            else if( 0 == strcmp( argv[count], "-startAuthSessionTest" ) )
            {
                startAuthSessionTestOnly = 1;
            }
            else
            {
                PrintHelp();
                return 1;
            }
        }
    }
    rval = InitTctiResMgrContext( &rmInterfaceConfig, &resMgrTctiContext, &resMgrInterfaceName[0] );
    if( rval != TSS2_RC_SUCCESS )
    {
        DebugPrintf( NO_PREFIX, "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resMgrInterfaceName, rval );
        Cleanup();
        return( 1 );
    }
    else
    {
        (( TSS2_TCTI_CONTEXT_INTEL *)resMgrTctiContext )->status.debugMsgEnabled = debugLevel;
    }

    sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        InitSysContextFailure();
    }
    else
    {
        int choice = 0;
        int subChoice = 0;

        InitTpmTest();
        do
        {
            printf("\n");
            choice = getchoice( firstLevelMenus );
//            printf("\nYou have chosen: %s - %s\n\n", firstLevelMenus[choice].index, firstLevelMenus[choice].name);
            if ( firstLevelMenus[choice].testFn != 0 )
            {
                (*firstLevelMenus[choice].testFn)();
            }
            else if( firstLevelMenus[choice].subMenus != 0)
            {
                do{
                    printf("\n%s:\n", firstLevelMenus[choice].name);
                    subChoice = getchoice( firstLevelMenus[choice].subMenus );
                    if( subChoice != 0 )
                    {
                        printf("\n%s:\n", firstLevelMenus[choice].subMenus[subChoice].name);
                        if( firstLevelMenus[choice].subMenus[subChoice].testFn != 0 )
                        {
                            (*firstLevelMenus[choice].subMenus[subChoice].testFn)();
                        }
                    }
                }while (subChoice != 0);
            }
        }while (choice != 0);

        TeardownSysContext( &sysContext );

        Cleanup();
    }

    return 0;
}


