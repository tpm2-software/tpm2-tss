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
// tpmclient.cpp : Defines the entry point for the console test application.
//

#ifdef _WIN32
#include "stdafx.h"
#else
#include <stdarg.h>
#endif

#ifndef UNICODE
#define UNICODE 1
#endif

#ifdef _WIN32
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define sprintf_s   snprintf
#define sscanf_s    sscanf
#endif

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi
#include <string.h>

#include <tss2/tpm20.h>
#include "sysapi_util.h"
#include "sample.h"
#include "resourcemgr.h"
#include "tpmclient.h"

// This is done to allow the tests to access fields
// in the sysContext structure that are needed for
// special test cases.
//
// ATTENTION:  Normal applications should NEVER do this!!
//
#include "sysapi_util.h"

#include <tcti/tcti_device.h>
#include <tcti/tcti_socket.h>
#include "syscontext.h"
#include "debug.h"

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

char outFileName[200] = "";

TPM_CC currentCommandCode;
TPM_CC *currentCommandCodePtr = &currentCommandCode;

#define errorStringSize 200
char errorString[errorStringSize];

UINT8 simulator = 1;

#if __linux || __unix
UINT8 testLocalTcti = 0;
#endif

UINT32 tpmMaxResponseLen = TPMBUF_LEN;

UINT8 resMgrInitialized = 0;

UINT8 pcrAfterExtend[20];
TPM_HANDLE loadedRsaKeyHandle;
TPM_HANDLE loadedSha1KeyHandle;

TPM2B_AUTH loadedSha1KeyAuth;

TPM_HANDLE handle1024, handle2048sha1, handle2048rsa;

UINT32 passCount = 1;
UINT32 demoDelay = 0;
int debugLevel = 0;
UINT8 indent = 0;

TSS2_SYS_CONTEXT *sysContext;

TCTI_SOCKET_CONF rmInterfaceConfig = {
    DEFAULT_HOSTNAME,
    DEFAULT_RESMGR_TPM_PORT
};
    
TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

UINT32 tpmSpecVersion = 0;
UINT32 tpmManufacturer = 0;

#define MSFT_MANUFACTURER_ID 0x4d534654

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

FILE *outFp;

//
// Used by some high level sample routines to copy the results.
//
void copyData( UINT8 *to, UINT8 *from, UINT32 length )
{
    if( to != 0 && from != 0 )
        memcpy( to, from, length );
}

int TpmClientPrintf( UINT8 type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    OpenOutFile( &outFp );

    if( outFp )
    {
        if( type == RM_PREFIX )
        {
            PrintRMDebugPrefix();
        }

        va_start( args, format );
        rval = vfprintf( outFp, format, args );
        va_end (args);

        CloseOutFile( &outFp );
    }
    else
    {
        printf( "TpmClientPrintf failed\n" );
    }
    
    return rval;
}

TPM_RC CompareTPM2B( TPM2B *buffer1, TPM2B *buffer2 )
{
    if( buffer1->size != buffer2->size )
        return TPM_RC_FAILURE;
    for( int i = 0; i < buffer1->size; i++ )
    {
        if( buffer1->buffer[0] != buffer2->buffer[0] )
            return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

void PrintSizedBufferOpen( TPM2B *sizedBuffer )
{
    int i;


    OpenOutFile( &outFp );

    if( outFp )
    {
        for( i = 0; i < sizedBuffer->size; i++ )
        {
            TpmClientPrintf( 0, "%2.2x ", sizedBuffer->buffer[i] );

            if( ( (i+1) % 16 ) == 0 )
            {
                TpmClientPrintf( 0, "\n" );
            }
        }
        TpmClientPrintf( 0, "\n" );

        CloseOutFile( &outFp );
    }
    else
    {
        printf( "PrintSizedBufferOpen failed\n" );
    }
            
}

void PrintSizedBuffer( TPM2B *sizedBuffer )
{
    int i;

    for( i = 0; i < sizedBuffer->size; i++ )
    {
        TpmClientPrintf( 0, "%2.2x ", sizedBuffer->buffer[i] );

        if( ( (i+1) % 16 ) == 0 )
        {
            TpmClientPrintf( 0, "\n" );
        }
    }
    TpmClientPrintf( 0, "\n" );
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
                
    sprintf_s( errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval );
}

char resMgrInterfaceName[] = "Resource Manager";

TSS2_RC InitTctiResMgrContext( TCTI_SOCKET_CONF *rmInterfaceConfig, TSS2_TCTI_CONTEXT **tctiContext, char *name )
{
    size_t size;
    
    TSS2_RC rval;

    rval = InitSocketTcti(NULL, &size, rmInterfaceConfig, 0, 0, &resMgrInterfaceName[0], 0 );
    if( rval != TSS2_RC_SUCCESS )
        return rval;
    
    *tctiContext = (TSS2_TCTI_CONTEXT *)malloc(size);

    if( *tctiContext )
    {
        rval = InitSocketTcti(*tctiContext, &size, rmInterfaceConfig, TCTI_MAGIC, TCTI_VERSION, resMgrInterfaceName, 0 );
    }
    else
    {
        rval = TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return rval;
}

TSS2_RC TeardownTctiResMgrContext( TSS2_TCTI_CONTEXT *tctiContext )
{
    return TeardownSocketTcti( tctiContext );
}

void Cleanup()
{
    fflush( stdout );

    if( resMgrTctiContext != 0 )
    {
        PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );

        TeardownTctiResMgrContext( resMgrTctiContext );
    }
    
#ifdef _WIN32        
    WSACleanup();
#endif        
    exit(1);
}

void InitSysContextFailure()
{
    TpmClientPrintf( 0, "InitSysContext failed, exiting...\n" );
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

void CheckPassed( UINT32 rval )
{
    OpenOutFile( &outFp );
    TpmClientPrintf( 0, "\tpassing case:  " );
    if ( rval != TPM_RC_SUCCESS) {
        ErrorHandler( rval);
        TpmClientPrintf( 0, "\tFAILED!  %s\n", errorString );
        Cleanup();
    }
    else
    {
        TpmClientPrintf( 0, "\tPASSED!\n" );
    }

    CloseOutFile( &outFp );
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
    OpenOutFile( &outFp );
    TpmClientPrintf( 0, "\tfailing case: " );
    if ( rval != expectedTpmErrorCode) {
        ErrorHandler( rval);
        TpmClientPrintf( 0, "\tFAILED!  Ret code s/b: %x, but was: %x\n", expectedTpmErrorCode, rval );
        Cleanup();
    }
    else
    {
        TpmClientPrintf( 0, "\tPASSED!\n" );
    }
    fflush( stdout );
    CloseOutFile( &outFp );
    Delay(demoDelay);
}

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
        TpmClientPrintf( 0, "TPM spec version:  %d\n", tpmSpecVersion );
    }
    else
    {
        TpmClientPrintf( 0, "Failed to get TPM spec version!!\n" );
        Cleanup();
    }   
}

void GetTpmManufacturer()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMS_CAPABILITY_DATA capabilityData;
    
    rval = Tss2_Sys_GetCapability( sysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER,
            1, 0, &capabilityData, 0 );
    CheckPassed( rval );

    if( capabilityData.data.tpmProperties.count == 1 && 
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_MANUFACTURER ) )
    {
        tpmManufacturer = capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else
    {
        TpmClientPrintf( 0, "Failed to get TPM manufacturer!!\n" );
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
    
    TpmClientPrintf( 0, "\nDICTIONARY ATTACK LOCK RESET TEST  :\n" );

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

    // Create policy session
    nonceTpm.t.size = sizeof( nonceTpm ) - 2;
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM_RH_NULL, TPM_RH_NULL, 0, &nonceCaller, &salt,
            TPM_SE_POLICY, &symmetric, TPM_ALG_SHA1, sessionHandle, &nonceTpm, 0 );
    return( rval );
}

void TestTpmStartup()
{
    UINT32 rval;
    
    TpmClientPrintf( 0, "\nSTARTUP TESTS:\n" );

    //
    // First test the one-call interface.
    //

    // First must do TPM reset.
    rval = TpmReset();
    CheckPassed(rval);

    // This one should pass.
    rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval);
    
    // This one should fail.
    rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
    CheckFailed( rval, TPM_RC_INITIALIZE );


    // Cycle power using simulator interface.
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );

    
    //
    // Now test the syncronous, non-one-call interface.
    //
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval);

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed( rval );
    
    // Cycle power using simulator interface.
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );


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
    CheckPassed(rval);
}


void ForceIOError( TSS2_TCTI_CONTEXT *tstTctiContext, SOCKET *savedTpmSock, SOCKET *savedOtherSock, int *savedDevFile, int tpmSock )
{
    if( resMgrInitialized )
    {
        if( tpmSock )
        {
            *savedTpmSock = ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->tpmSock;
            ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->tpmSock = ~*savedTpmSock;
        }
        else
        {
            *savedOtherSock = ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->otherSock;
            ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->otherSock = ~*savedOtherSock;
        }
    }
    else
    {
        *savedDevFile = ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->devFile;
        ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->devFile = ~*savedDevFile;
    }
}

void CleanupIOError( TSS2_TCTI_CONTEXT *tstTctiContext, SOCKET savedTpmSock, SOCKET savedOtherSock, int savedDevFile, int tpmSock )
{
    if( resMgrInitialized )
    {
        if( tpmSock )
        {
            ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->tpmSock = savedTpmSock;
        }
        else
        {
            ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->otherSock = savedOtherSock;
        }
    }
    else
    {
        ( (TSS2_TCTI_CONTEXT_INTEL *)tstTctiContext )->devFile = savedDevFile;
    }
}

void ForceContextError( TSS2_TCTI_CONTEXT *tstTctiContext, int magic, uint64_t *savedMagic, uint32_t *savedVersion )
{
    if( magic )
    {
        *savedMagic = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->magic;
        ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->magic = ~*savedMagic;
    }
    else
    {
        *savedVersion = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->version;
        ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->version = ~*savedVersion;
    }
}

void CleanupContextError( TSS2_TCTI_CONTEXT *tstTctiContext, int magic, uint64_t savedMagic, uint32_t savedVersion )
{
    if( magic )
    {
        ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->magic = savedMagic;
    }
    else
    {
        ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->version = savedVersion;
    }
}

void TestTctiApis( TSS2_TCTI_CONTEXT *tstTctiContext, int againstRM )
{
    uint8_t tpmStartCommandBuffer[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
    uint8_t getTestResultCommandBuffer[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7c };
    uint8_t responseBuffer[20];
    size_t responseSize;
    size_t expectedResponseSize;
    SOCKET savedTpmSock;
    SOCKET savedOtherSock;
    int savedDevFile;
    uint64_t savedMagic;
    uint32_t savedVersion;
    uint8_t goodResponseBuffer[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t goodResponseBuffer1[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t *goodRspBuffer;
    
    int responseBufferError = 0;
    unsigned int i;
    char *typeString;
    char typeRMString[] = "RM";
    char typeLocalString[] = "Local TPM";
    
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    if( tpmManufacturer == MSFT_MANUFACTURER_ID )
    {
        expectedResponseSize = 0x10;
        goodRspBuffer = &( goodResponseBuffer[0] );
    }
    else
    {
        expectedResponseSize = 0x18;
        goodRspBuffer = &( goodResponseBuffer1[0] );
    }

    if( againstRM != 0 )
    {
        typeString = &typeRMString[0];
    }
    else
    {
        typeString = &typeLocalString[0];
    }
    
    TpmClientPrintf( 0, "\nTCTI API TESTS (against %s TCTI interface):\n", typeString );

    //
    // Test transmit for NULL pointers.
    //
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( 0, sizeof( tpmStartCommandBuffer ), &tpmStartCommandBuffer[0] );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #1

    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( tstTctiContext, sizeof( tpmStartCommandBuffer ), 0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #2

    //
    // Test transmit for BAD CONTEXT:  magic.
    //
    ForceContextError( tstTctiContext, 1, &savedMagic, &savedVersion );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( 0, sizeof( tpmStartCommandBuffer ), &tpmStartCommandBuffer[0] );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #3
    CleanupContextError( tstTctiContext, 1, savedMagic, savedVersion );
    
    //
    // Test transmit for BAD CONTEXT:  version.
    //
    ForceContextError( tstTctiContext, 0, &savedMagic, &savedVersion );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( 0, sizeof( tpmStartCommandBuffer ), &tpmStartCommandBuffer[0] );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #4
    CleanupContextError( tstTctiContext, 0, savedMagic, savedVersion );
    
    //
    // Test transmit for IO error.
    //
    ForceIOError( tstTctiContext, &savedTpmSock, &savedOtherSock, &savedDevFile, 1 );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( tstTctiContext, sizeof( tpmStartCommandBuffer ), &tpmStartCommandBuffer[0] );
    CleanupIOError( tstTctiContext, savedTpmSock, savedOtherSock, savedDevFile, 1 );
    CheckFailed( rval, TSS2_TCTI_RC_IO_ERROR ); // #5

    if( againstRM  )
    {
        //
        // Test cancel for SEQUENCE error.
        //
        rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->cancel( tstTctiContext );
        CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE ); // #6

        //
        // Test setLocality for BAD_REFERENCE error.
        //
        rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->setLocality( 0, 0 );
        CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #7
    }
#if 0
    //
    // setLocality in TCTI interface to resource manager doesn't actually do
    // any IO, so this test case will never work.  Left it and this comment here
    // in case anyone ever questions why we're not testing this case.
    //
    
    //
    // Test setLocality for IO error.
    //
    ForceIOError( tstTctiContext, &savedTpmSock, &savedOtherSock, &savedDevFile, 0 );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->setLocality( tstTctiContext, 0 );
    CleanupIOError( tstTctiContext, savedTpmSock, savedOtherSock, savedDevFile, 0 );
    CheckFailed( rval, TSS2_TCTI_RC_IO_ERROR ); // #8
#endif
    
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( tstTctiContext, sizeof( tpmStartCommandBuffer ), &tpmStartCommandBuffer[0] );
    CheckPassed( rval ); // #9

    if( againstRM  )
    {
        //
        // Test cancel for IO error.
        //
        ForceIOError( tstTctiContext, &savedTpmSock, &savedOtherSock, &savedDevFile, 0 );
        rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->cancel( tstTctiContext );
        CleanupIOError( tstTctiContext, savedTpmSock, savedOtherSock, savedDevFile, 0 );
        CheckFailed( rval, TSS2_TCTI_RC_IO_ERROR ); // #8

        //
        // Test setLocality for BAD_REFERENCE error.
        //
        rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->setLocality( tstTctiContext, 0 );
        CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE ); // #10
    }
    
    //
    // Test transmit for SEQUENCE error.
    //
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( tstTctiContext, sizeof( tpmStartCommandBuffer ), &tpmStartCommandBuffer[0] );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE ); // #11

    responseSize = sizeof( responseBuffer );

    if( againstRM  )
    {
        //
        // Test cancel for BAD REFERENCE error.
        //
        rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->cancel( 0 );
        CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #12
    }
    
    //
    // Test receive for NULL pointers.
    //
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( 0, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #13

    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, 0, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #14

    //
    // Test receive for IO error.
    //
    ForceIOError( tstTctiContext, &savedTpmSock, &savedOtherSock, &savedDevFile, 1 );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CleanupIOError( tstTctiContext, savedTpmSock, savedOtherSock, savedDevFile, 1 );
    CheckFailed( rval, TSS2_TCTI_RC_IO_ERROR ); // #16

    //
    // Test receive for BAD CONTEXT:  magic.
    //
    ForceContextError( tstTctiContext, 1, &savedMagic, &savedVersion );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_CONTEXT ); // #17
    CleanupContextError( tstTctiContext, 1, savedMagic, savedVersion );

    //
    // Test receive for BAD CONTEXT:  version.
    //
    ForceContextError( tstTctiContext, 0, &savedMagic, &savedVersion );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_CONTEXT ); // #18
    CleanupContextError( tstTctiContext, 0, savedMagic, savedVersion );

    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval ); // #19

    if( againstRM  )
    {
        // Test cancel for SEQUENCE error.
        rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->cancel( tstTctiContext );
        CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE ); // #20
    }
    
    //
    // Test receive for SEQUENCE error.
    //
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_SEQUENCE ); // #21

    //
    // Test finalize for BAD REFERENCE error.
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->finalize( 0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #22


    //
    // Test Receive for too small a response buffer
    //
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->transmit( tstTctiContext, sizeof( getTestResultCommandBuffer ), &getTestResultCommandBuffer[0] );
    CheckPassed( rval ); // #23

    responseSize = sizeof( TPM20_Header_Out ) - 1;
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_INSUFFICIENT_BUFFER ); // #24

    // Test returned responseSize here.
    if( responseSize != expectedResponseSize )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  responseSize after receive with too small a buffer is incorrect, s/b: 0x%x, was: 0x%x\n", expectedResponseSize, responseSize );
        Cleanup();
    }

    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, 0, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval ); // #24

    // Test returned responseSize here.
    if( responseSize != expectedResponseSize )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  responseSize after receive with NULL responseBuffer is incorrect, s/b: 0x%x, was: 0x%x\n", expectedResponseSize, responseSize );
        Cleanup();
    }

    responseSize = sizeof( TPM20_Header_Out ) - 1 + sizeof( UINT16 );
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_INSUFFICIENT_BUFFER ); // #25

    // Test returned responseSize here.
    if( responseSize != expectedResponseSize )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  responseSize after receive with too small a buffer is incorrect, s/b: 0x%x, was: 0x%x\n", expectedResponseSize, responseSize );
        Cleanup();
    }

    responseSize = sizeof( TPM20_Header_Out ) - 1 + sizeof( UINT16 ) + sizeof( UINT32 ) - 1;
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_TCTI_RC_INSUFFICIENT_BUFFER ); // #26

    // Test returned responseSize here.
    if( responseSize != expectedResponseSize )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  responseSize after receive with too small a buffer is incorrect, s/b: 0x%x, was: 0x%x\n", expectedResponseSize, responseSize );
        Cleanup();
    }

    responseSize = expectedResponseSize;
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->receive( tstTctiContext, &responseSize, &responseBuffer[0], TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval ); // #27

    // Test responseBuffer here.
    // Now compare RP buffer to what it should be
    for( i = 0; i < responseSize; i++ )
    {
        if( responseBuffer[i] != goodRspBuffer[i] )
        {
            responseBufferError = 1;
            break;
        }
    }
    if( responseBufferError )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  responseBuffer after receive is incorrect, s/b:\n" );
        DebugPrintBuffer( (UINT8 *)&goodRspBuffer[0], responseSize );
        TpmClientPrintf( NO_PREFIX, "\nwas:\n" );
        DebugPrintBuffer( (UINT8 *)&responseBuffer, responseSize );
        Cleanup();
    }
    

    // Now test other corner cases for size:  1 bytes smaller than tag size and  1 bytes smaller smaller than tag size plus sizeof UINT32.
    
    
#if 0
    //
    // No getPollHandles function so these are #ifdef'd out for now.
    //
    
    //
    // Test getPollHandles for BAD REFERENCE errors.
    //
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->getPollHandles( (TSS2_TCTI_CONTEXT *)0, (TSS2_TCTI_POLL_HANDLE *)1, (size_t *)1 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #23
    
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->getPollHandles( tstTctiContext, (TSS2_TCTI_POLL_HANDLE *)0, (size_t *)1 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #24
    
    rval = ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tstTctiContext )->getPollHandles( tstTctiContext, (TSS2_TCTI_POLL_HANDLE *)1, (size_t *)0 );
    CheckFailed( rval, TSS2_TCTI_RC_BAD_REFERENCE ); // #25
#endif
}
    

void TestSapiApis()
{
    UINT32 rval;
    TPM2B_MAX_BUFFER    outData = { { MAX_DIGEST_BUFFER, } };
    TPM_RC              testResult;
    TSS2_SYS_CONTEXT    *testSysContext;
    TPM2B_PUBLIC        outPublic;
    TPM2B_NAME          name;
    TPM2B_NAME          qualifiedName;
    UINT8               commandCode[4];
    size_t				rpBufferUsedSize;
	const uint8_t 		*rpBuffer;
	const uint8_t 		goodRpBuffer[] = { 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                                           0x01, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00,
										   0x40 };
    TPMI_YES_NO         moreData;
    TPMS_CAPABILITY_DATA	capabilityData;
    int                 rpBufferError = 0;
    unsigned int        i;
    UINT32              savedRspSize;
    
    TpmClientPrintf( 0, "\nSAPI API TESTS:\n" );

    //
    // First test the one-call interface.
    //
    rval = Tss2_Sys_GetTestResult( sysContext, 0, &outData, &testResult, 0 );
    CheckPassed(rval); // #1 
    
    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #2

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_Execute( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #3

    //
    // Now test the syncronous, non-one-call interface.
    //
    rval = Tss2_Sys_GetTestResult_Prepare( sysContext );
    CheckPassed(rval); // #4

    // Check for BAD_REFERENCE error.
    rval = Tss2_Sys_Execute( 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #5

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed(rval); // #6

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_Execute( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #7

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #8

    // Get the command results
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckPassed(rval); // #9

    //
    // Now test the asyncronous, non-one-call interface.
    //
    rval = Tss2_Sys_GetTestResult_Prepare( sysContext );
    CheckPassed(rval); // #10

    // Test XXXX_Complete for bad sequence:  after _Prepare
    // and before ExecuteFinish
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #11
    
    // Check for BAD_REFERENCE error.
    rval = Tss2_Sys_ExecuteAsync( 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #12

    // Test ExecuteFinish for BAD_SEQUENCE
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #13

    // Execute the command asyncronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed(rval); // #14

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #15

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_Execute( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #16

    // Test ExecuteFinish for BAD_REFERENCE
    rval = Tss2_Sys_ExecuteFinish( 0, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #17

    // Test XXXX_Complete for bad sequence:  after _Prepare
    // and before ExecuteFinish
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #18
    
    // Get the command response. Wait a maximum of 20ms
    // for response.
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed(rval); // #19

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #20

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #21

    // Check for BAD_SEQUENCE error.
    rval = Tss2_Sys_Execute( sysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #22

    // Test _Complete for bad reference cases.
    rval = Tss2_Sys_GetTestResult_Complete( 0, &outData, &testResult );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #23

    // Get the command results
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckPassed(rval); // #24
    
    testSysContext = InitSysContext( 0,  resMgrTctiContext, &abiVersion );
    if( testSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // Test GetCommandCode for bad sequence
    rval = Tss2_Sys_GetCommandCode( testSysContext, &commandCode );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #25

    rval = Tss2_Sys_GetRpBuffer( testSysContext, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #26

    TeardownSysContext( &testSysContext );
    
    rval = Tss2_Sys_ReadPublic_Prepare( sysContext, handle2048rsa );
    CheckPassed(rval); // #27

    // Execute the command syncronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval ); // #28

    // Test _Complete for bad sequence case when ExecuteFinish has never
    // been done on a context.
    rval = Tss2_Sys_ReadPublic_Complete( sysContext, &outPublic, &name, &qualifiedName );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #29

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rval ); // #30

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #31

    rval = Tss2_Sys_ReadPublic_Prepare( sysContext, handle2048rsa );
    CheckPassed(rval); // #32

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #33
    
    rval = Tss2_Sys_ReadPublic_Prepare( sysContext, handle2048rsa );
    CheckPassed(rval); // #34

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed( rval ); // #35

	outPublic.t.size = name.t.size = qualifiedName.t.size = 0;
	rval = Tss2_Sys_ReadPublic( sysContext, handle2048rsa, 0,
            &outPublic, 0, 0, 0 );
    CheckPassed( rval ); // #36
            
    // Check case of ExecuteFinish receving TPM error code.
    // Subsequent _Complete call should fail with SEQUENCE error.
    rval = TpmReset();
    CheckPassed(rval); // #37
    
    rval = Tss2_Sys_GetCapability_Prepare( sysContext,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_ACTIVE_SESSIONS_MAX,
            1 );
    CheckPassed(rval); // #38

    // Execute the command asyncronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed(rval); // #39

    // Get the command response. Wait a maximum of 20ms
    // for response.
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TPM_RC_INITIALIZE ); // #40

    // Test _Complete for case when ExecuteFinish had an error.
    rval = Tss2_Sys_GetCapability_Complete( sysContext, 0, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #41

    rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval); // #42

    rval = Tss2_Sys_GetRpBuffer( 0, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #43
    
    rval = Tss2_Sys_GetRpBuffer( sysContext, 0, &rpBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #44
    
    rval = Tss2_Sys_GetRpBuffer( sysContext, &rpBufferUsedSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #45

    rval = Tss2_Sys_GetRpBuffer( sysContext, &rpBufferUsedSize, &rpBuffer );
    CheckPassed( rval ); // #46
    
    // Now test case for ExecuteFinish where TPM returns
    // an error.  ExecuteFinish should return same error
    // as TPM.
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval); // #47

    // Execute the command ayncronously.
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval ); // #48

    rval = Tss2_Sys_Startup( sysContext, TPM_SU_CLEAR );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #49

    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rval, TPM_RC_INITIALIZE ); // #50

    // Now test case for ExecuteFinish where TPM returns
    // an error.  ExecuteFinish should return same error
    // as TPM.
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval); // #51

    rval = Tss2_Sys_GetRpBuffer( sysContext, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #52
    
    // Execute the command ayncronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckFailed( rval, TPM_RC_INITIALIZE ); // #53

    rval = Tss2_Sys_GetRpBuffer( sysContext, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #54
    
    // Test one-call for null sysContext pointer.
    rval = Tss2_Sys_Startup( 0, TPM_SU_CLEAR );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #55

    // Test one-call for NULL input parameter that should be a
    // pointer.
    rval = Tss2_Sys_Create( testSysContext, 0xffffffff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #56

    // Test GetCommandCode for bad reference
    rval = Tss2_Sys_GetCommandCode( 0, &commandCode );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #57
    
    rval = Tss2_Sys_GetCommandCode( sysContext, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #58

    //
    // Test GetRpBuffer for case of no response params or handles.
    //
    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_STATE, 0 );
    CheckPassed( rval ); // #59

    rval = Tss2_Sys_GetRpBuffer( sysContext, &rpBufferUsedSize, &rpBuffer );
    CheckPassed( rval ); // #60

    if( rpBufferUsedSize != 0 )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  Tss2_Sys_GetRpBuffer returned non-zero size for command that returns no handles or parameters\n" );
        Cleanup();
    }

    //
    // Test GetRpBuffer for case of response params.
    //
    rval = Tss2_Sys_GetCapability( sysContext, 0, 
            TPM_CAP_TPM_PROPERTIES, TPM_PT_ACTIVE_SESSIONS_MAX,
            1, &moreData, &capabilityData, 0 );
    CheckPassed(rval); // #61

    rval = Tss2_Sys_GetRpBuffer( sysContext, &rpBufferUsedSize, &rpBuffer );
    CheckPassed( rval ); // #62

    if( rpBufferUsedSize != 17 )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  Tss2_Sys_GetRpBuffer returned wrong size for command that returns handles and/or parameters\n" );
        Cleanup();
    }

    // Now compare RP buffer to what it should be
    for( i = 0; i < rpBufferUsedSize; i++ )
    {
        if( rpBuffer[i] != goodRpBuffer[i] )
        {
            rpBufferError = 1;
            break;
        }
    }

    if( rpBufferError )
    {
        TpmClientPrintf( NO_PREFIX, "\nERROR!!  Tss2_Sys_GetRpBuffer returned wrong rpBuffer contents:\nrpBuffer was: \n\t" );
        DebugPrintBuffer( (UINT8 *)&rpBuffer, rpBufferUsedSize );
        TpmClientPrintf( NO_PREFIX, "\nrpBuffer s/b:\n\t" );
        DebugPrintBuffer( (UINT8 *)&(goodRpBuffer[0]), rpBufferUsedSize );
        Cleanup();
    }
    
    TeardownSysContext( &testSysContext );

    rval = Tss2_Sys_GetTestResult_Prepare( sysContext );
    CheckPassed(rval); // #63

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed(rval); // #64

    // Get the command results
    // NOTE: this test modifies internal fields of the sysContext structure.
    // DON'T DO THIS IN REAL APPS!!
    savedRspSize = CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->responseSize );
    ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->responseSize = 4097;
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->responseSize = savedRspSize;
    CheckFailed( rval, TSS2_SYS_RC_MALFORMED_RESPONSE ); // #65

    // NOTE: this test case is kind of bogus--no application would ever do this
    // since apps can't change the responseSize after TPM has returned the response.
    // ONce the MALFOMED_RESPONSE occurs, there's no way to recover the response data.
    rval = Tss2_Sys_GetTestResult_Complete( sysContext, &outData, &testResult );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #66
}


void TestTpmSelftest()
{   
    UINT32 rval;

    TpmClientPrintf( 0, "\nSELFTEST TESTS:\n" );

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
    
    TpmClientPrintf( 0, "\nGET_CAPABILITY TESTS:\n" );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );

    *( (UINT32 *)manuIDPtr ) = CHANGE_ENDIAN_DWORD( capabilityData.data.tpmProperties.tpmProperty[0].value );
    TpmClientPrintf( 0, "\t\tcount: %d, property: %x, manuId: %s\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            manuID );
            
    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_COMMAND_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    TpmClientPrintf( 0, "\t\tcount: %d, property: %x, max cmd size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );
            

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_COMMAND_SIZE, 40, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    TpmClientPrintf( 0, "\t\tcount: %d, property: %x, max cmd size: %d\n",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );
            

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_RESPONSE_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    TpmClientPrintf( 0, "\t count: %d, property: %x, max response size: %d\n",
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
    
    TpmClientPrintf( 0, "\nCLEAR and CLEAR CONTROL TESTS:\n" );

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
    UINT16 i, debugGapMax = DEBUG_GAP_MAX, debugMaxActiveSessions = DEBUG_MAX_ACTIVE_SESSIONS;
    TPMA_LOCALITY locality;
    TPM_HANDLE badSessionHandle = 0x03010000;

    TPMS_AUTH_COMMAND sessionData;
    TPM2B_NONCE     nonce;
    TSS2_SYS_CMD_AUTHS sessionsDataIn;

    TPMS_AUTH_COMMAND *sessionDataArray[1];

    TPM2B_AUTH      hmac;

    TPMS_CONTEXT    evictedSessionContext;
    TPM_HANDLE   evictedHandle;
    
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
    
    TpmClientPrintf( 0, "\nSTART_AUTH_SESSION TESTS:\n" );
    
    symmetric.algorithm = TPM_ALG_NULL;
    symmetric.keyBits.sym = 0;
    symmetric.mode.sym = 0;

    nonceCaller.t.size = 0;

    encryptedSalt.t.size = 0;
    
     // Init session
    rval = StartAuthSessionWithParams( &authSession, TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval );
    
    rval = Tss2_Sys_FlushContext( sysContext, authSession->sessionHandle );
    CheckPassed( rval );
    EndAuthSession( authSession );

    // Init session
    rval = StartAuthSessionWithParams( &authSession, TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, 0xff, &symmetric, TPM_ALG_SHA256 );
    CheckFailed( rval, TPM_RC_VALUE + TPM_RC_P + TPM_RC_3 );

    // Try starting a bunch to see if resource manager handles this correctly.
    
#ifdef DEBUG_GAP_HANDLING   
    for( i = 0; i < debugMaxActiveSessions*3; i++ )
#else        
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
#endif        
    {
//        TpmClientPrintf( 0, "i = 0x%4.4x\n", i );

        // Init session struct
        rval = StartAuthSessionWithParams( &sessions[i], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
        CheckPassed( rval );
        TpmClientPrintf( 0, "Number of sessions created: %d\n\n", i );

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
    TpmClientPrintf( 0, "loading evicted session's context\n" );
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
//        TpmClientPrintf( 0, "i(2) = 0x%4.4x\n", i );
        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );

        rval = EndAuthSession( sessions[i] );
    }

    // Now do some gap tests.
    rval = StartAuthSessionWithParams( &sessions[0], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval );

#ifdef DEBUG_GAP_HANDLING   
//    for( i = 1; i < debugGapMax/2; i++ )
    for( i = 1; i < 300; i++ )
#else        
    for( i = 1; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
#endif        
    {
//        TpmClientPrintf( 0, "i(3) = 0x%4.4x\n", i );
        
        rval = StartAuthSessionWithParams( &sessions[i], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i] );
        CheckPassed( rval );
    }

#ifdef DEBUG_GAP_HANDLING   
    // Now do some gap tests.
    rval = StartAuthSessionWithParams( &sessions[8], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval );
#endif
    
#ifdef DEBUG_GAP_HANDLING   
    for( i = 9; i < debugGapMax; i++ )
#else        
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
#endif        
    {
//        TpmClientPrintf( 0, "i(4) = 0x%4.4x\n", i );
        rval = StartAuthSessionWithParams( &sessions[i], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        rval = EndAuthSession( sessions[i] );
        CheckPassed( rval );
        
    }
    
#ifdef DEBUG_GAP_HANDLING   
    for( i = 0; i < 5; i++ )
    {
//        TpmClientPrintf( 0, "i(5) = 0x%4.4x\n", i );
        rval = StartAuthSessionWithParams( &sessions[i+16], TPM_RH_NULL, 0, TPM_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
        CheckPassed( rval );
    }

    for( i = 0; i < 5; i++ )
    {
//        TpmClientPrintf( 0, "i(6) = 0x%4.4x\n", i );
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
    
    TpmClientPrintf( 0, "\nCHANGE_EPS TESTS:\n" );

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
    
    TpmClientPrintf( 0, "\nCHANGE_PPS TESTS:\n" );

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

    TpmClientPrintf( 0, "\nHIERARCHY_CHANGE_AUTH TESTS:\n" );
    
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
    
    TpmClientPrintf( 0, "\nPCR_EXTEND, PCR_EVENT, PCR_ALLOCATE, and PCR_READ TESTS:\n" );
    
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
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_17 );
        
    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterBeforeExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    if( pcrValues.digests[0].t.size <= PCR_SIZE &&
            pcrValues.digests[0].t.size <= sizeof( pcrValues.digests[0].t.buffer ) )
        memcpy( &( pcrBeforeExtend[0] ), &( pcrValues.digests[0].t.buffer[0] ), pcrValues.digests[0].t.size );

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;
    
    rval = Tss2_Sys_PCR_Extend( sysContext, PCR_17, &sessionsData, &digests, 0  );
    CheckPassed( rval );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    memcpy( &( pcrAfterExtend[0] ), &( pcrValues.digests[0].t.buffer[0] ), pcrValues.digests[0].t.size );

    if( pcrUpdateCounterBeforeExtend == pcrUpdateCounterAfterExtend )
    {
        TpmClientPrintf( 0, "ERROR!! pcrUpdateCounter didn't change value\n" );
        Cleanup();
    }

    if( 0 == memcmp( &( pcrBeforeExtend[0] ), &( pcrAfterExtend[0] ), 20 ) )
    {
        TpmClientPrintf( 0, "ERROR!! PCR didn't change value\n" );
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
    
    rval = Tss2_Sys_PCR_Event( sysContext, PCR_18, &sessionsData, &eventData, &digests, 0  );
    CheckPassed( rval );
}

void TestGetRandom()
{
    UINT32 rval;
    TPM2B_DIGEST        randomBytes1, randomBytes2;
    
    TpmClientPrintf( 0, "\nGET_RANDOM TESTS:\n" );

    randomBytes1.t.size = sizeof( randomBytes1 ) - 2;
    rval = Tss2_Sys_GetRandom( sysContext, 0, 20, &randomBytes1, 0 );
    CheckPassed( rval );

    randomBytes2.t.size = sizeof( randomBytes2 ) - 2;
    rval = Tss2_Sys_GetRandom( sysContext, 0, 20, &randomBytes2, 0 );
    CheckPassed( rval );

    if( 0 == memcmp( &randomBytes1, &randomBytes2, 20 ) )
    {
        TpmClientPrintf( 0, "ERROR!! Random value is the same\n" );
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
    
    TpmClientPrintf( 0, "\nSHUTDOWN TESTS:\n" );
    
    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_STATE, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM_SU_CLEAR, &sessionsDataOut );
    CheckPassed( rval );

    if( !( tpmSpecVersion == 115 || tpmSpecVersion == 119 ) )
    {
        rval = Tss2_Sys_Shutdown( sysContext, 0, 0xff, 0 );
        CheckFailed( rval, TPM_RC_VALUE+TPM_RC_1+TPM_RC_P );
    }
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

    TpmClientPrintf( 0, "\nNV INDEX TESTS:\n" );

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
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
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

    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut ); 
    CheckFailed( rval, TPM_RC_2 + TPM_RC_HANDLE );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );

    nvPublic.t.size = 0;
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

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

    nvData.t.size = sizeof( nvData ) - 2;
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut ); 
    CheckPassed( rval );

    rval = Tss2_Sys_NV_WriteLock( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &sessionsDataOut ); 
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Write( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM_RC_NV_LOCKED );
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
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.nvIndex = TPM20_INDEX_TEST2;
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    nvPublic.t.size = 0;
    nvName.t.size = sizeof( nvName ) - 2;
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST2, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    nvData.t.size = sizeof( nvData ) - 2;
    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST2, &sessionsData, 32, 0, &nvData, 0 ); 
    CheckFailed( rval, TPM_RC_NV_AUTHORIZATION );

    // Now undefine the index.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );

#if 0
    TpmClientPrintf( 0, "\nStart of NVUndefineSpaceSpecial test\n" );
    
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
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM_RH_NULL, TPM_RH_PLATFORM, 0, &nonceNewer, &salt,
            TPM_SE_TRIAL, &symmetric, TPM_ALG_SHA1, &nvSessionHandle, &nvSessionNonce );
    CheckPassed( rval );

    nvSessionHandle = ( ( TPM20_StartAuthSession_Out *)(TpmOutBuff) )->sessionHandle;

    rval = Tss2_Sys_PolicyCommandCode ( sysContext, nvSessionHandle, 0, TPM_CC_NV_UndefineSpaceSpecial, 0 );
    CheckPassed( rval );

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

    TpmClientPrintf( 0, "\nHIERARCHY CONTROL TESTS:\n" );

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
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
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
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    nvPublic.t.size = 0;
    nvName.t.size = sizeof( nvName ) - 2;
    rval = Tss2_Sys_NV_ReadPublic( sysContext, TPM20_INDEX_TEST1, 0, &nvPublic, &nvName, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Read( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 32, 0, &nvData, &sessionsDataOut ); 
    CheckFailed( rval, TPM_RC_NV_UNINITIALIZED );

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
    
    // Now undefine the index so that next run will work correctly.
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );
}

TPM2B_PUBLIC    inPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };

void TestCreate(){
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive = { { sizeof( TPM2B_SENSITIVE_CREATE ) - 2, } };
    TPM2B_DATA              outsideInfo = { { sizeof( TPM2B_DATA ) - 2, } };
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
	TPM2B_NAME name = { { sizeof( TPM2B_NAME ) - 2, } };
	TPM2B_NAME name1 = { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_PRIVATE outPrivate = { { sizeof( TPM2B_PRIVATE ) - 2, } };
    TPM2B_PUBLIC outPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };
    TPM2B_CREATION_DATA creationData =  { { sizeof( TPM2B_CREATION_DATA ) - 2, } };
	TPM2B_DIGEST creationHash = { { sizeof( TPM2B_DIGEST ) - 2, } };
	TPMT_TK_CREATION creationTicket = { 0, 0, { { sizeof( TPM2B_DIGEST ) - 2, } } };

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
        
    TpmClientPrintf( 0, "\nCREATE, CREATE PRIMARY, and LOAD TESTS:\n" );

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
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );
    
    outPublic.t.size = 0;
    creationData.t.size = sizeof( TPM2B_CREATION_DATA ) - 2;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );
    
    outPublic.t.size = 0;
    creationData.t.size = 0;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_PLATFORM, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    TpmClientPrintf( 0, "\nNew key successfully created in platform hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
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
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    rval = (*HandleToNameFunctionPtr)( loadedSha1KeyHandle, &name1 );
    CheckPassed( rval );
    OpenOutFile( &outFp );
    TpmClientPrintf( 0, "Name of loaded key: " );
    PrintSizedBuffer( (TPM2B *)&name1 );
    CloseOutFile( &outFp );

    rval = CompareTPM2B( &name.b, &name1.b );
    CheckPassed( rval );
    
    TpmClientPrintf( 0, "\nLoaded key handle:  %8.8x\n", loadedSha1KeyHandle );
}

void TestEvict()
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_SENSITIVE_CREATE  inSensitive = { { sizeof( TPM2B_SENSITIVE_CREATE ) - 2, } };
    TPM2B_DATA              outsideInfo = { { sizeof( TPM2B_DATA ) - 2, } };
    TPML_PCR_SELECTION      creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    TPM2B_PRIVATE outPrivate = { { sizeof( TPM2B_PRIVATE ) - 2, } };
    TPM2B_PUBLIC outPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };
    TPM2B_CREATION_DATA creationData =  { { sizeof( TPM2B_CREATION_DATA ) - 2, } };
	TPM2B_DIGEST creationHash = { { sizeof( TPM2B_DIGEST ) - 2, } };
	TPMT_TK_CREATION creationTicket = { 0, 0, { { sizeof( TPM2B_DIGEST ) - 2, } } };

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TSS2_TCTI_CONTEXT *otherResMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *otherSysContext;
    char otherResMgrInterfaceName[] = "Other Resource Manager";

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;

    sessionsDataOut.rspAuthsCount = 1;
    
    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    TpmClientPrintf( 0, "\nEVICT CONTROL TESTS:\n" );

    // Make transient key persistent.
    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // init hmac
    sessionData.hmac.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    rval = Tss2_Sys_EvictControl( sysContext, TPM_RH_PLATFORM, handle2048rsa, &sessionsData, 0x81800000, &sessionsDataOut );
    CheckPassed( rval );

    sessionData.sessionHandle = TPM_RS_PW;

    // Init nonce.
    sessionData.nonce.t.size = 0;

    // Init session attributes
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    // Create new key under persistent one.
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.sign = 1;

    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA1;

    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.userAuth = loadedSha1KeyAuth;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = loadedSha1KeyAuth.b.size + 2;
    
    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;

    // Try creating a key under the persistent key using a different context.

    rval = InitTctiResMgrContext( &rmInterfaceConfig, &otherResMgrTctiContext, &otherResMgrInterfaceName[0] );
    if( rval != TSS2_RC_SUCCESS )
    {
        TpmClientPrintf( 0, "Resource Mgr, failed initialization: 0x%x.  Exiting...\n", rval );
        Cleanup();
        return;
    }
    else
    {
        (( TSS2_TCTI_CONTEXT_INTEL *)otherResMgrTctiContext )->status.debugMsgLevel = debugLevel;
    }
    
    otherSysContext = InitSysContext( 0, otherResMgrTctiContext, &abiVersion );
    if( otherSysContext == 0 )
    {
        InitSysContextFailure();
    }
    
    rval = Tss2_Sys_Create( otherSysContext, 0x81800000, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    rval = TeardownTctiResMgrContext( otherResMgrTctiContext );
    CheckPassed( rval );
    
    TeardownSysContext( &otherSysContext );
    
    outsideInfo.t.size = 0;
    outPublic.t.size = 0;
    creationData.t.size = 0;

    // Try creating a key under the transient key.  This should work, too.
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    // Reset persistent key to be transitent.
    sessionData.hmac.t.size = 0;
    rval = Tss2_Sys_EvictControl( sysContext, TPM_RH_PLATFORM, 0x81800000, &sessionsData, 0x81800000, &sessionsDataOut );
    CheckPassed( rval );
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
    rval = StartAuthSessionWithParams( policySession, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, trialSession ? TPM_SE_TRIAL : TPM_SE_POLICY , &symmetric, TPM_ALG_SHA256 );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    // Send policy command.
    rval = ( *buildPolicyFn )( sysContext, *policySession, policyDigest );
    CheckPassed( rval );

    // Get policy hash.
    policyDigest->t.size = sizeof( *policyDigest ) - 2;
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
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval );

    // Send PolicyLocality command
    *(UINT8 *)( (void *)&locality ) = 0;
    locality.TPM_LOC_THREE = 1;
    rval = Tss2_Sys_PolicyLocality( sysContext, (*policySession)->sessionHandle,
            0, locality, 0 );
    CheckPassed( rval );

    // Read policyHash
    policyDigest->t.size = sizeof( *policyDigest ) - 2;
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
    pcrDigest.t.size = sizeof( pcrDigest ) - 2;
    rval = TpmHashSequence( policySession->authHash, pcrValues.count, &pcrValues.digests[0], &pcrDigest );
    CheckPassed( rval );
    
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
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_PLATFORM, &cmdAuthArray,
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
    
    outPublic.t.size = 0;
    creationData.t.size = 0;
    outPrivate.t.size = sizeof( outPrivate ) - 2;
    creationHash.t.size = sizeof( creationHash ) - 2;
    rval = Tss2_Sys_Create( sysContext, srkHandle, &cmdAuthArray,
            &inSensitive, &inPublic, &outsideInfo, &creationPcr,
            &outPrivate, &outPublic, &creationData, &creationHash,
            &creationTicket, 0 );
    CheckPassed( rval );

    // Now we need to load the object.
    blobName.t.size = sizeof( blobName ) - 2;
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
    outData.t.size = sizeof( outData ) - 2;
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckFailed( rval, TPM_RC_S + TPM_RC_1 + TPM_RC_AUTH_FAIL );

    // Clear DA lockout.
    TestDictionaryAttackLockReset();
    
    // Now try to unseal the blob after setting the password.
    // This test should pass.
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
    { "LOCALITY", 0, CreateNVIndex, TestLocality },
    { "PASSWORD", BuildPasswordPolicy, CreateDataBlob, PasswordUnseal },
    { "PASSWORD/PCR", BuildPasswordPcrPolicy, CreateDataBlob, PasswordUnseal },
    { "AUTHVALUE", BuildAuthValuePolicy, CreateDataBlob, AuthValueUnseal },
    // TBD...        
};

void TestPolicy()
{
    UINT32 rval;
    unsigned int i;
    SESSION *policySession = 0;

    TpmClientPrintf( 0, "\nPOLICY TESTS:\n" );

    for( i = 0; i < ( sizeof( policyTestSetups ) / sizeof( POLICY_TEST_SETUP ) ); i++ )
    {
        TPM2B_DIGEST policyDigest;

        policyDigest.t.size = 0;

        rval = TPM_RC_SUCCESS;

        TpmClientPrintf( 0, "Policy Test: %s\n", policyTestSetups[i].name );

        // Create trial policy session and run policy commands, in order to create policyDigest.
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, true );
            CheckPassed( rval );
#ifdef DEBUG
            TpmClientPrintf( 0, "Built policy digest:  \n" );
            DebugPrintBuffer( &(policyDigest.t.buffer[0]), policyDigest.t.size );
#endif
        }

        // Create entity that will use that policyDigest as authPolicy.
        if( policyTestSetups[i].createObjectFn != 0 )
        {
#ifdef DEBUG
            TpmClientPrintf( 0, "Policy digest used to create object:  \n" );
            DebugPrintBuffer( &(policyDigest.t.buffer[0]), policyDigest.t.size );
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
            TpmClientPrintf( 0, "Command policy digest:  \n" );
            DebugPrintBuffer( &(policyDigest.t.buffer[0]), policyDigest.t.size );
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
    
    TpmClientPrintf( 0, "\nHASH TESTS:\n" );

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
        result.t.size = sizeof( result ) - 2;
        rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle[i], &sessionsData, &dataToHash,
                TPM_RH_PLATFORM, &result, &validation, &sessionsDataOut );
        CheckPassed( rval );
    }
    
    //  Now try to finish the interrupted sequence.
    rval = Tss2_Sys_SequenceUpdate ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash, &sessionsDataOut );
    CheckPassed( rval );
    
    dataToHash.t.size = sizeof( memoryToHash ) - MAX_DIGEST_BUFFER;
    memcpy( &dataToHash.t.buffer[0], &memoryToHash[MAX_DIGEST_BUFFER], dataToHash.t.size );
    rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle[0], &sessionsData, &dataToHash,
            TPM_RH_PLATFORM, &result, &validation, &sessionsDataOut );
    CheckPassed( rval );

    // Test the resulting hash.
    if( memcmp( (void *)&( result.t.buffer[0] ), (void *)&( goodHashValue[0] ), result.t.size ) )
    {
        TpmClientPrintf( 0, "ERROR!! resulting hash is incorrect.\n" );
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
    
    TpmClientPrintf( 0, "\nQUOTE CONTROL TESTS:\n" );

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
    
    TpmClientPrintf( 0, "\nPROVISION OTHER NV INDICES:\n" );

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
    DEBUG_PRINT_BUFFER( &( nvPolicyHash.t.buffer[0] ), nvPolicyHash.t.size );

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
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;

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
    locality.TPM_LOC_THREE = 1;
    locality.TPM_LOC_FOUR = 1;
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
    
    TpmClientPrintf( 0, "\nPROVISION NV AUX:\n" );

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
    nvPolicyHash.t.size = sizeof( nvPolicyHash ) - 2;
    rval = Tss2_Sys_PolicyGetDigest( sysContext, nvAuxPolicyAuthHandle, 0, &nvPolicyHash, 0 );
    CheckPassed( rval );

    // Now save the policy digest.
    DEBUG_PRINT_BUFFER( &( nvPolicyHash.t.buffer[0] ), nvPolicyHash.t.size );

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

    TpmClientPrintf( 0, "TPM AUX READ/WRITE TEST\n" );
    
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

        nvData.t.size = sizeof( TPM2B_MAX_NV_BUFFER ) - 2;
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

    TpmClientPrintf( 0, "TPM OTHER READ/WRITE TEST\n" );

    nvWriteData.t.size = 4;
    for( i = 0; i < nvWriteData.t.size; i++ )
        nvWriteData.t.buffer[i] = 0xff - i;

    nullSessionsData.cmdAuthsCount = 1;
    nullSessionsData.cmdAuths[0] = &nullSessionData;

    rval = Tss2_Sys_NV_Write( sysContext, INDEX_LCP_SUP, INDEX_LCP_SUP, &nullSessionsData, &nvWriteData, 0, &nullSessionsDataOut ); 
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Write( sysContext, INDEX_LCP_OWN, INDEX_LCP_OWN, &nullSessionsData, &nvWriteData, 0, &nullSessionsDataOut ); 
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Read( sysContext, INDEX_LCP_SUP, INDEX_LCP_SUP, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut ); 
    CheckPassed( rval );

    rval = Tss2_Sys_NV_Read( sysContext, INDEX_LCP_OWN, INDEX_LCP_OWN, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut ); 
    CheckPassed( rval );
}
    
void NvIndexProto()
{
    UINT32 rval;

    TpmClientPrintf( 0, "\nNV INDEX PROTOTYPE TESTS:\n" );

    
    // AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer
    // PS index: Write and read are unrestricted until TPM2_WriteLock. After that content is write protected
    // PO index: Write is restricted by ownerAuth; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer

    // Now we need to configure NV indices
    ProvisionNvAux();
    
    ProvisionOtherIndices();

    TpmAuxReadWriteTest();

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

    TpmClientPrintf( 0, "\nPCR ALLOCATE TEST  :\n" );

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

    pcrSelection.count = 3;
    pcrSelection.pcrSelections[0].hash = TPM_ALG_SHA256;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[0] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[0], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_5 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_7 );
    pcrSelection.pcrSelections[1].hash = TPM_ALG_SHA384;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[1] );
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[1], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[1], PCR_5 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[1], PCR_8 );
    pcrSelection.pcrSelections[2].hash = TPM_ALG_SHA256;
    CLEAR_PCR_SELECT_BITS( pcrSelection.pcrSelections[2] ); 
    SET_PCR_SELECT_SIZE( pcrSelection.pcrSelections[2], 3 );
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[2], PCR_6 );

    rval = Tss2_Sys_PCR_Allocate( sysContext, TPM_RH_PLATFORM, &sessionsData, &pcrSelection,
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
    
    TpmClientPrintf( 0, "\nUNSEAL TEST  :\n" );

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
    creationHash.t.size = sizeof( creationHash ) - 2;
    outPrivate.t.size = sizeof( outPrivate ) - 2;
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    CheckPassed( rval );

    name.t.size = sizeof( name ) - 2;
    rval = Tss2_Sys_LoadExternal ( sysContext, 0, 0, &outPublic,
            TPM_RH_PLATFORM, &loadedObjectHandle, &name, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, loadedObjectHandle ); 
    CheckPassed( rval );

    name.t.size = sizeof( name ) - 2;
    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedObjectHandle, &name, &sessionsDataOut);
    CheckPassed( rval );

    sessionData.hmac.t.size = sizeof( authStr ) - 1;
    memcpy( &( sessionData.hmac.t.buffer[0] ), authStr, sizeof( authStr ) - 1 );

    outData.t.size = sizeof( outData ) - 2;
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
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
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

    TpmClientPrintf( 0, "\nPASSWORD TESTS:\n" );

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

    TpmClientPrintf( 0, "\nSIMPLE POLICY TEST:\n" );

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
            &symmetric, sessionAlg );
    CheckPassed( rval );

    rval = Tss2_Sys_PolicyAuthValue( sysContext, trialPolicySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    // Get policy digest.
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
            &symmetric, sessionAlg );
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
        TpmClientPrintf( 0, "ERROR!! read data not equal to written data\n" );
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

    TpmClientPrintf( 0, "\nSIMPLE HMAC SESSION TEST:\n" );

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
            &symmetric, TPM_ALG_SHA256 );
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
        TpmClientPrintf( 0, "ERROR!! read data not equal to written data\n" );
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

    TpmClientPrintf( 0, "\nSIMPLE %s SESSION TEST:\n", testString );

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
                &symmetric, TPM_ALG_SHA256 );
        CheckPassed( rval );

        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                trialPolicySession->sessionHandle, 0, 0 );
        CheckPassed( rval );

        // Get policy digest.
        authPolicy.t.size = sizeof( authPolicy ) - 2;
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
            &symmetric, TPM_ALG_SHA256 );
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
        TpmClientPrintf( 0, "ERROR!! read data not equal to written data\n" );
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
    TpmClientPrintf( 0, "\nHMAC SESSION TESTS:\n" );

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

                TpmClientPrintf( 0, "\n\n%s:\n", hmacTestSetups[j].hmacTestDescription );

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
                    encryptedSalt.t.size = sizeof( encryptedSalt ) - 2;
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

                sessionsData.cmdAuths[0]->sessionHandle = TPM_RS_PW;
                sessionsData.cmdAuths[0]->nonce.t.size = 0;
                sessionsData.cmdAuths[0]->nonce.t.buffer[0] = 0xa5;
                sessionData.hmac.t.size = 0;

                // Undefine the index in case a previous test failure left it defined.
                rval = Tss2_Sys_NV_UndefineSpace( wrSysContext, TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );

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
                        TPM_SE_HMAC, &symmetric, TPM_ALG_SHA1 );
                CheckPassed( rval );

                // Get and print name of the session.
                rval = (*HandleToNameFunctionPtr)( nvSession->sessionHandle, &nvSession->name );
                CheckPassed( rval );

                OpenOutFile( &outFp );
                TpmClientPrintf( 0, "Name of authSession: " );
                PrintSizedBuffer( (TPM2B *)&nvSession->name );
                CloseOutFile( &outFp );

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

                    rval = StartAuthSessionWithParams( &nvSession, hmacTestSetups[j].tpmKey,  hmacTestSetups[j].salt, hmacTestSetups[j].bound, &nvAuth, &nonceOlder, &encryptedSalt, TPM_SE_HMAC, &symmetric, TPM_ALG_SHA1 );
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

    TpmClientPrintf( 0, "\n\nDECRYPT/ENCRYPT SESSION TESTS:\n" );

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
                &symmetric, TPM_ALG_SHA256 );
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
                TpmClientPrintf( 0, "ERROR!! decryptParamSize != 0\n" );
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
            TpmClientPrintf( 0, "ERROR!! read data not equal to written data\n" );
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
        rval = Tss2_Sys_NV_Read_Complete( sysContext, &readData );
        CheckPassed( rval );

        TpmClientPrintf( 0, "Decrypted read data = " );
        DEBUG_PRINT_BUFFER( &readData.t.buffer[0], (UINT32 )readData.t.size );

        // Check that write and read data are equal.
        if( memcmp( (void *)&readData.t.buffer[0],
                (void *)&writeData.t.buffer[0], readData.t.size ) )
        {
            TpmClientPrintf( 0, "ERROR!! read data not equal to written data\n" );
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
    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );

    CheckPassed( rval );

    // Load private key into TPM
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
    
    TpmClientPrintf( 0, "\nGET/SET DECRYPT PARAM TESTS:\n" );

    // Create two sysContext structures.
    decryptParamTestSysContext = InitSysContext( MAX_NV_BUFFER_SIZE, resMgrTctiContext, &abiVersion );
    if( decryptParamTestSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // Test for bad sequence:  Tss2_Sys_GetDecryptParam
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    // Test for bad sequence:  Tss2_Sys_SetDecryptParam
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.t.buffer[0] ) );
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
            TpmClientPrintf( 0, "ERROR!!  decryptParamBuffer[%d] s/b: %2.2x, was: %2.2x\n", i, nvWriteData.t.buffer[i], decryptParamBuffer[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize1, &cpBuffer1 );
    CheckPassed( rval );

    OpenOutFile( &outFp );
#ifdef DEBUG
    TpmClientPrintf( 0, "cpBuffer = ");
#endif    
    DEBUG_PRINT_BUFFER( (UINT8 *)cpBuffer1, cpBufferUsedSize1 );
    CloseOutFile( &outFp );
    
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
        TpmClientPrintf( 0, "ERROR!!  decryptParamSize s/b: 0, was: %u\n", (unsigned int)decryptParamSize );
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

    OpenOutFile( &outFp );
#ifdef DEBUG
    TpmClientPrintf( 0, "cpBuffer = ");
#endif    
    DEBUG_PRINT_BUFFER( (UINT8 *)cpBuffer2, cpBufferUsedSize2 );
    CloseOutFile( &outFp );

    if( cpBufferUsedSize1 != cpBufferUsedSize2 )
    {
        TpmClientPrintf( 0, "ERROR!!  cpBufferUsedSize1(%x) != cpBufferUsedSize2(%x)\n", (UINT32)cpBufferUsedSize1, (UINT32)cpBufferUsedSize2 );
        Cleanup();
    }
    for( i = 0; i < (int)cpBufferUsedSize1; i++ )
    {
        if( cpBuffer1[i] != cpBuffer2[i] )
        {
            TpmClientPrintf( 0, "ERROR!! cpBufferUsedSize1[%d] s/b: %2.2x, was: %2.2x\n", i, cpBuffer1[i], cpBuffer2[i] );
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

void SysInitializeTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    // NOTE: this should never be done in real applications.
    // It is only done here for test purposes.
    TSS2_TCTI_CONTEXT_INTEL tctiContextIntel;

    TpmClientPrintf( 0, "\nSYS INITIALIZE TESTS:\n" );

    rval = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)0, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );
    
    rval = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)0, (TSS2_ABI_VERSION *)1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );
    
    rval = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );
    
    rval = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT );

    // NOTE: don't do this in real applications.
    tctiContextIntel.transmit = (TCTI_TRANSMIT_PTR)0;
    tctiContextIntel.receive = (TCTI_RECEIVE_PTR)1;

    rval = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_TCTI_STRUCTURE );

    // NOTE: don't do this in real applications.
    tctiContextIntel.transmit = (TCTI_TRANSMIT_PTR)1;
    tctiContextIntel.receive = (TCTI_RECEIVE_PTR)0;

    rval = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_TCTI_STRUCTURE );
}

void SysFinalizeTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    TpmClientPrintf( 0, "\nSYS FINALIZE TESTS:\n" );

    rval = Tss2_Sys_Finalize( 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    // Note:  other cases tested by other tests.
}

void GetContextSizeTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_CONTEXT *testSysContext;
    
    TpmClientPrintf( 0, "\nSYS GETCONTEXTSIZE TESTS:\n" );

    testSysContext = InitSysContext( 9, resMgrTctiContext, &abiVersion );
    if( testSysContext == 0 )
    {
        InitSysContextFailure();
    }

    rval = Tss2_Sys_Startup( testSysContext, TPM_SU_CLEAR );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT );

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
            
    TpmClientPrintf( 0, "\nSYS GETTCTICONTEXT TESTS:\n" );

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

void PrepareTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_CONTEXT *testSysContext;
    
    TpmClientPrintf( 0, "\nSYS PREPARE TESTS:\n" );

    testSysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    if( testSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // Test for bad reference.
    rval = Tss2_Sys_GetTestResult_Prepare( 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    // Test for bad sequence:  after ExecuteAsync
    rval = Tss2_Sys_GetTestResult_Prepare( testSysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_ExecuteAsync( testSysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_GetTestResult_Prepare( testSysContext );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    rval = Tss2_Sys_ExecuteFinish( testSysContext, -1 );
    CheckPassed( rval );

    // Test for bad sequence:  after Execute
    rval = Tss2_Sys_GetTestResult_Prepare( testSysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_Execute( testSysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_GetTestResult_Prepare( testSysContext );
    CheckPassed( rval );

    rval = Tss2_Sys_GetTestResult_Prepare( testSysContext );
    CheckPassed( rval );

    // Test for other NULL params
    rval = Tss2_Sys_Create_Prepare( testSysContext, 0xffffffff, 0, 0, 0, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );
    
    TeardownSysContext( &testSysContext );
}

void  RmZeroSizedResponseTest()
{
    SESSION *encryptSession;
    TPM2B_NONCE nonceCaller;
    TPMT_SYM_DEF symmetric;
	TSS2_RC rval = TSS2_RC_SUCCESS;

    //
    // Tests what happens in RM when receive comes back with 0 sized response.
    // This happens when a command is sent to the simulator but the simulator
    // isn't "powered on".
    // Added this test because this took me a while to understand, and I
    // never want to have to debug this again.
    //
    
    TpmClientPrintf( 0, "\nRM ZERO SIZED RESPONSE TEST:\n" );

    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );

    nonceCaller.t.size = 1;
    nonceCaller.t.buffer[0] = 0xa5;
    
    // AES encryption/decryption and CFB mode.
    symmetric.algorithm = TPM_ALG_AES;
    symmetric.keyBits.aes = 128;
    symmetric.mode.aes = TPM_ALG_CFB;

    // Start policy session for encrypt session.
    rval = StartAuthSessionWithParams( &encryptSession,
            TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, 0, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckFailed( rval, TSS2_TCTI_RC_IO_ERROR );
}


void CmdRspAuthsTests()
{
    SESSION *encryptSession, *decryptSession, *auditSession;
    TPM2B_NONCE nonceCaller, nonceTpm;
    TPMT_SYM_DEF symmetric;
	TSS2_RC rval = TSS2_RC_SUCCESS;
    int i;
    TPM2B_ENCRYPTED_SECRET	encryptedSalt; 
	UINT32 savedMaxCommandSize, savedResponseSize;

    TSS2_SYS_CONTEXT *otherSysContext;
    TPM_HANDLE testSessionHandle;

    TPMS_AUTH_COMMAND encryptCmdAuth, decryptCmdAuth, auditCmdAuth;
    TPMS_AUTH_COMMAND *cmdAuthArray[3] = { &encryptCmdAuth, &decryptCmdAuth, &auditCmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuths = { 3, &cmdAuthArray[0] };

    TPMS_AUTH_RESPONSE encryptRspAuth, decryptRspAuth, auditRspAuth;
    TPMS_AUTH_RESPONSE *rspAuthArray[3] =
            { &encryptRspAuth, &decryptRspAuth, &auditRspAuth };
    TSS2_SYS_RSP_AUTHS rspAuths = { 3, &rspAuthArray[0] };
    
    TpmClientPrintf( 0, "\nSETCMDAUTHS TESTS:\n" );

    nonceCaller.t.size = SHA256_DIGEST_SIZE;

    for( i = 0; i < nonceCaller.t.size; i++ )
    {
        nonceCaller.t.buffer[i] = 0xa5;
    }
    
    // AES encryption/decryption and CFB mode.
    symmetric.algorithm = TPM_ALG_AES;
    symmetric.keyBits.aes = 128;
    symmetric.mode.aes = TPM_ALG_CFB;

    // Start encrypt session.
    rval = StartAuthSessionWithParams( &encryptSession,
            TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, 0, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval ); // #1

    // Start decrypt session.
    rval = StartAuthSessionWithParams( &decryptSession,
            TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, 0, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval );  // #2

    // Start audit session.
    rval = StartAuthSessionWithParams( &auditSession,
            TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, 0, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval ); // #3

    encryptCmdAuth.sessionHandle = encryptSession->sessionHandle;
    encryptCmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&encryptCmdAuth.sessionAttributes ) ) = 0;
    encryptCmdAuth.sessionAttributes.encrypt = 1;
    encryptCmdAuth.hmac.t.size = 0;

    decryptCmdAuth.sessionHandle = decryptSession->sessionHandle;
    decryptCmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&decryptCmdAuth.sessionAttributes ) ) = 0;
    decryptCmdAuth.sessionAttributes.decrypt = 1;
    decryptCmdAuth.hmac.t.size = 0;

    auditCmdAuth.sessionHandle = auditSession->sessionHandle;
    auditCmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&auditCmdAuth.sessionAttributes ) ) = 0;
    auditCmdAuth.sessionAttributes.audit = 1;
    auditCmdAuth.hmac.t.size = 0;

    // Test for bad sequence.
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #4

    encryptedSalt.t.size = 0;
    rval = Tss2_Sys_StartAuthSession_Prepare( sysContext,
            TPM_RH_NULL, TPM_RH_NULL, &nonceCaller, &encryptedSalt, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval ); // #5

    // Test for bad reference.
    rval = Tss2_Sys_SetCmdAuths( 0, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #6

    rval = Tss2_Sys_SetCmdAuths( sysContext, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #7

    // Test for count == 0; this should pass.
    cmdAuths.cmdAuthsCount= 0;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckPassed( rval ); // #8

    // Test for bad value.
    cmdAuths.cmdAuthsCount= 3;
    cmdAuthArray[0] = 0;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE ); // #9

    cmdAuthArray[0] = &encryptCmdAuth;
    cmdAuthArray[1] = 0;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE ); // #10

    cmdAuthArray[1] = &decryptCmdAuth;
    cmdAuthArray[2] = 0;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE ); // #11
    cmdAuthArray[2] = &auditCmdAuth;
    
    // Test for insufficient context.
    cmdAuths.cmdAuthsCount= 0;
    savedMaxCommandSize = ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize;
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = sizeof( TPM20_Header_In ) + 3 * sizeof( TPM_HANDLE ) - 1;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckPassed( rval ); // #12
    
    cmdAuths.cmdAuthsCount= 0;
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = sizeof( TPM20_Header_In ) + 3 * sizeof( TPM_HANDLE );
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckPassed( rval );// #13
    
    cmdAuths.cmdAuthsCount= 3;
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = sizeof( TPM20_Header_In ) + 3 * sizeof( TPM_HANDLE );
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT ); // #14

    // Do successful one; use this to get size of command.
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = savedMaxCommandSize;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckPassed( rval ); // #15

    // Then set maxCommandSize to the the previously gotten commandSize - 1.  This should fail.
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = GetCommandSize( sysContext ) - 1;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckFailed( rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT ); // #16
    
    // Reset size of sysContext.
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = savedMaxCommandSize;

    // Setup for response auths test.
    ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->maxCommandSize = CHANGE_ENDIAN_DWORD( savedMaxCommandSize );
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckPassed( rval ); // #15

	TpmClientPrintf( 0, "\nGETRSPAUTHS TESTS:\n" );

    // Test for bad sequence.
    rval = Tss2_Sys_GetRspAuths( sysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #1

    otherSysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    if( otherSysContext == 0 )
    {
        InitSysContextFailure();
    }

    //
    // Test for command that failed:  invalid handle.
    //
    rval = Tss2_Sys_StartAuthSession_Prepare( otherSysContext,
            0xffffffff, TPM_RH_NULL, &nonceCaller, &encryptedSalt, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval ); // #2

    rval = Tss2_Sys_Execute( otherSysContext );
    CheckFailed( rval, TPM_RC_VALUE | TPM_RC_1 | TPM_RC_H ); // #3

    rval = Tss2_Sys_GetRspAuths( otherSysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #4

    //
    // Test for command that can never take sessions.
    //
    rval = Tss2_Sys_ReadClock_Prepare( otherSysContext );
    CheckPassed( rval ); // #5

    rval = Tss2_Sys_Execute( otherSysContext );
    CheckPassed( rval ); // #6

    rval = Tss2_Sys_GetRspAuths( otherSysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #7

    // Setup for testing for bad references and other conditions.
    rval = Tss2_Sys_StartAuthSession_Prepare( sysContext,
            TPM_RH_NULL, TPM_RH_NULL, &nonceCaller, &encryptedSalt, TPM_SE_HMAC,
            &symmetric, TPM_ALG_SHA256 );
    CheckPassed( rval ); // #8

    cmdAuths.cmdAuthsCount = 2;
    rval = Tss2_Sys_SetCmdAuths( sysContext, &cmdAuths );
    CheckPassed( rval ); // #9
	
	rval = Tss2_Sys_Execute( sysContext );
    CheckPassed( rval ); // #10

    // Test for bad reference.
    rval = Tss2_Sys_GetRspAuths( 0, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #11

    rval = Tss2_Sys_GetRspAuths( sysContext, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); // #12

    // Test for bad count.
    rspAuths.rspAuthsCount = 0;
    rval = Tss2_Sys_GetRspAuths( sysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE ); // #13

    // Test for non-matching count: specified count doesn't
    // match returned count.
    rspAuths.rspAuthsCount = 1;
    rval = Tss2_Sys_GetRspAuths( sysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_INVALID_SESSIONS ); // #14

    // Test for non-matching count: cmd auth count doesn't
    // match returned auth count.
    rspAuths.rspAuthsCount = 3;
    savedResponseSize = CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->tpmOutBuffPtr ) )->responseSize );
    ( (TPM20_Header_Out *)( ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->tpmOutBuffPtr ) )->responseSize = CHANGE_ENDIAN_DWORD( savedResponseSize - 5 );
    rval = Tss2_Sys_GetRspAuths( sysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_INVALID_SESSIONS ); // #15

    // Test for malformed response.
    rspAuths.rspAuthsCount = 2;
    ( (TPM20_Header_Out *)( ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->tpmOutBuffPtr ) )->responseSize = CHANGE_ENDIAN_DWORD( savedResponseSize - 7 );
    rval = Tss2_Sys_GetRspAuths( sysContext, &rspAuths );
    CheckFailed( rval, TSS2_SYS_RC_MALFORMED_RESPONSE ); // #16
        
    // Ths one should pass.
    ( (TPM20_Header_Out *)( ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->tpmOutBuffPtr ) )->responseSize = CHANGE_ENDIAN_DWORD( savedResponseSize );
    rval = Tss2_Sys_GetRspAuths( sysContext, &rspAuths );
    CheckPassed( rval ); // #17

    // Check for bad sequence.
    rval = Tss2_Sys_StartAuthSession_Complete( sysContext,
            &testSessionHandle, &nonceTpm );
    CheckPassed( rval ); // #17

    // Others?
    
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
    const uint8_t 		*cpBuffer;
    
    TpmClientPrintf( 0, "\nGET/SET ENCRYPT PARAM TESTS:\n" );

    // Do Prepare.
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 ); 
    CheckPassed( rval ); // #1

    // Test for bad sequence
    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #2
    
    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, &( nvWriteData.t.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); // #3

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

    // Size too large...should pass, but doesn't.
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckPassed( rval ); // #21

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
            TpmClientPrintf( 0, "ERROR!! encryptParamBuffer[%d] s/b: %2.2x, was: %2.2x\n", i, encryptParamBuffer[i], encryptParamBuffer1[i] );
            Cleanup();
        }
    }
    
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
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

    TpmClientPrintf( 0, "\nRM TESTS:\n" );
    
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
        TpmClientPrintf( 0, "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", otherResMgrInterfaceName, rval );
        Cleanup();
        return;
    }
    else
    {
        (( TSS2_TCTI_CONTEXT_INTEL *)otherResMgrTctiContext )->status.debugMsgLevel = debugLevel;
    }
    
    otherSysContext = InitSysContext( 0, otherResMgrTctiContext, &abiVersion );
    if( otherSysContext == 0 )
    {
        InitSysContextFailure();
    }

    // TEST WITH AN INVALID COMMAND CODE.
    
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM_SU_CLEAR );
    CheckPassed(rval);

    //
    // Alter the CC by altering the CC field in sysContext.
    //
    // WARNING:  This is something only a test application should do. Do
    // not use this as sample code.
    //
    ((TPM20_Header_In *)( ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )->tpmInBuffPtr) )->commandCode = TPM_CC_FIRST - 1;
    rval = Tss2_Sys_Execute( sysContext );
    CheckFailed( rval, TPM_RC_COMMAND_CODE );

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

    TpmClientPrintf( 0, "\nEC Ephemeral TESTS:\n" );

    // Test SAPI for case of Q size field not being set to 0.
    Q.t.size = 0xff;
    rval = Tss2_Sys_EC_Ephemeral( sysContext, 0, TPM_ECC_BN_P256, &Q, &counter, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    Q.t.size = 0;
    rval = Tss2_Sys_EC_Ephemeral( sysContext, 0, TPM_ECC_BN_P256, &Q, &counter, 0 );
    CheckPassed( rval );
}
    

void AbiVersionTests()
{
    UINT32 contextSize = 1000;
    TSS2_RC rval;
    TSS2_SYS_CONTEXT *sysContext;
    TSS2_ABI_VERSION tstAbiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

    TpmClientPrintf( 0, "\nABI NEGOTIATION TESTS:\n" );

    // Get the size needed for system context structure.
    contextSize = Tss2_Sys_GetContextSize( contextSize );

    // Allocate the space for the system context structure.
    sysContext = (TSS2_SYS_CONTEXT *)malloc( contextSize );

    if( sysContext != 0 )
    {
        // Initialized the system context structure.
        tstAbiVersion.tssCreator = 0xF0000000;
        rval = Tss2_Sys_Initialize( sysContext, contextSize, resMgrTctiContext, &tstAbiVersion );
        CheckFailed( rval, TSS2_SYS_RC_ABI_MISMATCH );
        
        tstAbiVersion.tssCreator = TSSWG_INTEROP;
        tstAbiVersion.tssFamily = 0xF0000000;
        rval = Tss2_Sys_Initialize( sysContext, contextSize, resMgrTctiContext, &tstAbiVersion );
        CheckFailed( rval, TSS2_SYS_RC_ABI_MISMATCH );        

        tstAbiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
        tstAbiVersion.tssLevel = 0xF0000000;
        rval = Tss2_Sys_Initialize( sysContext, contextSize, resMgrTctiContext, &tstAbiVersion );
        CheckFailed( rval, TSS2_SYS_RC_ABI_MISMATCH );        
        
        tstAbiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
        tstAbiVersion.tssVersion = 0xF0000000;
        rval = Tss2_Sys_Initialize( sysContext, contextSize, resMgrTctiContext, &tstAbiVersion );
        CheckFailed( rval, TSS2_SYS_RC_ABI_MISMATCH );
    }
    free( sysContext );
}


#ifdef __cplusplus
extern "C" {
#endif

extern int dummy_test();

#ifdef __cplusplus
}
#endif

extern TSS2_RC SocketSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    size_t             command_size,      /* in */
    uint8_t           *command_buffer     /* in */
    );

TSS2_RC SocketReceiveTpmResponse(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    size_t          *response_size,     /* out */
    unsigned char   *response_buffer,    /* in */
    int32_t         timeout
    );

void TestCreate1()
{
    UINT32 rval;
    TPM2B_SENSITIVE_CREATE  inSensitive = { { sizeof( TPM2B_SENSITIVE_CREATE ) - 2, } };
    TPM2B_PUBLIC            inPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };
    TPM2B_DATA              outsideInfo = { { sizeof( TPM2B_DATA ) - 2, } };
    TPML_PCR_SELECTION      creationPCR;

    TPMS_AUTH_COMMAND sessionData = { TPM_RS_PW, };
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = { &sessionDataOut };
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { 1, &sessionDataOutArray[0] };

    TPM2B_NAME name = { { sizeof( TPM2B_NAME ) - 2, } };
    TPM2B_PUBLIC outPublic = { { sizeof( TPM2B_PUBLIC ) - 2, } };
    TPM2B_CREATION_DATA creationData =  { { sizeof( TPM2B_CREATION_DATA ) - 2, } };
    TPM2B_DIGEST creationHash = { { sizeof( TPM2B_DIGEST ) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, 0, { { sizeof( TPM2B_DIGEST ) - 2, } } };

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
        
    printf( "\nCREATE PRIMARY, encrypt and decrypt TESTS:\n" );

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
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_OWNER, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckFailed( rval, TSS2_SYS_RC_BAD_VALUE );

    outPublic.t.size = 0;
    creationData.t.size = 0;
    outPublic.t.publicArea.authPolicy.t.size = sizeof( TPM2B_DIGEST ) - 2;
    outPublic.t.publicArea.unique.keyedHash.t.size = sizeof( TPM2B_DIGEST ) - 2;
    rval = Tss2_Sys_CreatePrimary( sysContext, TPM_RH_OWNER, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &handle2048rsa, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut );
    CheckPassed( rval );

    printf( "\nNew key successfully created in owner hierarchy (RSA 2048).  Handle: 0x%8.8x\n",
            handle2048rsa );
    printf( "Name of created primary key: " );
    PrintSizedBuffer( (TPM2B *)&name );
  
    char buffer1contents[] = "test";
    //char buffer2contents[] = "string";

    TPMI_DH_OBJECT keyHandle = handle2048rsa;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_PUBLIC_KEY_RSA message;
    TPM2B_PUBLIC_KEY_RSA outData;
    
    message.t.size = strlen(buffer1contents);
    memcpy(message.t.buffer, buffer1contents, message.t.size);

    inScheme.scheme = TPM_ALG_NULL;
    
    //printf("keyHandle: %x\n", keyHandle); 
    rval = Tss2_Sys_RSA_Encrypt(sysContext, keyHandle, &sessionsData, &message, &inScheme, &outsideInfo, &outData, &sessionsDataOut);
    if( tpmSpecVersion >= 124 )
        CheckFailed( rval, TPM_RC_S + TPM_RC_1 + TPM_RC_HANDLE );
    else
        CheckFailed( rval, TPM_RC_1 + TPM_RC_HANDLE );

    outData.t.size = sizeof( outData ) - 2;
    rval = Tss2_Sys_RSA_Encrypt(sysContext, keyHandle, 0, &message, &inScheme, &outsideInfo, &outData, &sessionsDataOut);
    CheckPassed( rval );
    
    for (int i=0; i<message.t.size; i++)
    	printf("\nlabel size:%d, label buffer:%x, outData size:%d, outData buffer:%x, msg size:%d, msg buffer:%x", outsideInfo.t.size, outsideInfo.t.buffer[i], outData.t.size, outData.t.buffer[i], message.t.size, message.t.buffer[i]);
    CheckPassed(rval);
}

#if __linux || __unix
//
// NOTE:  these tests must be run when no RM is running in the system and when a local TPM is installe.
//
void TestLocalTCTI()
{
    char deviceTctiConfig[DEVICE_TCTI_CONFIG_SIZE];
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    TSS2_TCTI_CONTEXT *downstreamTctiContext;

    TpmClientPrintf( NO_PREFIX,  "WARNING!!  This test requires that a local TPM is present and that the resource manager has NOT been started.\n\n" );
       
    // Test TCTI interface against local TPM TCTI interface, if available.
    //
    // Init downstream interface to tpm (in this case the local TPM).
    //
    sprintf_s( deviceTctiConfig, DEVICE_TCTI_CONFIG_SIZE, "%s ", "/dev/tpm0" );

    rval = InitDeviceTctiContext( deviceTctiConfig, &downstreamTctiContext );
    if( rval != TSS2_RC_SUCCESS )
    {
        TpmClientPrintf( NO_PREFIX,  "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", "local TPM", rval );
        CheckPassed( rval );
    }
    else
    {
        if( debugLevel == DBG_COMMAND )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
        }
        
        TestTctiApis( downstreamTctiContext, 0 );

        TeardownDeviceTctiContext( deviceTctiConfig, downstreamTctiContext );

        exit( 0 );
    }
    
}
#endif

void TpmTest()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT32 i;

    nullSessionsDataOut.rspAuthsCount = 1;
    nullSessionsDataOut.rspAuths[0]->nonce = nullSessionNonceOut;
    nullSessionsDataOut.rspAuths[0]->hmac = nullSessionHmac;
    nullSessionNonceOut.t.size = 0;
    nullSessionNonce.t.size = 0;
            
    loadedSha1KeyAuth.t.size = 2;
    loadedSha1KeyAuth.t.buffer[0] = 0x00;
    loadedSha1KeyAuth.t.buffer[1] = 0xff;

    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );

    InitEntities();
    
    InitNullSession( &nullSessionData);

    AbiVersionTests();

    SysInitializeTests();

    SysFinalizeTests();

    GetContextSizeTests();

    GetTctiContextTests();
    
    GetSetDecryptParamTests();

#ifdef _WIN32
    // This test can only be run agains the simulator
    RmZeroSizedResponseTest();    
#endif
    
    rval = PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );

    rval = PlatformCommand( resMgrTctiContext, MS_SIM_NV_ON );
    CheckPassed( rval );
    TestTpmStartup();

    // Run this directly after Startup tests to test for
    // a resource mgr corner case with SaveContext.
    TestStartAuthSession();

    GetTpmVersion();

    GetTpmManufacturer();

    TestTctiApis( resMgrTctiContext, 1 );

    CmdRspAuthsTests();
	    
    PrepareTests();

    // Clear DA lockout.
    TestDictionaryAttackLockReset();

    TestTpmSelftest();

    TestDictionaryAttackLockReset();
    
    TestCreate();

    TestCreate1();

    TestSapiApis();

    TestHierarchyControl();

    NvIndexProto();
        
    GetSetEncryptParamTests();

    TestEncryptDecryptSession();

    SimpleHmacOrPolicyTest( true );

    SimpleHmacOrPolicyTest( false );
   
    for( i = 1; i <= (UINT32)passCount; i++ )
    {
        TpmClientPrintf( 0, "\n****** PASS #: %d ******\n\n", i );
        
        TestTpmGetCapability();

        TestPcrExtend();

        TestHash();

        TestPolicy();

        TestTpmClear();

        TestChangeEps();

        TestChangePps();

        TestHierarchyChangeAuth();

        TestGetRandom();

        if( i < 2 )
            TestShutdown();

        TestNV();

        TestCreate();

        TestEvict();
        
        NvIndexProto();

        PasswordTest();

        HmacSessionTest();

        TestQuote();

        TestDictionaryAttackLockReset();

        TestPcrAllocate();

        TestUnseal();

        TestRM();
        
        EcEphemeralTest();
#if 0
        TestRsaEncryptDecrypt();
#endif
    }

    // Clear out RM entries for objects.
    rval = Tss2_Sys_FlushContext( sysContext, handle2048rsa );
    CheckPassed( rval );
    rval = Tss2_Sys_FlushContext( sysContext, loadedSha1KeyHandle );
    CheckPassed( rval );
    
endTests:    
    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
}


char version[] = "0.90";

void PrintHelp()
{
    printf( "TPM client test app, Version %s\nUsage:  tpmclient [-rmhost hostname|ip_addr] [-rmport port] [-passes passNum] [-demoDelay delay] [-dbg dbgLevel] [-startAuthSessionTest] "
#if __linux || __unix
            "[-localTctiTest]"
#endif            
            "\n\n"
            "where:\n"
            "\n"
            "-rmhost specifies the host IP address for the system running the resource manager (default: %s)\n"
            "-rmport specifies the port number for the system running the resource manager (default: %d)\n"
            "-passes specifies the number of test passes (default: 1)\n"
            "-demoDelay specifies a delay in units of loops, not time (default:  0)\n"
            "-dbg specifies level of debug messages:\n"
            "   0 (high level test results)\n"
            "   1 (test app send/receive byte streams)\n"
            "   2 (resource manager send/receive byte streams)\n"
            "   3 (resource manager tables)\n"
            "-startAuthSessionTest enables some special tests of the resource manager for starting sessions\n"
#if __linux || __unix
            "-localTctiTest enables a TCTI interface test against a local TPM.  WARNING:  This test requires no resource manager and a local TPM\n"
#endif            
#ifdef SHARED_OUT_FILE
            "-out selects the output file (default is stdout)\n"
#endif            
            , version, DEFAULT_HOSTNAME, DEFAULT_RESMGR_TPM_PORT );
}

int main(int argc, char* argv[])
{
    int count;
    TSS2_RC rval;
    
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);
#ifdef SHARED_OUT_FILE
    if( argc > 12 )
#else        
    if( argc > 10 )
#endif        
    {
        PrintHelp();
        return 1;
    }
    else
    {
        for( count = 1; count < argc; count++ )
        {
           if( 0 == strcmp( argv[count], "-rmhost" ) )
            {
                count++;
                if( count >= argc)
                {
                    PrintHelp();
                    return 1;
                }
                rmInterfaceConfig.hostname = argv[count];
            }
            else if( 0 == strcmp( argv[count], "-rmport" ) )
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
                if( count >= argc || 1 != sscanf_s( argv[count], "%x", &passCount ) )
                {
                    PrintHelp();
                    return 1;
                }
            }
            else if( 0 == strcmp( argv[count], "-demoDelay" ) )
            {
                count++;
                if( count >= argc || 1 != sscanf_s( argv[count], "%x", &demoDelay ) )
                {
                    PrintHelp();
                    return 1;
                }
            }            
            else if( 0 == strcmp( argv[count], "-dbg" ) )
            {
                count++;
                if( count >= argc || 1 != sscanf_s( argv[count], "%d", &debugLevel ) )
                {
                    PrintHelp();
                    return 1;
                }
            }            
#if __linux || __unix
            else if( 0 == strcmp( argv[count], "-localTctiTest" ) )
            {
                testLocalTcti = 1;
            }
#endif
            
#ifdef SHARED_OUT_FILE
            else if( 0 == strcmp( argv[count], "-out" ) )
            {
                count++;
                if( count >= argc || 1 != sscanf_s( argv[count], "%199s", &outFileName, sizeof( outFileName ) ) )
                {
                    PrintHelp();
                    return 1;
                }
                else
                {
                    OpenOutFile( &outFp );

                    if( outFp == 0 )
                    {
                        printf( "Unable to open file, %s\n", &outFileName[0] );
                        PrintHelp();
                        return 1;
                    }
                    CloseOutFile( &outFp );
                }
            }            
#endif
            else
            {
                PrintHelp();
                return 1;
            }
        }
    }

    if( 0 == strcmp( outFileName, "" ) )
    {
        outFp = stdout;
    }
	else
	{
		outFp = 0;
	}

#if __linux || __unix
    if( testLocalTcti )
    {
        TestLocalTCTI();
    }
#endif
    
    rval = InitTctiResMgrContext( &rmInterfaceConfig, &resMgrTctiContext, &resMgrInterfaceName[0] );
    if( rval != TSS2_RC_SUCCESS )
    {
        TpmClientPrintf( 0, "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resMgrInterfaceName, rval );
#ifdef _WIN32        
        WSACleanup();
#endif
        if( resMgrTctiContext != 0 )
            free( resMgrTctiContext );
        
        return( 1 );
    }
    else
    {
        (( TSS2_TCTI_CONTEXT_INTEL *)resMgrTctiContext )->status.debugMsgLevel = debugLevel;
        resMgrInitialized = 1;
    }
    
    sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        InitSysContextFailure();
    }
    else
    {
        TpmTest();

        rval = TeardownTctiResMgrContext( resMgrTctiContext );
        CheckPassed( rval );
        
        TeardownSysContext( &sysContext );
    }

    return 0;
}


