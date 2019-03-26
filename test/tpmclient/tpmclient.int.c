/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************;
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 ***********************************************************************;
 */

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_sys.h"
#include "tss2_tcti_device.h"
#include "tss2_tcti_mssim.h"

#include "../integration/context-util.h"
#include "../integration/sapi-util.h"
#include "../integration/session-util.h"
#include "util/tss2_endian.h"
#include "sysapi_util.h"
#define LOGMODULE testtpmclient
#include "util/log.h"

/*
 * TPM indices and sizes
 */
#define NV_AUX_INDEX_SIZE     96
#define NV_PS_INDEX_SIZE      34

#define INDEX_AUX                       0x01800003 /* NV Storage */
#define INDEX_LCP_OWN                   0x01400001 /* Launch Policy Owner */
#define INDEX_LCP_SUP                   0x01800001 /* Launch Policy Default (Supplier) */
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


TSS2_SYS_CONTEXT *sysContext;

TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;

#define INIT_SIMPLE_TPM2B_SIZE(type) (type).size = sizeof(type) - 2;
#define YES 1
#define NO 0

static void ErrorHandler(UINT32 rval, char *errorString, int errorStringSize)
{
    UINT32 errorLevel = rval & TSS2_RC_LAYER_MASK;
    char levelString[32];

    switch (errorLevel)
    {
        case TSS2_TPM_RC_LAYER:
            strcpy(levelString, "TPM");
            break;
        case TSS2_SYS_RC_LAYER:
            strcpy(levelString, "System API");
            break;
        case TSS2_MU_RC_LAYER:
            strcpy(levelString, "System API TPM encoded");
            break;
        case TSS2_TCTI_RC_LAYER:
            strcpy(levelString, "TCTI");
            break;
        case TSS2_RESMGR_TPM_RC_LAYER:
            strcpy(levelString, "Resource Mgr TPM encoded");
            break;
        case TSS2_RESMGR_RC_LAYER:
            strcpy(levelString, "Resource Mgr");
            break;
        default:
            strcpy(levelString, "Unknown Level");
            break;
    }

    snprintf(errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval);
}

static void Cleanup()
{
    if (resMgrTctiContext != NULL) {
        tcti_platform_command(resMgrTctiContext, MS_SIM_POWER_OFF);
        tcti_teardown(resMgrTctiContext);
        resMgrTctiContext = NULL;
    }

    exit(1);
}

static void InitSysContextFailure()
{
    LOG_ERROR("InitSysContext failed, exiting...");
    Cleanup();
}

#define ERROR_STR_LEN 200
#define CheckPassed(rval) {             \
    char error_string[ERROR_STR_LEN];         \
    if ((rval) != TPM2_RC_SUCCESS) {      \
      ErrorHandler((rval), error_string, ERROR_STR_LEN); \
      LOG_INFO("passing case: \tFAILED!  %s (%s@%u)",  \
               error_string, __FUNCTION__, __LINE__ ); \
      Cleanup(); \
    } else {     \
      LOG_INFO("passing case: \tPASSED! (%s@%u)", \
               __FUNCTION__, __LINE__); \
    } \
  }

#define CheckFailed(rval, expected_rval) { \
    char error_string[ERROR_STR_LEN];             \
    if ((rval) != (expected_rval)) {    \
      ErrorHandler((rval), error_string, ERROR_STR_LEN); \
      LOG_INFO("\tfailing case: FAILED! %s  Ret code s/b: 0x%x, but was: 0x%x (%s@%u)", \
               error_string, (expected_rval), (rval), __FUNCTION__, __LINE__ ); \
      Cleanup(); \
    } else { \
      LOG_INFO("\tfailing case: PASSED! (%s@%u)", \
           __FUNCTION__, __LINE__); \
    } \
  }

static TSS2_RC TpmReset()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = (TSS2_RC)tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_OFF );
    if( rval == TSS2_RC_SUCCESS )
    {
        rval = (TSS2_RC)tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_ON );
    }
    return rval;
}

static void TestDictionaryAttackLockReset()
{
    UINT32 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    LOG_INFO("DICTIONARY ATTACK LOCK RESET TEST  :" );

    rval = Tss2_Sys_DictionaryAttackLockReset ( sysContext, TPM2_RH_LOCKOUT, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );
}

static TSS2_RC StartPolicySession( TPMI_SH_AUTH_SESSION *sessionHandle )
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

    /* Create policy session */
    INIT_SIMPLE_TPM2B_SIZE( nonceTpm );
    rval = Tss2_Sys_StartAuthSession ( sysContext, TPM2_RH_NULL, TPM2_RH_NULL, 0, &nonceCaller, &salt,
            TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA1, sessionHandle, &nonceTpm, 0 );
    return( rval );
}

static void TestTpmStartup()
{
    UINT32 rval;

    LOG_INFO("STARTUP TESTS:" );

    /*
     * First test the one-call interface.
     */

    /* First must do TPM reset. */
    rval = TpmReset();
    CheckPassed(rval);

    /* This one should pass. */
    rval = Tss2_Sys_Startup( sysContext, TPM2_SU_CLEAR );
    CheckPassed(rval);

    /* This one should fail. */
    rval = Tss2_Sys_Startup( sysContext, TPM2_SU_CLEAR );
    CheckFailed( rval, TPM2_RC_INITIALIZE );


    /* Cycle power using simulator interface. */
    rval = tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );
    rval = tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );


    /*
     * Now test the synchronous, non-one-call interface.
     */
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM2_SU_CLEAR );
    CheckPassed(rval);

    /* Execute the command synchronously. */
    rval = Tss2_Sys_Execute( sysContext );
    CheckPassed( rval );

    /* Cycle power using simulator interface. */
    rval = tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed( rval );
    rval = tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed( rval );


    /*
     * Now test the asynchronous, non-one-call interface.
     */
    rval = Tss2_Sys_Startup_Prepare( sysContext, TPM2_SU_CLEAR );
    CheckPassed(rval);

    /* Execute the command asynchronously. */
    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed(rval);

    /*
     * Get the command response. Wait a maximum of 20ms
     * for response.
     */
    rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed(rval);
}

static void TestTpmGetCapability()
{
    UINT32 rval;

    char manuID[5] = "    ";
    char *manuIDPtr = &manuID[0];
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    LOG_INFO("GET_CAPABILITY TESTS:" );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );

    *((UINT32 *)manuIDPtr) = BE_TO_HOST_32(capabilityData.data.tpmProperties.tpmProperty[0].value);
    LOG_INFO("\t\tcount: %d, property: %x, manuId: %s",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            manuID );

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MAX_COMMAND_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    LOG_INFO("\t\tcount: %d, property: %x, max cmd size: %d",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );


    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MAX_COMMAND_SIZE, 40, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    LOG_INFO("\t\tcount: %d, property: %x, max cmd size: %d",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );


    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MAX_RESPONSE_SIZE, 1, &moreData, &capabilityData, 0 );
    CheckPassed( rval );
    LOG_INFO("\t count: %d, property: %x, max response size: %d",
            capabilityData.data.tpmProperties.count,
            capabilityData.data.tpmProperties.tpmProperty[0].property,
            capabilityData.data.tpmProperties.tpmProperty[0].value );

    rval = Tss2_Sys_GetCapability( sysContext, 0, 0xff, TPM2_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0 );
    CheckFailed(rval, TPM2_RC_VALUE+TPM2_RC_1+TPM2_RC_P);
}

static void TestTpmClear()
{
    UINT32 rval;
    TPM2B_AUTH      hmac = { .size = 0 };
    TPM2B_NONCE     nonce = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TSS2L_SYS_AUTH_COMMAND sessionsDataIn = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce=nonce,
        .hmac=hmac}}};

    LOG_INFO("CLEAR and CLEAR CONTROL TESTS:" );

    rval = Tss2_Sys_Clear ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, YES, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Clear ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, 0 );
    CheckFailed( rval, TPM2_RC_DISABLED );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckPassed( rval );

    sessionsDataIn.auths[0].sessionAttributes = 0xff;
    rval = Tss2_Sys_Clear ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_9 + TPM2_RC_RESERVED_BITS );

    rval = Tss2_Sys_ClearControl ( sysContext, TPM2_RH_PLATFORM, &sessionsDataIn, NO, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_9 + TPM2_RC_RESERVED_BITS );
}

#define SESSIONS_ABOVE_MAX_ACTIVE 0
#define DEBUG_MAX_ACTIVE_SESSIONS   8
#define DEBUG_GAP_MAX   2*DEBUG_MAX_ACTIVE_SESSIONS

SESSION *sessions[SESSIONS_COUNT];

static void TestStartAuthSession()
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


    /* Init sessionHandle */
    sessionData.sessionHandle = badSessionHandle;

    /* Init nonce. */
    nonce.size = 0;
    sessionData.nonce = nonce;

    /* init hmac */
    hmac.size = 0;
    sessionData.hmac = hmac;

    /* Init session attributes */
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    encryptedSalt.size = 0;

    LOG_INFO("START_AUTH_SESSION TESTS:" );

    symmetric.algorithm = TPM2_ALG_NULL;
    symmetric.keyBits.sym = 0;
    symmetric.mode.sym = 0;

    nonceCaller.size = 0;

    encryptedSalt.size = 0;

     /* Init session */
    rval = create_auth_session(&authSession, TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext( sysContext, authSession->sessionHandle );
    CheckPassed( rval );
    end_auth_session( authSession );

    /* Init session */
    rval = create_auth_session(&authSession, TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, 0xff, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckFailed( rval, TPM2_RC_VALUE + TPM2_RC_P + TPM2_RC_3 );

    /*
     * Try starting a bunch to see if resource manager handles this correctly.
     */
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
    {
        /* Init session struct */
        rval = create_auth_session(&sessions[i], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );
        LOG_INFO("Number of sessions created: %d", i+1 );

    }
    /* clean up the sessions that I don't want here. */
    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *)); i++ )
    {
        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        end_auth_session(sessions[i]);
    }

    /* Now do some gap tests. */
    rval = create_auth_session(&sessions[0], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    for( i = 1; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
    {
        rval = create_auth_session(&sessions[i], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        end_auth_session(sessions[i]);
    }

    for( i = 0; i < ( sizeof(sessions) / sizeof (SESSION *) ); i++ )
    {
        rval = create_auth_session(&sessions[i], TPM2_RH_NULL, 0, TPM2_RH_PLATFORM, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_FlushContext( sysContext, sessions[i]->sessionHandle );
        CheckPassed( rval );

        end_auth_session(sessions[i]);
    }
}

static void TestChangeEps()
{
    UINT32 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    LOG_INFO("CHANGE_EPS TESTS:" );

    rval = Tss2_Sys_ChangeEPS( sysContext, TPM2_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );
}

static void TestChangePps()
{
    UINT32 rval;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    LOG_INFO("CHANGE_PPS TESTS:" );

    rval = Tss2_Sys_ChangePPS( sysContext, TPM2_RH_PLATFORM, &sessionsData, &sessionsDataOut );
    CheckPassed( rval );
}

static void TestHierarchyChangeAuth()
{
    UINT32 rval;
    TPM2B_AUTH      newAuth;
    int i;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    LOG_INFO("HIERARCHY_CHANGE_AUTH TESTS:" );

    newAuth.size = 0;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    /* Init new auth */
    newAuth.size = 20;
    for( i = 0; i < newAuth.size; i++ )
        newAuth.buffer[i] = i;

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    sessionsData.auths[0].hmac = newAuth;
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

    /* Init new auth */
    newAuth.size = 0;

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
    CheckPassed( rval );

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

static void TestPcrExtend()
{
    UINT32 rval;
    UINT16 i, digestSize;
    TPML_PCR_SELECTION  pcrSelection;
    UINT32 pcrUpdateCounterBeforeExtend;
    UINT32 pcrUpdateCounterAfterExtend;
    UINT8 pcrBeforeExtend[PCR_SIZE];
    TPM2B_EVENT eventData;
    TPML_DIGEST pcrValues;
    TPML_DIGEST_VALUES digests;
    TPML_PCR_SELECTION pcrSelectionOut;
    UINT8 pcrAfterExtend[20];

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    LOG_INFO("PCR_EXTEND, PCR_EVENT, PCR_ALLOCATE, and PCR_READ TESTS:" );

    /* Init digests */
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

    /* Clear out PCR select bit field */
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;

    /* Now set the PCR you want to read */
    SET_PCR_SELECT_BIT( pcrSelection.pcrSelections[0], PCR_17 );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterBeforeExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    if( pcrValues.digests[0].size <= PCR_SIZE &&
            pcrValues.digests[0].size <= sizeof( pcrValues.digests[0].buffer ) )
        memcpy( &( pcrBeforeExtend[0] ), &( pcrValues.digests[0].buffer[0] ), pcrValues.digests[0].size );

    rval = Tss2_Sys_PCR_Extend( sysContext, PCR_17, &sessionsData, &digests, 0  );
    CheckPassed( rval );

    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelection, &pcrUpdateCounterAfterExtend, &pcrSelectionOut, &pcrValues, 0 );
    CheckPassed( rval );

    memcpy( &( pcrAfterExtend[0] ), &( pcrValues.digests[0].buffer[0] ), pcrValues.digests[0].size );

    if( pcrUpdateCounterBeforeExtend == pcrUpdateCounterAfterExtend )
    {
        LOG_ERROR("ERROR!! pcrUpdateCounter didn't change value" );
        Cleanup();
    }

    if( 0 == memcmp( &( pcrBeforeExtend[0] ), &( pcrAfterExtend[0] ), 20 ) )
    {
        LOG_ERROR("ERROR!! PCR didn't change value" );
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

static void TestShutdown()
{
    UINT32 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    LOG_INFO("SHUTDOWN TESTS:" );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM2_SU_STATE, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, TPM2_SU_CLEAR, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_Shutdown( sysContext, 0, 0xff, 0 );
    CheckFailed( rval, TPM2_RC_VALUE+TPM2_RC_1+TPM2_RC_P );
}

static void TestNV()
{
    UINT32 rval;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    int i;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    TPM2B_MAX_NV_BUFFER nvData;

    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    LOG_INFO("NV INDEX TESTS:" );

    nvAuth.size = 20;
    for( i = 0; i < nvAuth.size; i++ ) {
        nvAuth.buffer[i] = (UINT8)i;
    }

    publicInfo.size = 0;
    publicInfo.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    /* First zero out attributes. */
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    /* Now set the attributes. */
    publicInfo.nvPublic.attributes |= TPMA_NV_PPREAD;
    publicInfo.nvPublic.attributes |= TPMA_NV_PPWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_WRITE_STCLEAR;
    publicInfo.nvPublic.attributes |= TPMA_NV_PLATFORMCREATE;
    publicInfo.nvPublic.attributes |= TPMA_NV_ORDERLY;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = 32;

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

    /* Should fail since index is already defined. */
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_NV_DEFINED );

    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

#if 1
    /*
     * The following, at one point, was commented out so that NVDefine will
     * work on successive invocations of client app.
     *
     * Noticed on 12/13/12, this doesn't seem to be necessary anymore.
     * Maybe something else fixed it.
     *
     * Seems to be a bug in TPM 2.0 simulator that if:
     *   First pass of tpmclient.exe after restarting TPM 2.0 simulator will
     *       work fine.
     *   If NVWrite is done, subsequent invocations of tpmclient.exe will
     *      ALWAYS fail on the first call to Tpm2NVDefineSpace with 0x2cb error.
     *      Removing NVWrite fixes this.
     *      And restarting TPM 2.0 simulator will make it work the first time
     *      and fail subsequent times.
     *      Removing NVWrite works around this problem.
     */
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

    /* Now undefine the index. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    /* Now undefine the index so that next run will work correctly. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );

    publicInfo.nvPublic.attributes &= ~TPMA_NV_PPREAD;
    publicInfo.nvPublic.attributes &= ~TPMA_NV_PPWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_OWNERREAD;
    publicInfo.nvPublic.attributes |= TPMA_NV_OWNERWRITE;
    publicInfo.nvPublic.attributes &= ~TPMA_NV_PLATFORMCREATE;
    publicInfo.nvPublic.attributes |= TPMA_NV_ORDERLY;
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

    /* Now undefine the index. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_OWNER, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    /* Now undefine the index so that next run will work correctly. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_OWNER, TPM20_INDEX_TEST2, &sessionsData, 0 );
    CheckPassed( rval );
}

static void TestHierarchyControl()
{
    UINT32 rval;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    int i;
    TPM2B_NAME nvName;
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_MAX_NV_BUFFER nvData;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    LOG_INFO("HIERARCHY CONTROL TESTS:" );

    nvAuth.size = 20;
    for( i = 0; i < nvAuth.size; i++ ) {
        nvAuth.buffer[i] = i;
    }

    publicInfo.size = 0;
    publicInfo.nvPublic.nvIndex = TPM20_INDEX_TEST1;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    /* First zero out attributes. */
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    /* Now set the attributes. */
    publicInfo.nvPublic.attributes |= TPMA_NV_PPREAD;
    publicInfo.nvPublic.attributes |= TPMA_NV_PPWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_PPWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_WRITE_STCLEAR;
    publicInfo.nvPublic.attributes |= TPMA_NV_PLATFORMCREATE;
    publicInfo.nvPublic.attributes |= TPMA_NV_ORDERLY;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = 32;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &sessionsData, &nvAuth, &publicInfo, 0 );
    CheckPassed( rval );

    /* Test SAPI for case where nvPublic.size != 0 */
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

    /* Need to do TPM reset and Startup to re-enable platform hierarchy. */
    rval = TpmReset();
    CheckPassed(rval);

    rval = Tss2_Sys_Startup ( sysContext, TPM2_SU_CLEAR );
    CheckPassed( rval );

    rval = Tss2_Sys_HierarchyControl( sysContext, TPM2_RH_PLATFORM, &sessionsData, TPM2_RH_PLATFORM, YES, &sessionsDataOut );
    CheckPassed( rval );

    /* Now undefine the index so that next run will work correctly. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_TEST1, &sessionsData, 0 );
    CheckPassed( rval );
}

static TSS2_RC DefineNvIndex( TPMI_RH_PROVISION authHandle, TPMI_SH_AUTH_SESSION sessionAuthHandle, TPM2B_AUTH *auth, TPM2B_DIGEST *authPolicy,
    TPMI_RH_NV_INDEX nvIndex, TPMI_ALG_HASH nameAlg, TPMA_NV attributes, UINT16 size  )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_NV_PUBLIC publicInfo;

    /* Command and response session data structures. */
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    attributes |= TPMA_NV_ORDERLY;

    /* Init public info structure. */
    publicInfo.size = 0;
    publicInfo.nvPublic.attributes = attributes;
    CopySizedByteBuffer((TPM2B *)&publicInfo.nvPublic.authPolicy, (TPM2B *)authPolicy);
    publicInfo.nvPublic.dataSize = size;
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = nameAlg;

    /* Create the index */
    rval = Tss2_Sys_NV_DefineSpace( sysContext, authHandle, &sessionsData, auth, &publicInfo, &sessionsDataOut );

    return rval;
}

typedef struct {
    char name[50];
    TSS2_RC (*buildPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *trialPolicySession, TPM2B_DIGEST *policyDigest );
    TSS2_RC (*createObjectFn )( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest );
    TSS2_RC (*testPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession );
} POLICY_TEST_SETUP;

static TSS2_RC BuildPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession,
    TSS2_RC (*buildPolicyFn )( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest ),
    TPM2B_DIGEST *policyDigest, bool trialSession )
{
    /*
     * NOTE:  this policySession will be either a trial or normal policy session
     * depending on the value of the passed in trialSession parameter.
     */
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = {0,};
    TPMT_SYM_DEF symmetric;
    TSS2_RC rval;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    /* Start policy session. */
    symmetric.algorithm = TPM2_ALG_NULL;
    rval = create_auth_session(policySession, TPM2_RH_NULL, 0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, trialSession ? TPM2_SE_TRIAL : TPM2_SE_POLICY , &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    if( rval != TPM2_RC_SUCCESS )
        return rval;

    /* Send policy command. */
    rval = ( *buildPolicyFn )( sysContext, *policySession, policyDigest );
    CheckPassed( rval );

    /* Get policy hash. */
    INIT_SIMPLE_TPM2B_SIZE( *policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, (*policySession)->sessionHandle,
            0, policyDigest, 0 );
    CheckPassed( rval );

    if( trialSession )
    {
        /* Need to flush the session here. */
        rval = Tss2_Sys_FlushContext( sysContext, (*policySession)->sessionHandle );
        CheckPassed( rval );

        /* And remove the session from sessions table. */
        end_auth_session( *policySession );
    }

    return rval;
}

static TSS2_RC CreateNVIndex( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPMA_LOCALITY locality;
    TPM2B_ENCRYPTED_SECRET encryptedSalt = {0};
    TPMT_SYM_DEF symmetric;
    TPMA_NV nvAttributes;
    TPM2B_AUTH  nvAuth;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    /*
     * Since locality is a fairly simple command and we can guarantee
     * its correctness, we don't need a trial session for this.
     */

    /* Start real policy session */
    symmetric.algorithm = TPM2_ALG_NULL;
    rval = create_auth_session(policySession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY,
            &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    /* Send PolicyLocality command */
    *(UINT8 *)( (void *)&locality ) = 0;
    locality |= TPMA_LOCALITY_TPM2_LOC_THREE;
    rval = Tss2_Sys_PolicyLocality( sysContext, (*policySession)->sessionHandle,
            0, locality, 0 );
    CheckPassed( rval );

    /* Read policyHash */
    INIT_SIMPLE_TPM2B_SIZE( *policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext,
            (*policySession)->sessionHandle, 0, policyDigest, 0 );
    CheckPassed( rval );

    nvAuth.size = 0;

    /* Now set the attributes. */
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes |= TPMA_NV_POLICYREAD;
    nvAttributes |= TPMA_NV_POLICYWRITE;
    nvAttributes |= TPMA_NV_PLATFORMCREATE;

    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW, &nvAuth, policyDigest,
            TPM20_INDEX_PASSWORD_TEST, TPM2_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    rval = AddEntity(TPM20_INDEX_PASSWORD_TEST, &nvAuth);
    CheckPassed(rval);

    return rval;
}


static TSS2_RC TestLocality( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = { 1, };
    TSS2_TCTI_CONTEXT *tctiContext;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths = {{
        .sessionHandle = policySession->sessionHandle,
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};


    /* Init write data. */
    nvWriteData.size = 0;

    rval = Tss2_Sys_GetTctiContext(sysContext, &tctiContext);
    CheckPassed(rval);

    rval = Tss2_Tcti_SetLocality(tctiContext, 2);
    CheckPassed(rval);

    /* Do NV write using open session's policy. */
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_LOCALITY );

    rval = Tss2_Tcti_SetLocality(tctiContext, 3);
    CheckPassed( rval );

    /* Do NV write using open session's policy. */
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckPassed( rval );

    /* Do another NV write using open session's policy. */
    rval = Tss2_Sys_NV_Write( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0, &sessionsDataOut );
    CheckFailed( rval, TPM2_RC_POLICY_FAIL + TPM2_RC_S + TPM2_RC_1 );

    /* Delete NV index */
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].nonce.size = 0;
    sessionsData.auths[0].nonce.buffer[0] = 0xa5;
    sessionsData.auths[0].hmac.size = 0;

    /* Now undefine the index. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );

    DeleteEntity(TPM20_INDEX_PASSWORD_TEST);

    return rval;
}

UINT8 passwordPCRTestPassword[] = "password PCR";
UINT8 dataBlob[] = "some data";
TPM2_HANDLE blobHandle;
TPM2B_AUTH blobAuth;

static TSS2_RC BuildPasswordPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;

    rval = Tss2_Sys_PolicyPassword( sysContext, policySession->sessionHandle, 0, 0 );
    CheckPassed( rval );

    return rval;
}

static TSS2_RC CreateDataBlob( TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, TPM2B_DIGEST *policyDigest )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
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

    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = { .count = 1, .auths = {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    inSensitive.size = 0;
    inSensitive.sensitive.userAuth.size = 0;
    inSensitive.sensitive.data.size = 0;

    inPublic.size = 0;
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;
    *(UINT32 *)&( inPublic.publicArea.objectAttributes) = 0;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
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

    cmdAuthArray.auths[0].sessionHandle = TPM2_RS_PW;

    inSensitive.sensitive.userAuth.size = 0;
    blobAuth.size = sizeof( passwordPCRTestPassword );
    memcpy( &blobAuth.buffer, passwordPCRTestPassword, sizeof( passwordPCRTestPassword ) );
    CopySizedByteBuffer((TPM2B *)&inSensitive.sensitive.userAuth, (TPM2B *)&blobAuth);
    data.size = sizeof( dataBlob );
    memcpy( &data.buffer, dataBlob, sizeof( dataBlob ) );
    CopySizedByteBuffer((TPM2B *)&inSensitive.sensitive.data, (TPM2B *)&data);

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
    inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
    inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
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

    /* Now we need to load the object. */
    INIT_SIMPLE_TPM2B_SIZE( blobName );
    rval = Tss2_Sys_Load( sysContext, srkHandle, &cmdAuthArray, &outPrivate, &outPublic, &blobHandle, &blobName, 0 );
    CheckPassed( rval );

    return rval;
}

static TSS2_RC PasswordUnseal( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession )
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_SENSITIVE_DATA outData;
    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = { .count = 1, .auths = {{
        .sessionHandle = policySession->sessionHandle,
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION,
        .nonce = {.size = 0},
        .hmac = {.size = 0}}}};

    /*
     * Now try to unseal the blob without setting the password.
     * This test should fail.
     */
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckFailed( rval, TPM2_RC_S + TPM2_RC_1 + TPM2_RC_AUTH_FAIL );

    /* Clear DA lockout. */
    TestDictionaryAttackLockReset();

    /*
     * Now try to unseal the blob after setting the password.
     * This test should pass.
     */
    INIT_SIMPLE_TPM2B_SIZE( outData );
    cmdAuthArray.auths[0].hmac.size = sizeof( passwordPCRTestPassword );
    memcpy( &cmdAuthArray.auths[0].hmac.buffer, passwordPCRTestPassword, sizeof( passwordPCRTestPassword ) );
    rval = Tss2_Sys_Unseal( sysContext, blobHandle, &cmdAuthArray, &outData, 0 );
    CheckPassed( rval );

    /* Add test to make sure we unsealed correctly. */

    /*
     * Now we'll want to flush the data blob and remove it
     * from resource manager tables.
     */
    rval = Tss2_Sys_FlushContext( sysContext, blobHandle );
    CheckPassed( rval );

    return rval;
}

POLICY_TEST_SETUP policyTestSetups[] =
{
    /*
     * NOTE:  Since locality is a fairly simple command and we
     * can guarantee its correctness, we don't need a trial
     * session for this. buildPolicyFn pointer can be 0 in
     * this case.
     */
    { "LOCALITY", 0, CreateNVIndex, TestLocality },
    { "PASSWORD", BuildPasswordPolicy, CreateDataBlob, PasswordUnseal },
};

static void TestPolicy()
{
    UINT32 rval;
    unsigned int i;
    SESSION *policySession = 0;

    LOG_INFO("POLICY TESTS:" );

    for( i = 0; i < ( sizeof( policyTestSetups ) / sizeof( POLICY_TEST_SETUP ) ); i++ )
    {
        TPM2B_DIGEST policyDigest;

        policyDigest.size = 0;

        rval = TPM2_RC_SUCCESS;

        LOG_INFO("Policy Test: %s", policyTestSetups[i].name );

        /* Create trial policy session and run policy commands, in order to create policyDigest. */
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, true );
            CheckPassed( rval );
            LOGBLOB_DEBUG(&(policyDigest.buffer[0]), policyDigest.size, "Built policy digest:");
        }

        /* Create entity that will use that policyDigest as authPolicy. */
        if( policyTestSetups[i].createObjectFn != 0 )
        {
            LOGBLOB_DEBUG(&(policyDigest.buffer[0]), policyDigest.size,
                    "Policy digest used to create object:");

            rval = ( *policyTestSetups[i].createObjectFn )( sysContext, &policySession, &policyDigest);
            CheckPassed( rval );
        }

        /*
         * Create real policy session and run policy commands; after this
         * we're ready to authorize actions on the entity.
         */
        if( policyTestSetups[i].buildPolicyFn != 0)
        {
            rval = BuildPolicy( sysContext, &policySession, policyTestSetups[i].buildPolicyFn, &policyDigest, false );
            CheckPassed( rval );
            LOGBLOB_DEBUG(&(policyDigest.buffer[0]), policyDigest.size,
                    "Command policy digest: ");
        }

        if( policySession )
        {
            /* Now do tests by authorizing actions on the entity. */
            rval = ( *policyTestSetups[i].testPolicyFn)( sysContext, policySession );
            CheckPassed( rval );

            /* Need to flush the session here. */
            rval = Tss2_Sys_FlushContext( sysContext, policySession->sessionHandle );
            CheckPassed( rval );

            /* And remove the session from test app session table. */
            end_auth_session( policySession );
        }
        else
        {
            CheckFailed( rval, 0xffffffff );
        }
    }
}

#define MAX_TEST_SEQUENCES 10
static void TestHash()
{
    UINT32 rval;
    TPM2B_AUTH auth;
    TPMI_DH_OBJECT  sequenceHandle[MAX_TEST_SEQUENCES];
    TSS2L_SYS_AUTH_COMMAND sessionsData;
    TPM2B_MAX_BUFFER dataToHash;
    TPM2B_DIGEST result;
    TPMT_TK_HASHCHECK validation;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
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

    LOG_INFO("HASH TESTS:" );

    auth.size = 2;
    auth.buffer[0] = 0;
    auth.buffer[1] = 0xff;
    rval = Tss2_Sys_HashSequenceStart ( sysContext, 0, &auth, TPM2_ALG_SHA1, &sequenceHandle[0], 0 );
    CheckPassed( rval );

    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].nonce.size = 0;
    sessionsData.auths[0].hmac = auth;
    sessionsData.auths[0].sessionAttributes = 0;
    sessionsData.count = 1;

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

    /* Test the resulting hash. */
    if (memcmp(result.buffer, goodHashValue, result.size)) {
        LOG_ERROR("ERROR!! resulting hash is incorrect." );
        Cleanup();
    }
}

static void TestQuote()
{
    UINT32 rval;
    TPM2B_DATA qualifyingData;
    UINT8 qualDataString[] = { 0x00, 0xff, 0x55, 0xaa };
    TPMT_SIG_SCHEME inScheme;
    TPML_PCR_SELECTION  pcrSelection;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .sessionAttributes = 0,
            .nonce = { .size = 0 },
            .hmac = { .size = 0, .buffer={0x00} },
        }},
    };
    TPM2_HANDLE handle, handle_parent;

    LOG_INFO("QUOTE CONTROL TESTS:" );

    qualifyingData.size = sizeof( qualDataString );
    memcpy( &( qualifyingData.buffer[0] ), qualDataString, sizeof( qualDataString ) );

    inScheme.scheme = TPM2_ALG_NULL;

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;

    /* Clear out PCR select bit field */
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;

    /* Now set the PCR you want */
    pcrSelection.pcrSelections[0].pcrSelect[( PCR_17/8 )] = ( 1 << ( PCR_18 % 8) );

    rval = create_primary_rsa_2048_aes_128_cfb(sysContext, &handle_parent);
    CheckPassed( rval );

    rval = create_keyedhash_key (sysContext, handle_parent, &handle);
    CheckPassed( rval );

    /* Test with wrong type of key. */
    INIT_SIMPLE_TPM2B_SIZE( quoted );
    rval = Tss2_Sys_Quote ( sysContext, handle, &sessionsData, &qualifyingData, &inScheme,
            &pcrSelection,  &quoted, &signature, &sessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext(sysContext, handle);
    CheckPassed( rval );

    rval = Tss2_Sys_FlushContext(sysContext, handle_parent);
    CheckPassed( rval );
}

static void ProvisionOtherIndices()
{
    UINT32 rval;
    TPMI_SH_AUTH_SESSION otherIndicesPolicyAuthHandle;
    TPM2B_DIGEST  nvPolicyHash;
    TPM2B_AUTH  nvAuth;
    TSS2L_SYS_AUTH_RESPONSE otherIndicesSessionsDataOut;
    TPM2B_NV_PUBLIC publicInfo;
    TSS2L_SYS_AUTH_COMMAND otherIndicesSessionsData = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    LOG_INFO("PROVISION OTHER NV INDICES:" );

    /*
     * AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled by authValue and is unrestricted since authValue is set to emptyBuffer
     * Do this by setting up two policies and ORing them together when creating AuxIndex:
     * 1.  PolicyLocality(3) && PolicyCommand(NVWrite)
     * 2.  EmptyAuth policy && PolicyCommand(NVRead)
     * Page 126 of Part 1 describes how to do this.
     */

    /* Steps: */
    rval = StartPolicySession( &otherIndicesPolicyAuthHandle );
    CheckPassed( rval );

    /* 3.  GetPolicyDigest and save it */
    INIT_SIMPLE_TPM2B_SIZE( nvPolicyHash );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, otherIndicesPolicyAuthHandle, 0, &nvPolicyHash, 0 );
    CheckPassed( rval );

    /* Now save the policy digest from the first OR branch. */
    LOGBLOB_INFO(&( nvPolicyHash.buffer[0] ), nvPolicyHash.size, "nvPolicyHash");

    /* init nvAuth */
    nvAuth.size = 0;

    publicInfo.size = 0;
    publicInfo.nvPublic.nvIndex = INDEX_LCP_SUP;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    /* First zero out attributes. */
    publicInfo.nvPublic.attributes = 0;

    /* Now set the attributes. */
    publicInfo.nvPublic.attributes |= TPMA_NV_AUTHREAD;
    publicInfo.nvPublic.attributes |= TPMA_NV_AUTHWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_PLATFORMCREATE;
    /* Following commented out for convenience during development. */
    /* publicInfo.nvPublic.attributes |= TPMA_NV_POLICY_DELETE; */
    publicInfo.nvPublic.attributes |= TPMA_NV_WRITEDEFINE;
    publicInfo.nvPublic.attributes |= TPMA_NV_ORDERLY;

    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = NV_PS_INDEX_SIZE;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &otherIndicesSessionsData,
            &nvAuth, &publicInfo, &otherIndicesSessionsDataOut );
    CheckPassed( rval );

    publicInfo.nvPublic.nvIndex = INDEX_LCP_OWN;
    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &otherIndicesSessionsData,
            &nvAuth, &publicInfo, &otherIndicesSessionsDataOut );
    CheckPassed( rval );

    /* Now teardown session */
    rval = Tss2_Sys_FlushContext( sysContext, otherIndicesPolicyAuthHandle );
    CheckPassed( rval );
}


static TSS2_RC InitNvAuxPolicySession( TPMI_SH_AUTH_SESSION *nvAuxPolicySessionHandle )
{
    TPMA_LOCALITY locality;
    TSS2_RC rval;

    rval = StartPolicySession( nvAuxPolicySessionHandle );
    CheckPassed( rval );

    /* 2.  PolicyLocality(3) */
    *(UINT8 *)((void *)&locality) = 0;
    locality |= TPMA_LOCALITY_TPM2_LOC_THREE;
    locality |= TPMA_LOCALITY_TPM2_LOC_FOUR;
    rval = Tss2_Sys_PolicyLocality( sysContext, *nvAuxPolicySessionHandle, 0, locality, 0 );

    return( rval );
}

static void ProvisionNvAux()
{
    UINT32 rval;
    TPMI_SH_AUTH_SESSION nvAuxPolicyAuthHandle;
    TPM2B_DIGEST  nvPolicyHash;
    TPM2B_AUTH  nvAuth;
    TSS2L_SYS_AUTH_RESPONSE nvAuxSessionsDataOut;
    TPM2B_NV_PUBLIC publicInfo;
    TSS2L_SYS_AUTH_COMMAND nvAuxSessionsData = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    LOG_INFO("PROVISION NV AUX:" );

    /*
     * AUX index: Write is controlled by TPM2_PolicyLocality; Read is controlled
     * by authValue and is unrestricted since authValue is set to emptyBuffer
     * Do this by setting up two policies and ORing them together when creating
     * AuxIndex:
     * 1.  PolicyLocality(3) && PolicyCommand(NVWrite)
     * 2.  EmptyAuth policy && PolicyCommand(NVRead)
     * Page 126 of Part 1 describes how to do this.
     */

    /* Steps: */
    rval = InitNvAuxPolicySession( &nvAuxPolicyAuthHandle );
    CheckPassed( rval );

    /* 3.  GetPolicyDigest and save it */
    INIT_SIMPLE_TPM2B_SIZE( nvPolicyHash );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, nvAuxPolicyAuthHandle, 0, &nvPolicyHash, 0 );
    CheckPassed( rval );

    /* Now save the policy digest. */
    LOGBLOB_INFO(&( nvPolicyHash.buffer[0] ), nvPolicyHash.size, "nvPolicyHash");

    /* init nvAuth */
    nvAuth.size = 0;

    publicInfo.size = 0;
    publicInfo.nvPublic.nvIndex = INDEX_AUX;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    /* First zero out attributes. */
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    /* Now set the attributes. */
    publicInfo.nvPublic.attributes |= TPMA_NV_AUTHREAD;
    publicInfo.nvPublic.attributes |= TPMA_NV_POLICYWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_PLATFORMCREATE;
    /* Following commented out for convenience during development. */
    /* publicInfo.nvPublic.attributes.TPMA_NV_POLICY_DELETE = 1; */

    publicInfo.nvPublic.authPolicy.size = GetDigestSize( TPM2_ALG_SHA1 );
    memcpy( (UINT8 *)&( publicInfo.nvPublic.authPolicy.buffer ), (UINT8 *)&(nvPolicyHash.buffer[0]),
            nvPolicyHash.size );

    publicInfo.nvPublic.dataSize = NV_AUX_INDEX_SIZE;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM, &nvAuxSessionsData,
            &nvAuth, &publicInfo, &nvAuxSessionsDataOut );
    CheckPassed( rval );

    /* Now teardown session */
    rval = Tss2_Sys_FlushContext( sysContext, nvAuxPolicyAuthHandle );
    CheckPassed( rval );
}

TSS2L_SYS_AUTH_COMMAND nullSessionsData = { 1, { 0 } };
TSS2L_SYS_AUTH_RESPONSE nullSessionsDataOut = { 0, { 0 } };
TPM2B_NONCE nullSessionNonce, nullSessionNonceOut;
TPM2B_AUTH nullSessionHmac;

static void TpmAuxWrite(int locality)
{
    TSS2_RC rval;
    int i;
    TPMI_SH_AUTH_SESSION nvAuxPolicyAuthHandle;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    TSS2_TCTI_CONTEXT *tctiContext;

    rval = InitNvAuxPolicySession( &nvAuxPolicyAuthHandle );
    CheckPassed( rval );

    /* Now we're going to test it. */
    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

    nullSessionsData.auths[0].sessionHandle = nvAuxPolicyAuthHandle;

    /* Make sure that session terminates after NVWrite completes. */
    nullSessionsData.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;

    rval = Tss2_Sys_GetTctiContext(sysContext, &tctiContext);
    CheckPassed(rval);

    rval = Tss2_Tcti_SetLocality(tctiContext, locality);
    CheckPassed(rval);

    nullSessionsData.count = 1;

    rval = Tss2_Sys_NV_Write( sysContext, INDEX_AUX, INDEX_AUX, &nullSessionsData, &nvWriteData, 0, &nullSessionsDataOut );

    {
        TSS2_RC setLocalityRval;
        setLocalityRval = Tss2_Tcti_SetLocality(tctiContext, 3);
        CheckPassed( setLocalityRval );
    }

    if( locality == 3 || locality == 4 )
    {
        CheckPassed( rval );

        /*
         * No teardown of session needed, since the authorization was
         * successful.
         */
    }
    else
    {
        CheckFailed( rval, TPM2_RC_LOCALITY );

        /* Now teardown session */
        rval = Tss2_Sys_FlushContext( sysContext, nvAuxPolicyAuthHandle );
        CheckPassed( rval );
    }
}

static void TpmAuxReadWriteTest()
{
    UINT32 rval;
    int testLocality;
    TPM2B_MAX_NV_BUFFER nvData;
    TSS2_TCTI_CONTEXT *tctiContext;

    LOG_INFO("TPM AUX READ/WRITE TEST" );

    nullSessionsData.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;

    /* Try writing it from all localities.  Only locality 3 should work. */
    for( testLocality = 0; testLocality < 5; testLocality++ )
    {
        TpmAuxWrite( testLocality );
    }

    nullSessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = Tss2_Sys_GetTctiContext(sysContext, &tctiContext);
    CheckPassed(rval);

    /* Try reading it from all localities.  They all should work. */
    for( testLocality = 0; testLocality < 5; testLocality++ )
    {
        rval = Tss2_Tcti_SetLocality(tctiContext, testLocality);
        CheckPassed( rval );

        INIT_SIMPLE_TPM2B_SIZE( nvData );
        rval = TSS2_RETRY_EXP( Tss2_Sys_NV_Read( sysContext, INDEX_AUX, INDEX_AUX, &nullSessionsData, 4, 0, &nvData, &nullSessionsDataOut ));
        CheckPassed( rval );

        rval = Tss2_Tcti_SetLocality(tctiContext, 3);
        CheckPassed( rval );
    }
}

static void TpmOtherIndicesReadWriteTest()
{
    UINT32 rval;
    TPM2B_MAX_NV_BUFFER nvWriteData;
    int i;
    TPM2B_MAX_NV_BUFFER nvData;

    nullSessionsData.auths[0].sessionHandle = TPM2_RS_PW;

    LOG_INFO("TPM OTHER READ/WRITE TEST" );

    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

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

static void NvIndexProto()
{
    UINT32 rval;

    LOG_INFO("NV INDEX PROTOTYPE TESTS:" );


    /*
     * AUX index: Write is controlled by TPM2_PolicyLocality;
     * Read is controlled by authValue and is unrestricted since authValue is
     * set to emptyBuffer.
     * PS index: Write and read are unrestricted until TPM2_WriteLock.
     * After that content is write protected.
     * PO index: Write is restricted by ownerAuth; Read is controlled by
     * authValue and is unrestricted since authValue is set to emptyBuffer.
     */

    /* Now we need to configure NV indices */
    ProvisionNvAux();

    ProvisionOtherIndices();

    TpmAuxReadWriteTest();

    TpmOtherIndicesReadWriteTest();

    /* Now undefine the aux index, so that subsequent test passes will work. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, INDEX_AUX, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );

    /*
     * Now undefine the other indices, so that subsequent test passes will work.
     */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, INDEX_LCP_SUP, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, INDEX_LCP_OWN, &nullSessionsData, &nullSessionsDataOut );
    CheckPassed( rval );
}

static void TestPcrAllocate()
{
    UINT32 rval;
    TPML_PCR_SELECTION  pcrSelection;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPMI_YES_NO allocationSuccess;
    UINT32 maxPcr;
    UINT32 sizeNeeded;
    UINT32 sizeAvailable;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    LOG_INFO("PCR ALLOCATE TEST  :" );

    pcrSelection.count = 0;

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

static void TestUnseal()
{
    UINT32 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_DATA              outsideInfo;
    TPM2B_PUBLIC            inPublic;
    TPM2_HANDLE loadedObjectHandle, handle_parent;

    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1,
        .auths= {{
            .sessionHandle = TPM2_RS_PW,
            .sessionAttributes = 0,
            .nonce={.size=0},
            .hmac={.size=0, .buffer={0x00}}
        }},
    };

    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
    TPM2B_SENSITIVE_DATA outData;


    const char authStr[] = "test";
    const char sensitiveData[] = "this is sensitive";

    LOG_INFO("UNSEAL TEST  :" );

    inSensitive.size = 0;
    inSensitive.sensitive.userAuth.size = sizeof( authStr ) - 1;
    memcpy( &( inSensitive.sensitive.userAuth.buffer[0] ), authStr, sizeof( authStr ) - 1 );
    inSensitive.sensitive.data.size = sizeof( sensitiveData ) - 1;
    memcpy( &( inSensitive.sensitive.data.buffer[0] ), sensitiveData, sizeof( sensitiveData ) - 1 );

    inPublic.size = 0;
    inPublic.publicArea.authPolicy.size = 0;

    inPublic.publicArea.unique.keyedHash.size = 0;

    outsideInfo.size = 0;
    creationPCR.count = 0;

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;

    *(UINT32 *)&( inPublic.publicArea.objectAttributes) = 0;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;

    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    inPublic.publicArea.unique.keyedHash.size = 0;

    outsideInfo.size = 0;

    outPublic.size = 0;
    creationData.size = 0;

    rval = create_primary_rsa_2048_aes_128_cfb(sysContext, &handle_parent);
    CheckPassed( rval );

    INIT_SIMPLE_TPM2B_SIZE( creationHash );
    INIT_SIMPLE_TPM2B_SIZE( outPrivate );
    rval = Tss2_Sys_Create( sysContext, handle_parent, &sessionsData, &inSensitive, &inPublic,
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
    rval = Tss2_Sys_Load (sysContext, handle_parent, &sessionsData, &outPrivate, &outPublic,
            &loadedObjectHandle, &name, &sessionsDataOut);
    CheckPassed(rval);

    sessionsData.auths[0].hmac.size = sizeof( authStr ) - 1;
    memcpy( &( sessionsData.auths[0].hmac.buffer[0] ), authStr, sizeof( authStr ) - 1 );

    INIT_SIMPLE_TPM2B_SIZE( outData );
    rval = Tss2_Sys_Unseal( sysContext, loadedObjectHandle, &sessionsData, &outData, &sessionsDataOut );
    CheckPassed(rval);

    rval = Tss2_Sys_FlushContext(sysContext, loadedObjectHandle);
    CheckPassed(rval);

    rval = Tss2_Sys_FlushContext(sysContext, handle_parent);
    CheckPassed(rval);
}


static void CreatePasswordTestNV( TPMI_RH_NV_INDEX nvIndex, char * password )
{
    UINT32 rval;
    int i;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_NV_PUBLIC publicInfo;
    TPM2B_AUTH  nvAuth;


    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    nvAuth.size = strlen( password );
    for( i = 0; i < nvAuth.size; i++ ) {
        nvAuth.buffer[i] = password[i];
    }

    publicInfo.size = 0;
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;

    /* First zero out attributes. */
    *(UINT32 *)&( publicInfo.nvPublic.attributes ) = 0;

    /* Now set the attributes. */
    publicInfo.nvPublic.attributes |= TPMA_NV_AUTHREAD;
    publicInfo.nvPublic.attributes |= TPMA_NV_AUTHWRITE;
    publicInfo.nvPublic.attributes |= TPMA_NV_PLATFORMCREATE;
    publicInfo.nvPublic.attributes |= TPMA_NV_ORDERLY;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = 32;

    rval = Tss2_Sys_NV_DefineSpace( sysContext, TPM2_RH_PLATFORM,
            &sessionsData, &nvAuth, &publicInfo, &sessionsDataOut );
    CheckPassed( rval );
}

static void PasswordTest()
{
    char *password = "test password";
    UINT32 rval;
    int i;

    /* Authorization array for response. */
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    /* Authorization array for command (only has one auth structure). */
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    TPM2B_MAX_NV_BUFFER nvWriteData;

    LOG_INFO("PASSWORD TESTS:" );

    /*
     * Create an NV index that will use password authorizations.
     * The password will be "test password".
     */
    CreatePasswordTestNV( TPM20_INDEX_PASSWORD_TEST, password );

    /* Init password (HMAC field in authorization structure). */
    sessionsData.auths[0].hmac.size = strlen( password );
    memcpy( &( sessionsData.auths[0].hmac.buffer[0] ),
            &( password[0] ), sessionsData.auths[0].hmac.size );

    /* Initialize write data. */
    nvWriteData.size = 4;
    for( i = 0; i < nvWriteData.size; i++ )
        nvWriteData.buffer[i] = 0xff - i;

    /*
     * Attempt write with the correct password.
     * It should pass.
     */
    rval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0,
            &sessionsDataOut );
    /*
     * Check that the function passed as
     * expected.  Otherwise, exit.
     */
    CheckPassed( rval );

    /* Alter the password so it's incorrect. */
    sessionsData.auths[0].hmac.buffer[4] = 0xff;
    rval = Tss2_Sys_NV_Write( sysContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &sessionsData, &nvWriteData, 0,
            &sessionsDataOut );
    /*
     * Check that the function failed as expected,
     * since password was incorrect.  If wrong
     * response code received, exit.
     */
    CheckFailed( rval,
            TPM2_RC_S + TPM2_RC_1 + TPM2_RC_AUTH_FAIL );

    /*
     * Change hmac to null one, since null auth is
     * used to undefine the index.
     */
    sessionsData.auths[0].hmac.size = 0;

    /* Now undefine the index. */
    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval );
}

static void SimpleHmacOrPolicyTest( bool hmacTest )
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
    TPM2_SE tpmSe;
    char *testString;
    char testStringHmac[] = "HMAC";
    char testStringPolicy[] = "POLICY";

    /* Response authorization area. */
    TSS2L_SYS_AUTH_RESPONSE nvRspAuths;

    /* Command authorization area: one password session. */
    TSS2L_SYS_AUTH_COMMAND nvCmdAuths = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
        .nonce={.size=0},
        .hmac={.size=0}}}};

    TSS2_SYS_CONTEXT *simpleTestContext;
    TPM2B_NONCE nonceCaller;

    nonceCaller.size = 0;

    if( hmacTest )
        testString = testStringHmac;
    else
        testString = testStringPolicy;

    LOG_INFO("SIMPLE %s SESSION TEST:", testString );
    /* If LOG_INFO is not compiled in, this variable is unused */
    (void)(testString);

    /* Create sysContext structure. */
    simpleTestContext = sapi_init_from_tcti_ctx(resMgrTctiContext);
    if (simpleTestContext == NULL)
        InitSysContextFailure();

    /* Setup the NV index's authorization value. */
    nvAuth.size = strlen( sharedSecret );
    for( i = 0; i < nvAuth.size; i++ )
        nvAuth.buffer[i] = sharedSecret[i];

    /*
     * Create NV index.
     */
    if( hmacTest )
    {
        /* Setup the NV index's authorization value. */
        nvAuth.size = strlen( sharedSecret );
        for( i = 0; i < nvAuth.size; i++ )
            nvAuth.buffer[i] = sharedSecret[i];

        /*
         * Set NV index's authorization policy
         * to zero sized policy since we won't be
         * using policy to authorize.
         */

        authPolicy.size = 0;
    }
    else
    {
        /*
         * Zero sized encrypted salt, since the session
         * is unsalted.
         */

        encryptedSalt.size = 0;

        /* No symmetric algorithm. */
        symmetric.algorithm = TPM2_ALG_NULL;

        /*
         * Create the NV index's authorization policy
         * using a trial policy session.
         */
        rval = create_auth_session(&trialPolicySession,
                TPM2_RH_NULL, 0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt,
                TPM2_SE_TRIAL,
                &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
        CheckPassed( rval );

        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                trialPolicySession->sessionHandle, 0, 0 );
        CheckPassed( rval );

        /* Get policy digest. */
        INIT_SIMPLE_TPM2B_SIZE( authPolicy );
        rval = Tss2_Sys_PolicyGetDigest( simpleTestContext,
                trialPolicySession->sessionHandle,
                0, &authPolicy, 0 );
        CheckPassed( rval );

        /* End the trial session by flushing it. */
        rval = Tss2_Sys_FlushContext( simpleTestContext,
                trialPolicySession->sessionHandle );
        CheckPassed( rval );

        /*
         * And remove the trial policy session from
         * sessions table.
         */
        end_auth_session( trialPolicySession );
    }

    /*
     * Now set the NV index's attributes:
     * policyRead, authWrite, and platormCreate.
     */
    *(UINT32 *)( &nvAttributes ) = 0;
    if( hmacTest )
    {
        nvAttributes |= TPMA_NV_AUTHREAD;
        nvAttributes |= TPMA_NV_AUTHWRITE;
    }
    else
    {
        nvAttributes |= TPMA_NV_POLICYREAD;
        nvAttributes |= TPMA_NV_POLICYWRITE;
    }
    nvAttributes |= TPMA_NV_PLATFORMCREATE;

    /* Create the NV index. */
    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW,
            &nvAuth, &authPolicy, TPM20_INDEX_PASSWORD_TEST,
            TPM2_ALG_SHA256, nvAttributes, 32  );
    CheckPassed( rval );

    /*
     * Add index and associated authorization value to
     * entity table.  This helps when we need
     * to calculate HMACs.
     */
    rval = AddEntity(TPM20_INDEX_PASSWORD_TEST, &nvAuth);
    CheckPassed(rval);

    /* Get the name of the NV index. */
    rval = tpm_handle_to_name(
            resMgrTctiContext,
            TPM20_INDEX_PASSWORD_TEST,
            &nvName);
    CheckPassed( rval );


    /*
     * Start HMAC or real (non-trial) policy authorization session:
     * it's an unbound and unsalted session, no symmetric
     * encryption algorithm, and SHA256 is the session's
     * hash algorithm.
     */

    /*
     * Zero sized encrypted salt, since the session
     * is unsalted.
     */
    encryptedSalt.size = 0;

    /* No symmetric algorithm. */
    symmetric.algorithm = TPM2_ALG_NULL;

    /*
     * Create the session, hmac or policy depending
     * on hmacTest.
     * Session state (session handle, nonces, etc.) gets
     * saved into nvSession structure for later use.
     */
    if( hmacTest )
        tpmSe = TPM2_SE_HMAC;
    else
        tpmSe = TPM2_SE_POLICY;

    rval = create_auth_session(&nvSession, TPM2_RH_NULL,
            0, TPM2_RH_NULL, 0, &nonceCaller, &encryptedSalt, tpmSe,
            &symmetric, TPM2_ALG_SHA256, resMgrTctiContext );
    CheckPassed( rval );

    /*
     * Get the name of the session and save it in
     * the nvSession structure.
     */
    rval = tpm_handle_to_name(
            resMgrTctiContext,
            nvSession->sessionHandle,
            &(nvSession->name) );
    CheckPassed( rval );

    /* Initialize NV write data. */
    nvWriteData.size = sizeof( dataToWrite );
    for( i = 0; i < nvWriteData.size; i++ )
    {
        nvWriteData.buffer[i] = dataToWrite[i];
    }

    /*
     * Now setup for writing the NV index.
     */
    if( !hmacTest )
    {
        /* Send policy command. */
        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                nvSession->sessionHandle, 0, 0 );
        CheckPassed( rval );
    }

    /* First call prepare in order to create cpBuffer. */
    rval = Tss2_Sys_NV_Write_Prepare( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval );

    /* Configure command authorization area, except for HMAC. */
    nvCmdAuths.auths[0].sessionHandle = nvSession->sessionHandle;
    nvCmdAuths.auths[0].nonce.size = 1;
    nvCmdAuths.auths[0].nonce.buffer[0] = 0xa5;
    nvCmdAuths.auths[0].sessionAttributes = 0;
    nvCmdAuths.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;

    /* Roll nonces for command */
    roll_nonces(nvSession, &nvCmdAuths.auths[0].nonce );

    /*
     * Complete command authorization area, by computing
     * HMAC and setting it in nvCmdAuths.
     */
    rval = compute_command_hmac(
            simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            TPM2_RH_NULL,
            &nvCmdAuths);
    CheckPassed(rval);

    /*
     * Finally!!  Write the data to the NV index.
     * If the command is successful, the command
     * HMAC was correct.
     */
    sessionCmdRval = Tss2_Sys_NV_Write(simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, &nvWriteData, 0, &nvRspAuths);
    CheckPassed(sessionCmdRval);

    /* Roll nonces for response */
    roll_nonces(nvSession, &nvRspAuths.auths[0].nonce );

    if (sessionCmdRval == TPM2_RC_SUCCESS) {
        /*
         * If the command was successful, check the
         * response HMAC to make sure that the
         * response was received correctly.
         */
        rval = check_response_hmac(
                simpleTestContext,
                &nvCmdAuths,
                TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST,
                TPM2_RH_NULL,
                &nvRspAuths);
        CheckPassed(rval);
    }

    if( !hmacTest )
    {
        /* Send policy command. */
        rval = Tss2_Sys_PolicyAuthValue( simpleTestContext,
                nvSession->sessionHandle, 0, 0 );
        CheckPassed( rval );
    }

    /* First call prepare in order to create cpBuffer. */
    rval = Tss2_Sys_NV_Read_Prepare( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            sizeof( dataToWrite ), 0 );
    CheckPassed( rval );

    /* Roll nonces for command */
    roll_nonces(nvSession, &nvCmdAuths.auths[0].nonce );

    /* End the session after next command. */
    nvCmdAuths.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;

    /*
     * Complete command authorization area, by computing
     * HMAC and setting it in nvCmdAuths.
     */
    rval = compute_command_hmac(
            simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            TPM2_RH_NULL,
            &nvCmdAuths);
    CheckPassed(rval);

    /*
     * And now read the data back.
     * If the command is successful, the command
     * HMAC was correct.
     */
    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    sessionCmdRval = Tss2_Sys_NV_Read( simpleTestContext,
            TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, sizeof( dataToWrite ), 0,
            &nvReadData, &nvRspAuths );
    CheckPassed( sessionCmdRval );

    /* Roll nonces for response */
    roll_nonces(nvSession, &nvRspAuths.auths[0].nonce );

    if (sessionCmdRval == TPM2_RC_SUCCESS) {
        /*
         * If the command was successful, check the
         * response HMAC to make sure that the
         * response was received correctly.
         */
        rval = check_response_hmac(
                simpleTestContext,
                &nvCmdAuths,
                TPM20_INDEX_PASSWORD_TEST,
                TPM20_INDEX_PASSWORD_TEST,
                TPM2_RH_NULL,
                &nvRspAuths);
        CheckPassed(rval);
    }

    /* Check that write and read data are equal. */
    if( memcmp( (void *)&nvReadData.buffer[0],
            (void *)&nvWriteData.buffer[0], nvReadData.size ) )
    {
        LOG_ERROR("ERROR!! read data not equal to written data" );
        Cleanup();
    }

    /*
     * Now cleanup:  undefine the NV index and delete
     * the NV index's entity table entry.
     */

    /* Setup authorization for undefining the NV index. */
    nvCmdAuths.auths[0].sessionHandle = TPM2_RS_PW;
    nvCmdAuths.auths[0].nonce.size = 0;
    nvCmdAuths.auths[0].hmac.size = 0;

    /* Undefine the NV index. */
    rval = Tss2_Sys_NV_UndefineSpace( simpleTestContext,
            TPM2_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST,
            &nvCmdAuths, 0 );
    CheckPassed( rval );

    /* Delete the NV index's entry in the entity table. */
    DeleteEntity(TPM20_INDEX_PASSWORD_TEST);

    /* Remove the real session from sessions table. */
    end_auth_session( nvSession );

    sapi_teardown(simpleTestContext);
}

static void GetSetDecryptParamTests()
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

    LOG_INFO("GET/SET DECRYPT PARAM TESTS:" );

    /* Create two sysContext structures. */
    decryptParamTestSysContext = sapi_init_from_tcti_ctx(resMgrTctiContext);
    if (decryptParamTestSysContext == NULL)
        InitSysContextFailure();

    /* Test for bad sequence:  Tss2_Sys_GetDecryptParam */
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    /* Test for bad sequence:  Tss2_Sys_SetDecryptParam */
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE );

    /*
     * NOTE:  Two tests for BAD_SEQUENCE for GetDecryptParam and
     * SetDecryptParam after ExecuteAsync are in the GetSetEncryptParamTests
     * function, just because it's easier to do this way.
     */

    /* Do Prepare. */
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData1, 0x55aa );
    CheckPassed( rval );

    /* Test for bad reference:  Tss2_Sys_GetDecryptParam */
    rval = Tss2_Sys_GetDecryptParam( 0, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, 0, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );


    /* Test for bad reference:  Tss2_Sys_SetDecryptParam */
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );

    rval = Tss2_Sys_SetDecryptParam( 0, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE );


    /* Test for bad size. */
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 5, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 3, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    /* Test for good size. */
    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckPassed( rval );

    /* Make sure that the set operation really did the right thing. */
    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );
    for( i = 0; i < 4; i++ )
    {
        if( decryptParamBuffer[i] != nvWriteData.buffer[i] )
        {
            LOG_ERROR("ERROR!!  decryptParamBuffer[%d] s/b: %2.2x, was: %2.2x", i, nvWriteData.buffer[i], decryptParamBuffer[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize1, &cpBuffer1 );
    CheckPassed( rval );

    LOGBLOB_DEBUG((UINT8 *)cpBuffer1, cpBufferUsedSize1, "cpBuffer = ");

    /* Test for no decrypt param. */
    rval = Tss2_Sys_NV_Read_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, sizeof( nvWriteData ) - 2, 0 );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_NO_DECRYPT_PARAM );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_NO_DECRYPT_PARAM );

    /* Null decrypt param. */
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, 0, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );

    /* Check that size == 0. */
    if( decryptParamSize != 0 )
    {
        LOG_ERROR("ERROR!!  decryptParamSize s/b: 0, was: %u", (unsigned int)decryptParamSize );
        Cleanup();
    }

    /* Test for insufficient size. */
    rval = Tss2_Sys_GetCpBuffer(decryptParamTestSysContext, &cpBufferUsedSize2, &cpBuffer2);
    CheckPassed(rval);
    nvWriteData.size = TPM2_MAX_COMMAND_SIZE -
            BE_TO_HOST_32(((TPM20_Header_In *)(((_TSS2_SYS_CONTEXT_BLOB *)decryptParamTestSysContext)->cmdBuffer))->commandSize) + 1;

    rval = Tss2_Sys_SetDecryptParam(decryptParamTestSysContext, nvWriteData.size, nvWriteData.buffer);
    CheckFailed(rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT);

    /*
     * Test that one less will work.
     * This tests that we're checking the correct corner case.
     */
    nvWriteData.size -= 1;
    rval = Tss2_Sys_SetDecryptParam(decryptParamTestSysContext, nvWriteData.size, nvWriteData.buffer);
    CheckPassed(rval);

    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, 0, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_GetDecryptParam( decryptParamTestSysContext, &decryptParamSize, &decryptParamBuffer );
    CheckPassed( rval );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckPassed( rval );

    rval = Tss2_Sys_GetCpBuffer( decryptParamTestSysContext, &cpBufferUsedSize2, &cpBuffer2 );
    CheckPassed( rval );

    LOGBLOB_INFO((UINT8 *)cpBuffer2, cpBufferUsedSize2, "cpBuffer = ");

    if( cpBufferUsedSize1 != cpBufferUsedSize2 )
    {
        LOG_ERROR("ERROR!!  cpBufferUsedSize1(%x) != cpBufferUsedSize2(%x)", (UINT32)cpBufferUsedSize1, (UINT32)cpBufferUsedSize2 );
        Cleanup();
    }
    for( i = 0; i < (int)cpBufferUsedSize1; i++ )
    {
        if( cpBuffer1[i] != cpBuffer2[i] )
        {
            LOG_ERROR("ERROR!! cpBufferUsedSize1[%d] s/b: %2.2x, was: %2.2x", i, cpBuffer1[i], cpBuffer2[i] );
            Cleanup();
        }
    }

    /* Test case of zero sized decrypt param, another case of bad size. */
    nvWriteData1.size = 0;
    rval = Tss2_Sys_NV_Write_Prepare( decryptParamTestSysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData1, 0x55aa );
    CheckPassed( rval );

    rval = Tss2_Sys_SetDecryptParam( decryptParamTestSysContext, 1, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE );

    sapi_teardown(decryptParamTestSysContext);
}

static void SysFinalizeTests()
{
    LOG_INFO("SYS FINALIZE TESTS:" );

    Tss2_Sys_Finalize( 0 );

    /* Note:  other cases tested by other tests. */
}

static void GetContextSizeTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_CONTEXT *testSysContext;

    LOG_INFO("SYS GETCONTEXTSIZE TESTS:" );

    testSysContext = sapi_init_from_tcti_ctx(resMgrTctiContext);
    if (testSysContext == NULL)
        InitSysContextFailure();

    rval = Tss2_Sys_Startup(testSysContext, TPM2_SU_CLEAR);
    CheckPassed(rval);

    rval = Tss2_Sys_GetTestResult_Prepare(testSysContext);
    CheckPassed(rval);

    sapi_teardown(testSysContext);
}

static void GetTctiContextTests()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_SYS_CONTEXT *testSysContext;
    TSS2_TCTI_CONTEXT *tctiContext;

    LOG_INFO("SYS GETTCTICONTEXT TESTS:" );

    testSysContext = sapi_init_from_tcti_ctx(resMgrTctiContext);
    if (testSysContext == NULL)
        InitSysContextFailure();

    rval = Tss2_Sys_GetTctiContext(testSysContext, 0);
    CheckFailed(rval, TSS2_SYS_RC_BAD_REFERENCE);

    rval = Tss2_Sys_GetTctiContext(0, &tctiContext);
    CheckFailed(rval, TSS2_SYS_RC_BAD_REFERENCE);

    sapi_teardown(testSysContext);
}

static void GetSetEncryptParamTests()
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

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1, .auths= {{
        .sessionHandle = TPM2_RS_PW }}};

    TPM2B_MAX_NV_BUFFER nvReadData;
    const uint8_t       *cpBuffer;
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    LOG_INFO("GET/SET ENCRYPT PARAM TESTS:" );

    /* Do Prepare. */
    rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, 0, 0 );
    CheckPassed( rval ); /* #1 */

    resp_header_from_cxt(ctx)->tag = TPM2_ST_SESSIONS;

    /* Test for bad sequence */
    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); /* #2 */

    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, &( nvWriteData.buffer[0] ) );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); /* #3 */

    /* Create NV index */

    /* Set empty policy and auth value. */
    authPolicy.size = 0;
    nvAuth.size = 0;

    /* Now set the attributes. */
    *(UINT32 *)( (void *)&nvAttributes ) = 0;
    nvAttributes |= TPMA_NV_AUTHREAD;
    nvAttributes |= TPMA_NV_AUTHWRITE;
    nvAttributes |= TPMA_NV_PLATFORMCREATE;

    rval = DefineNvIndex( TPM2_RH_PLATFORM, TPM2_RS_PW, &nvAuth, &authPolicy,
            TPM20_INDEX_PASSWORD_TEST, TPM2_ALG_SHA1, nvAttributes, 32  );
    CheckPassed( rval ); /* #4 */

    /* Write the index. */
    rval = Tss2_Sys_NV_Write_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &nvWriteData, 0 );
    CheckPassed( rval ); /* #5 */

    /* NOTE: add GetCpBuffer tests here, just because it's easier. */
    rval = Tss2_Sys_GetCpBuffer( 0, (size_t *)4, (const uint8_t **)4 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #6 */

    rval = Tss2_Sys_GetCpBuffer( sysContext, (size_t *)0, (const uint8_t **)4 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #7 */

    rval = Tss2_Sys_GetCpBuffer( sysContext, (size_t *)4, (const uint8_t **)0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #8 */


    rval = Tss2_Sys_SetCmdAuths( sysContext, &sessionsData );
    CheckPassed( rval ); /* #9 */

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    CheckPassed( rval ); /* #10 */

    /*
     * NOTE: Stick two tests for BAD_SEQUENCE for GetDecryptParam and
     * SetDecryptParam here, just because it's easier to do this way.
     */
    rval = Tss2_Sys_GetDecryptParam( sysContext, (size_t *)4, (const uint8_t **)4 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); /* #11 */

    rval = Tss2_Sys_SetDecryptParam( sysContext, 10, (uint8_t *)4 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); /* #12 */

    /*
     * NOTE: Stick test for BAD_SEQUENCE for GetCpBuffer here, just
     * because it's easier to do this way.
     */
    rval = Tss2_Sys_GetCpBuffer( sysContext, (size_t *)4, &cpBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SEQUENCE ); /* #13 */

    /*
     * Now finish the write command so that TPM isn't stuck trying
     * to send a response.
     */
    rval = Tss2_Sys_ExecuteFinish( sysContext, -1 );
    CheckPassed( rval ); /* #14 */

    /* Test GetEncryptParam for no encrypt param case. */
    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_NO_ENCRYPT_PARAM ); /* #15 */

    /* Test SetEncryptParam for no encrypt param case. */
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckFailed( rval, TSS2_SYS_RC_NO_ENCRYPT_PARAM ); /* #16 */

    /* Now read it and do tests on get/set encrypt functions */
    rval = Tss2_Sys_NV_Read_Prepare( sysContext, TPM20_INDEX_PASSWORD_TEST, TPM20_INDEX_PASSWORD_TEST, 4, 0 );
    CheckPassed( rval ); /* #17 */

    INIT_SIMPLE_TPM2B_SIZE( nvReadData );
    rval = Tss2_Sys_NV_Read( sysContext, TPM20_INDEX_PASSWORD_TEST,
            TPM20_INDEX_PASSWORD_TEST, &sessionsData, 4, 0, &nvReadData, &sessionsDataOut );
    CheckPassed( rval ); /* #18 */

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckPassed( rval ); /* #19 */

    /* Test case of encryptParamSize being too small. */
    encryptParamSize--;
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE ); /* #20 */
    encryptParamSize += 2;

    /* Size too large... */
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_SIZE ); /* #21 */

    encryptParamSize--;
    rval = Tss2_Sys_SetEncryptParam( sysContext, encryptParamSize, encryptParamBuffer1 );
    CheckPassed( rval ); /* #22 */

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, &encryptParamBuffer );
    CheckPassed( rval ); /* #23 */

    /* Test that encryptParamBuffer is the same as encryptParamBuffer1 */
    for( i = 0; i < 4; i++ )
    {
        if( encryptParamBuffer[i] != encryptParamBuffer1[i] )
        {
            LOG_ERROR("ERROR!! encryptParamBuffer[%d] s/b: %2.2x, was: %2.2x", i, encryptParamBuffer[i], encryptParamBuffer1[i] );
            Cleanup();
        }
    }

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, TPM2_RH_PLATFORM, TPM20_INDEX_PASSWORD_TEST, &sessionsData, 0 );
    CheckPassed( rval ); /* #24 */


    /* Test for bad reference */
    rval = Tss2_Sys_GetEncryptParam( 0, &encryptParamSize, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #25 */

    rval = Tss2_Sys_GetEncryptParam( sysContext, 0, &encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #26 */

    rval = Tss2_Sys_GetEncryptParam( sysContext, &encryptParamSize, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #27 */

    rval = Tss2_Sys_SetEncryptParam( sysContext, 4, 0 );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #28 */

    rval = Tss2_Sys_SetEncryptParam( 0, 4, encryptParamBuffer );
    CheckFailed( rval, TSS2_SYS_RC_BAD_REFERENCE ); /* #29 */
}

static void EcEphemeralTest()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_ECC_POINT Q;
    UINT16 counter;

    LOG_INFO("EC Ephemeral TESTS:" );

    /* Test SAPI for case of Q size field not being set to 0. */
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

    nullSessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    nullSessionsDataOut.count = 1;
    nullSessionsDataOut.auths[0].nonce = nullSessionNonceOut;
    nullSessionsDataOut.auths[0].hmac = nullSessionHmac;
    nullSessionNonceOut.size = 0;
    nullSessionNonce.size = 0;

    rval = tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_OFF );
    CheckPassed(rval);

    rval = tcti_platform_command( resMgrTctiContext, MS_SIM_POWER_ON );
    CheckPassed(rval);

    SysFinalizeTests();

    GetContextSizeTests();

    GetTctiContextTests();

    GetSetDecryptParamTests();

    TestTpmStartup();

    /*
     * Run this directly after Startup tests to test for
     * a resource mgr corner case with SaveContext.
     */
    TestStartAuthSession();
    /* Clear DA lockout. */
    TestDictionaryAttackLockReset();
    TestDictionaryAttackLockReset();
    TestHierarchyControl();
    NvIndexProto();
    GetSetEncryptParamTests();
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
    NvIndexProto();
    PasswordTest();
    TestQuote();
    TestDictionaryAttackLockReset();
    TestPcrAllocate();
    TestUnseal();
    EcEphemeralTest();
    return 0;
}
