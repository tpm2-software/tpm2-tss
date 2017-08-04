#include "log.h"
#include "common/debug.h"
#include "sapi/tpm20.h"
#include "sysapi_util.h"
#include "test.h"
#include "tcti/tcti_device.h"
#include "tcti/tcti_socket.h"
#include "common/tcti_util.h"
#include "context-util.h"
#include <stdio.h>

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2;

/**
 */
int test_invoke(TSS2_SYS_CONTEXT *sapi_context, test_opts_t *opts) {
    TSS2_TCTI_CONTEXT *otherResMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *otherSysContext;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_NAME name;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TSS2_RC rc = TSS2_RC_SUCCESS;

    TPM_HANDLE handle2048rsa = 0;
    TPMS_CONTEXT context;
    TSS2_TCTI_CONTEXT *tctiContext;

    TPM2B_AUTH loadedSha1KeyAuth;

    TPMI_DH_CONTEXT loadedHandle, newHandle, newNewHandle, newHandleDummy;
    TPMS_CONTEXT newContext;
    char otherResMgrInterfaceName[] = "Test RM Resource Manager";

    print_log("RM tests started.");

    loadedSha1KeyAuth.t.size = 2;
    loadedSha1KeyAuth.t.buffer[0] = 0x00;
    loadedSha1KeyAuth.t.buffer[1] = 0xff;

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
    *(UINT32 *)&(inPublic.t.publicArea.objectAttributes) = 0;
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
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;


    print_log("Resource Mgr trying initialization...");
    otherResMgrTctiContext = tcti_init_from_opts(opts);
    if (otherResMgrTctiContext == NULL) {
      print_fail("Resource Mgr, %s, failed initialization.  Exiting...",
                  otherResMgrInterfaceName);
    }
    print_log("otherResMgrTctiContext initialized");

    otherSysContext = InitSysContext(0, otherResMgrTctiContext, &abiVersion);
    if (otherSysContext == 0) {
        print_fail("InitSysContext failed, exiting...");
    }

    // TEST WITH AN INVALID COMMAND CODE.

    rc = Tss2_Sys_Startup_Prepare(sapi_context, TPM_SU_CLEAR);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("Startup_Prepare FAILED! Response Code : %x", rc);
    }

    //
    // Alter the CC by altering the CC field in sapi_context.
    //
    // WARNING:  This is something only a test application should do. Do
    // not use this as sample code.
    //
    ((TPM20_Header_In *)(((_TSS2_SYS_CONTEXT_BLOB *)sapi_context)->tpmInBuffPtr))
        ->commandCode = TPM_CC_FIRST - 1;
    rc = Tss2_Sys_Execute(sapi_context);
    if (rc != TPM_RC_COMMAND_CODE)
    {
        print_fail("Execute FAILED! Response Code : %x", rc);
    }

    // TEST OWNERSHIP

    // Try to access a key created by the first TCTI context.
    sessionData.hmac.t.size = 2;
    sessionData.hmac.t.buffer[0] = 0x00;
    sessionData.hmac.t.buffer[1] = 0xff;

    inPublic.t.publicArea.type = TPM_ALG_RSA;
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;

    // First clear attributes bit field.
    *(UINT32 *)&(inPublic.t.publicArea.objectAttributes) = 0;
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

    // This one should pass, because the same context is allowed to save the
    // context.
    rc = Tss2_Sys_ContextSave(sapi_context, handle2048rsa, &context);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ContextSave FAILED! Response Code : %x", rc);
    }

    // This one should pass, since we saved the context first.
    rc = Tss2_Sys_ContextLoad(otherSysContext, &context, &loadedHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ContextLoad FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_FlushContext(otherSysContext, loadedHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("FlushContext FAILED! Response Code : %x", rc);
    }

    // NOW, DO SOME LOCALITY TESTS

    // Test with null tctiContext ptr.
    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)(
        0, 0);
    if (rc != TSS2_TCTI_RC_BAD_REFERENCE)
    {
        print_fail("setLocality FAILED! Response Code : %x", rc);
    }

    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)(
        otherResMgrTctiContext, 0);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("setLocality FAILED! Response Code : %x", rc);
    }

    // Now try changing localities between send and receive.
    rc = Tss2_Sys_ContextLoad(otherSysContext, &context, &loadedHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ContextLoad FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_FlushContext_Prepare(otherSysContext, loadedHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("FlushContext_Prepare FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteAsync(otherSysContext);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ExecuteAsync FAILED! Response Code : %x", rc);
    }

    // This should fail because locality is changing between send and receive.
    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->setLocality)(
        otherResMgrTctiContext, 1);
    if (rc != TSS2_TCTI_RC_BAD_SEQUENCE)
    {
        print_fail("setLocality FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteFinish(otherSysContext, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ExecuteFinish FAILED! Response Code : %x", rc);
    }

    // NOW, DO SOME CANCEL TESTS

    rc = Tss2_Sys_GetTctiContext(sapi_context, &tctiContext);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("GetTctiContext FAILED! Response Code : %x", rc);
    }

    // Try cancel with null tctiContext ptr.
    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)(0);
    if (rc != TSS2_TCTI_RC_BAD_REFERENCE)
    {
        print_fail("cancel FAILED! Response Code : %x", rc);
    }

    // Try cancel when no commands are pending.
    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)(
        otherResMgrTctiContext);
    if (rc != TSS2_TCTI_RC_BAD_SEQUENCE)
    {
        print_fail("cancel FAILED! Response Code : %x", rc);
    }

    // Then try cancel with a pending command:  send cancel before blocking
    // _Finish call.
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    rc = Tss2_Sys_CreatePrimary_Prepare(sapi_context, TPM_RH_PLATFORM, &inSensitive,
                                        &inPublic, &outsideInfo, &creationPCR);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("CreatePrimary_Prepare FAILED! Response Code : %x", rc);
    }

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
    rc = Tss2_Sys_SetCmdAuths(sapi_context, &sessionsData);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("SetCmdAuths FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ExecuteAsync FAILED! Response Code : %x", rc);
    }

    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel)(tctiContext);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("cancel FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteFinish(sapi_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TPM_RC_CANCELED)
    {
        print_fail("ExecuteFinish FAILED! Response Code : %x", rc);
    }

    // Then try cancel with a pending command:  send cancel after non-blocking
    // _Finish call.
    rc = Tss2_Sys_CreatePrimary_Prepare(sapi_context, TPM_RH_PLATFORM, &inSensitive,
                                        &inPublic, &outsideInfo, &creationPCR);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("CreatePrimary_Prepare FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_SetCmdAuths(sapi_context, &sessionsData);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("SetCmdAuths FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ExecuteAsync FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteFinish(sapi_context, 0);
    if (rc != TSS2_TCTI_RC_TRY_AGAIN)
    {
        print_fail("ExecuteFinish FAILED! Response Code : %x", rc);
    }

    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel)(tctiContext);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("cancel FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteFinish(sapi_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TPM_RC_CANCELED)
    {
        print_fail("ExecuteFinish FAILED! Response Code : %x", rc);
    }

    // Then try cancel from a different connection:  it should just get a sequence
    // error.
    rc = Tss2_Sys_CreatePrimary_Prepare(sapi_context, TPM_RH_PLATFORM, &inSensitive,
                                        &inPublic, &outsideInfo, &creationPCR);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("CreatePrimary_Prepare FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_SetCmdAuths(sapi_context, &sessionsData);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("SetCmdAuths FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ExecuteAsync FAILED! Response Code : %x", rc);
    }

    rc = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)otherResMgrTctiContext)->cancel)(
        otherResMgrTctiContext);
    if (rc != TSS2_TCTI_RC_BAD_SEQUENCE)
    {
        print_fail("cancel FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_ExecuteFinish(sapi_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ExecuteFinish FAILED! Response Code : %x", rc);
    }

    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE(name);
    INIT_SIMPLE_TPM2B_SIZE(creationHash);
    creationHash.t.size = sizeof(creationHash);
    rc = Tss2_Sys_CreatePrimary_Complete(sapi_context, &newHandle, &outPublic,
                                         &creationData, &creationHash,
                                         &creationTicket, &name);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("CreatePrimary_Complete FAILED! Response Code : %x", rc);
    }

    //
    // Now try saving context for object and loading it using a different
    // connection.
    //

    // First save context.
    rc = Tss2_Sys_ContextSave(sapi_context, newHandle, &newContext);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ContextSave FAILED! Response Code : %x", rc);
    }

    //
    // Now create an object with different hierarchy.  This will make sure that
    // RM is getting correct hierarchy in it's table.
    // NOTE:  this test can only be verified by looking at RM output.
    //
    outPublic.t.size = 0;
    creationData.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE(name);
    INIT_SIMPLE_TPM2B_SIZE(creationHash);
    rc = Tss2_Sys_CreatePrimary(
        sapi_context, TPM_RH_ENDORSEMENT, &sessionsData, &inSensitive, &inPublic,
        &outsideInfo, &creationPCR, &newHandleDummy, &outPublic, &creationData,
        &creationHash, &creationTicket, &name, &sessionsDataOut);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("CreatePrimary FAILED! Response Code : %x", rc);
    }

    // Now try loading the context using a different connection.
    rc = Tss2_Sys_ContextLoad(otherSysContext, &newContext, &newNewHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("ContextLoad FAILED! Response Code : %x", rc);
    }

    // Flush original connection's object.
    rc = Tss2_Sys_FlushContext(sapi_context, newHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("FlushContext FAILED! Response Code : %x", rc);
    }

    // Now flush new object from other connection.  Should work.
    rc = Tss2_Sys_FlushContext(otherSysContext, newNewHandle);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("FlushContext FAILED! Response Code : %x", rc);
    }

    // Now flush dummy object.
    rc = Tss2_Sys_FlushContext(sapi_context, newHandleDummy);
    if (rc != TPM_RC_SUCCESS)
    {
        print_fail("FlushContext FAILED! Response Code : %x", rc);
    }

    TeardownTctiContext(&otherResMgrTctiContext);

    TeardownSysContext(&otherSysContext);

    print_log("RM Test Passed!");
    return 0;
}
