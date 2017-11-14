#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"
#include "sapi-util.h"

/*
 * System API tests including invalid cases
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TPM2B_MAX_BUFFER    outData = TPM2B_NAMED_INIT(TPM2B_MAX_BUFFER, buffer);
    TPM2B_PUBLIC        outPublic;
    TPM2B_NAME          name = TPM2B_NAME_INIT;
    TPM2B_NAME          qualifiedName;
    TPM2_HANDLE          handle = 0;
    TPM2_CC              commandCode;
    size_t              rpBufferUsedSize;
    const uint8_t      *rpBuffer;
    TSS2_RC             rc;

    print_log("System API test");
    /* Test for bad reference. */
    rc = Tss2_Sys_GetTestResult_Prepare(0);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("Invalid prepare test FAILED! Response Code : 0x%x", rc);

    /* Test for bad sequence:  after ExecuteAsync */
    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("Invalid prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_ExecuteFinish(sapi_context, -1);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    /* Test for bad sequence:  after Execute */
    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_Execute(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("Prepare test FAILED! Response Code : 0x%x", rc);

    /* Test for other NULL params */
    rc = Tss2_Sys_Create_Prepare(sapi_context, 0xffffffff, 0, 0, 0, 0);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("Invalid prepare test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetTestResult(sapi_context, 0, &outData, &rc, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("GetTestResult test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_Execute(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test the synchronous, non-one-call interface. */
    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_REFERENCE error. */
    rc = Tss2_Sys_Execute(0);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Execute the command synchronously. */
    rc = Tss2_Sys_Execute(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_Execute(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Now test the asynchronous, non-one-call interface. */
    rc = Tss2_Sys_GetTestResult_Prepare(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetTestResult_Complete(sapi_context, &outData, &rc);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_REFERENCE error. */
    rc = Tss2_Sys_ExecuteAsync(0);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test ExecuteFinish for BAD_SEQUENCE */
    rc = Tss2_Sys_ExecuteFinish(sapi_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Execute the command asynchronously. */
    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_Execute(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test ExecuteFinish for BAD_REFERENCE */
    rc = Tss2_Sys_ExecuteFinish(0, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test XXXX_Complete for bad sequence:  after _Prepare
     * and before ExecuteFinish */
    rc = Tss2_Sys_GetTestResult_Complete(sapi_context, &outData, &rc);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Get the command response. Wait a maximum of 20ms
     * for response. */
    rc = Tss2_Sys_ExecuteFinish(sapi_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_ExecuteFinish(sapi_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Check for BAD_SEQUENCE error. */
    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test _Complete for bad reference cases. */
    rc = Tss2_Sys_GetTestResult_Complete(0, &outData, &rc);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_ReadPublic_Prepare(sapi_context, handle);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    /* Execute the command synchronously. */
    rc = Tss2_Sys_ExecuteAsync(sapi_context);
    if (rc != TSS2_RC_SUCCESS)
        print_fail ("SAPI test FAILED! Response Code : 0x%x", rc);

    /* Test _Complete for bad sequence case when ExecuteFinish has never
     * been done on a context. */
    rc = Tss2_Sys_ReadPublic_Complete(sapi_context, &outPublic, &name, &qualifiedName);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetRpBuffer(sapi_context, &rpBufferUsedSize, &rpBuffer);
    if (rc != TSS2_SYS_RC_BAD_SEQUENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);
    /* CheckFailed(rc, TSS2_SYS_RC_BAD_SEQUENCE); */

    /* Test one-call for null sapi_context pointer. */
    rc = Tss2_Sys_Startup(0, TPM2_SU_CLEAR);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test one-call for NULL input parameter that should be a pointer. */
    rc = Tss2_Sys_Create(sapi_context, 0xffffffff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    /* Test GetCommandCode for bad reference */
    rc = Tss2_Sys_GetCommandCode(0, (UINT8 (*)[4])&commandCode);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_GetCommandCode(sapi_context, NULL);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE)
        print_fail ("SAPI invalid test FAILED! Response Code : 0x%x", rc);

    print_log("System API test Passed!");
    return 0;
}
