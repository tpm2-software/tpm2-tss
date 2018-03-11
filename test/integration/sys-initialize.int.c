#include <stdio.h>
#define LOGMODULE test
#include "util/log.h"
#include "test.h"
#include "tpm20.h"
#include "tss2-tcti/tcti.h"
#include "tss2-sys/include/sysapi_util.h"

/**
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;

    // NOTE: this should never be done in real applications.
    // It is only done here for test purposes.
    TSS2_TCTI_CONTEXT_INTEL tctiContextIntel;

    LOG_INFO("Sys_Initialize tests started.");

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)0, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)0, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)0 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_INSUFFICIENT_CONTEXT ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    // NOTE: don't do this in real applications.
    TSS2_TCTI_RECEIVE (&tctiContextIntel) = (TSS2_TCTI_RECEIVE_FCN)1;
    TSS2_TCTI_TRANSMIT (&tctiContextIntel) = (TSS2_TCTI_TRANSMIT_FCN)0;

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_TCTI_STRUCTURE ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    // NOTE: don't do this in real applications.
    TSS2_TCTI_RECEIVE (&tctiContextIntel) = (TSS2_TCTI_RECEIVE_FCN)0;
    TSS2_TCTI_TRANSMIT (&tctiContextIntel) = (TSS2_TCTI_TRANSMIT_FCN)1;

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_TCTI_STRUCTURE ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    LOG_INFO("Sys_Initialize Test Passed!");
    return 0;
}
