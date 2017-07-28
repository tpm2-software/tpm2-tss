#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"

/**
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;

    // NOTE: this should never be done in real applications.
    // It is only done here for test purposes.
    TSS2_TCTI_CONTEXT_INTEL tctiContextIntel;

    print_log("Sys_Initialize tests started.");

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)0, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  )
    {
        print_fail("Sys_Initialize FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)0, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  )
    {
        print_fail("Sys_Initialize FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)0 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  )
    {
        print_fail("Sys_Initialize FAILED! Response Code : %x", rc);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_INSUFFICIENT_CONTEXT )
    {
        print_fail("Sys_Initialize FAILED! Response Code : %x", rc);
    }

    // NOTE: don't do this in real applications.
    tctiContextIntel.transmit = (TCTI_TRANSMIT_PTR)0;
    tctiContextIntel.receive = (TCTI_RECEIVE_PTR)1;

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_TCTI_STRUCTURE )
    {
        print_fail("Sys_Initialize FAILED! Response Code : %x", rc);
    }

    // NOTE: don't do this in real applications.
    tctiContextIntel.transmit = (TCTI_TRANSMIT_PTR)1;
    tctiContextIntel.receive = (TCTI_RECEIVE_PTR)0;

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_TCTI_STRUCTURE )
    {
        print_fail("Sys_Initialize FAILED! Response Code : %x", rc);
    }

    print_log("Sys_Initialize Test Passed!");
    return 0;
}
