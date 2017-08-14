#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"

/**
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context, test_opts_t *opts)
{
    TSS2_RC rc;
    UINT32 contextSize;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_ABI_VERSION tstAbiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

    print_log( "ABI NEGOTIATION TESTS" );

    // Get the size needed for sapi context structure.
    contextSize = Tss2_Sys_GetContextSize( 0 );

    rc = Tss2_Sys_GetTctiContext (sapi_context, &tcti_context);
    if( rc != TSS2_RC_SUCCESS )
    {
        print_fail("ABIVersion FAILED! Response Code : %x", rc);
    }

    // Initialized the system context structure.
    tstAbiVersion.tssCreator = 0xF0000000;
    rc = Tss2_Sys_Initialize( sapi_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        print_fail("ABIVersion FAILED! Response Code : %x", rc);
    }

    tstAbiVersion.tssCreator = TSSWG_INTEROP;
    tstAbiVersion.tssFamily = 0xF0000000;
    rc = Tss2_Sys_Initialize( sapi_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        print_fail("ABIVersion FAILED! Response Code : %x", rc);
    }

    tstAbiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    tstAbiVersion.tssLevel = 0xF0000000;
    rc = Tss2_Sys_Initialize( sapi_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        print_fail("ABIVersion FAILED! Response Code : %x", rc);
    }

    tstAbiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    tstAbiVersion.tssVersion = 0xF0000000;
    rc = Tss2_Sys_Initialize( sapi_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        print_fail("ABIVersion FAILED! Response Code : %x", rc);
    }


    print_log("ABIVersion Test Passed!");
    return 0;
}
