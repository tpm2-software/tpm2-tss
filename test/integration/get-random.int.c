#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"

/**
 * This program contains integration test for SAPI Tss2_Sys_GetRandom.
 * First, this test is checking the return code to make sure the
 * SAPI is executed correctly(return code should return TPM2_RC_SUCCESS).
 * Second, the SAPI is called twice to make sure the return randomBytes
 * are different by comparing the two randomBytes through memcmp.
 * It might not be the best test for random bytes generator but
 * at least this test shows the return randomBytes are differen.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM2B_DIGEST randomBytes1 = {sizeof (TPM2B_DIGEST) - 2,};
    TPM2B_DIGEST randomBytes2 = {sizeof (TPM2B_DIGEST) - 2,};
    int bytes = 20;

    print_log("GetRandom tests started.");
    rc = Tss2_Sys_GetRandom(sapi_context, 0, bytes, &randomBytes1, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail("GetRandom FAILED! Response Code : %x", rc);
    rc = Tss2_Sys_GetRandom(sapi_context, 0, bytes, &randomBytes2, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail("GetRandom FAILED! Response Code : %x", rc);
    if(memcmp(&randomBytes1, &randomBytes2, bytes) == 0) {
        print_fail("Comparison FAILED! randomBytes 0x%p & 0x%p are the same.", &randomBytes1, &randomBytes2);
    }
    print_log("GetRandom Test Passed!");
    return 0;
}
