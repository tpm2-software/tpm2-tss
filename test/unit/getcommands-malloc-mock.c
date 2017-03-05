#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tpm20.h"

extern TSS2_RC GetCommands( TSS2_SYS_CONTEXT *resMgrSysContext, TPML_CCA **supportedCommands );

void*
__wrap_malloc (size_t size)
{
    return (void*) mock ();
}

TPM_RC
__wrap_Tss2_Sys_GetCapability (TSS2_SYS_CONTEXT         *sys_ctx,
                               TSS2_SYS_CMD_AUTHS const *cmdAuthArray,
                               TPM_CAP                   capability,
                               UINT32                    property,
                               UINT32                    propertyCount,
                               TPMI_YES_NO              *moreData,
                               TPMS_CAPABILITY_DATA     *capabilityData,
                               TSS2_SYS_RSP_AUTHS       *rspAuthsArray)
{
    capabilityData->capability = TPM_CAP_TPM_PROPERTIES;
    capabilityData->data.tpmProperties.count = 1;
    capabilityData->data.tpmProperties.tpmProperty[0].property = TPM_PT_TOTAL_COMMANDS;
    capabilityData->data.tpmProperties.tpmProperty[0].value = 0;

    return (TSS2_RC) mock ();
}
/* This test forces a failure in the call to malloc in GetCommands. To do
 * this we must mock both Tss2_Sys_GetCapability and malloc. Mocking the
 * Tss2 function is required to get to the malloc call where we're forcing
 * the filure. This test ensures that when malloc fails, GetCommands returns
 * the right error layer / level and the right INSUFFICIENT_BUFFER code.
 */
static void
getcommand_malloc_fail (void **state)
{
    TSS2_SYS_CONTEXT *sys_ctx = NULL;
    TPML_CCA *commands;
    TSS2_RC ret, ret_expected = TSS2_BASE_RC_INSUFFICIENT_BUFFER + TSS2_RESMGR_ERROR_LEVEL;

    /* Return value for Tss2_Sys_GetCapability.
     * The calling function (GetCommands) will pass it a valid
     * TPMS_CAPABILITY_DATA structure and that's the only parameter we need.
     */
    will_return (__wrap_Tss2_Sys_GetCapability, TPM_RC_SUCCESS);
    /* Return value for malloc: this causes the error condition we're
     * testing
     */
    will_return (__wrap_malloc, NULL);
    ret = GetCommands (sys_ctx, &commands);
    assert_int_equal (ret, ret_expected);
}

int
main (int argc, char* argv[])
{
    const UnitTest tests[] = {
        unit_test (getcommand_malloc_fail),
    };
    return run_tests (tests);
}
