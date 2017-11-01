#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"
#include "sysapi_util.h"

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPMS_CAPABILITY_DATA capability_data;

    print_log("Get TPM Properties Test started.");
    rc = Tss2_Sys_GetCapability(sapi_context, 0, TPM_CAP_TPM_PROPERTIES,
                                TPM_PT_MANUFACTURER, 1, 0, &capability_data, 0);
    if (rc != TSS2_RC_SUCCESS ||
        capability_data.data.tpmProperties.tpmProperty[0].property != TPM_PT_MANUFACTURER)
        print_fail("Get TPM Properties TPM_PT_MANUFACTURER FAILED! Response Code : 0x%x", rc);

    print_log("TPM Manufacturer 0x%x", capability_data.data.tpmProperties.tpmProperty[0].value);

    rc = Tss2_Sys_GetCapability(sapi_context, 0, TPM_CAP_TPM_PROPERTIES,
                                TPM_PT_REVISION, 1, 0, &capability_data, 0);
    if (rc != TSS2_RC_SUCCESS ||
        capability_data.data.tpmProperties.tpmProperty[0].property != TPM_PT_REVISION)
        print_fail("Get TPM Properties TPM_PT_REVISION FAILED! Response Code : 0x%x", rc);

    print_log("TPM revision 0x%X", capability_data.data.tpmProperties.tpmProperty[0].value);

    print_log("Get TPM Properties Test Passed!");
    return 0;
}
