/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for exit

#include "tss2_common.h"      // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_sys.h"         // for Tss2_Sys_GetCapability, TSS2_SYS_CONTEXT
#include "tss2_tpm2_types.h"  // for TPMS_TAGGED_PROPERTY, TPMS_CAPABILITY_DATA

#define LOGMODULE test
#include "test.h"             // for test_invoke
#include "util/log.h"         // for LOG_INFO, LOG_ERROR

int
test_invoke (TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    TPMS_CAPABILITY_DATA capability_data;

    LOG_INFO("Get TPM Properties Test started.");
    rc = Tss2_Sys_GetCapability(sys_context, 0, TPM2_CAP_TPM_PROPERTIES,
                                TPM2_PT_MANUFACTURER, 1, 0, &capability_data, 0);
    if (rc != TSS2_RC_SUCCESS ||
        capability_data.data.tpmProperties.tpmProperty[0].property != TPM2_PT_MANUFACTURER) {
        LOG_ERROR("Get TPM Properties TPM2_PT_MANUFACTURER FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_INFO("TPM Manufacturer 0x%x", capability_data.data.tpmProperties.tpmProperty[0].value);

    rc = Tss2_Sys_GetCapability(sys_context, 0, TPM2_CAP_TPM_PROPERTIES,
                                TPM2_PT_REVISION, 1, 0, &capability_data, 0);
    if (rc != TSS2_RC_SUCCESS ||
        capability_data.data.tpmProperties.tpmProperty[0].property != TPM2_PT_REVISION) {
        LOG_ERROR("Get TPM Properties TPM2_PT_REVISION FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_INFO("TPM revision 0x%X", capability_data.data.tpmProperties.tpmProperty[0].value);

    LOG_INFO("Get TPM Properties Test Passed!");
    return 0;
}
