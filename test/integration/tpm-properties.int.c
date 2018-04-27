/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ***********************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include "tss2_sys.h"

#define LOGMODULE test
#include "util/log.h"
#include "test.h"
#include "sysapi_util.h"

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPMS_CAPABILITY_DATA capability_data;

    LOG_INFO("Get TPM Properties Test started.");
    rc = Tss2_Sys_GetCapability(sapi_context, 0, TPM2_CAP_TPM_PROPERTIES,
                                TPM2_PT_MANUFACTURER, 1, 0, &capability_data, 0);
    if (rc != TSS2_RC_SUCCESS ||
        capability_data.data.tpmProperties.tpmProperty[0].property != TPM2_PT_MANUFACTURER) {
        LOG_ERROR("Get TPM Properties TPM2_PT_MANUFACTURER FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_INFO("TPM Manufacturer 0x%x", capability_data.data.tpmProperties.tpmProperty[0].value);

    rc = Tss2_Sys_GetCapability(sapi_context, 0, TPM2_CAP_TPM_PROPERTIES,
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
