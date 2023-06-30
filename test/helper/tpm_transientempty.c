/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#include "tss2_tctildr.h"
#include "tss2_sys.h"

#define LOGMODULE test
#include "util/log.h"
#include "test-common.h"

#define TAB_SIZE(x) (sizeof(x)/sizeof(x[0]))

int
main (int argc, char *argv[])
{
    TSS2_RC rc;
    TSS2_ABI_VERSION abi_version = {
        .tssCreator = 1,
        .tssFamily = 2,
        .tssLevel = 1,
        .tssVersion = 108,
    };
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_SYS_CONTEXT *sys_context;
    TPMS_CAPABILITY_DATA caps;
    size_t size;
    char *name_conf;

    name_conf = getenv(ENV_TCTI);
    if (!name_conf) {
        LOG_ERROR("TCTI module not specified. Use environment variable: " ENV_TCTI);
        return 1;
    }

    rc = Tss2_TctiLdr_Initialize(name_conf, &tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error loading TCTI: %s", name_conf);
        return 1;
    }

    size = Tss2_Sys_GetContextSize(0);
    sys_context = (TSS2_SYS_CONTEXT *) calloc(1, size);
    if (sys_context == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for the SYS context\n", size);
        return 1;
    }
    rc = Tss2_Sys_Initialize(sys_context, size, tcti_context, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to initialize SYS context: 0x%x\n", rc);
        free(sys_context);
        return 1;
    }

    rc = Tss2_Sys_GetCapability(sys_context, NULL, TPM2_CAP_HANDLES,
                                TPM2_HR_TRANSIENT,
                                TAB_SIZE(caps.data.handles.handle), NULL,
                                &caps, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM GetCapabilities FAILED! Response Code : 0x%"PRIx32, rc);
        exit(1);
    }

    Tss2_Sys_Finalize(sys_context);
    free(sys_context);
    Tss2_TctiLdr_Finalize(&tcti_context);

    if (caps.data.handles.count) {
        LOG_ERROR("TPM contains transient entries");
        for (UINT32 i = 0; i < caps.data.handles.count; i++)
            LOG_ERROR("Handle %"PRIx32, caps.data.handles.handle[i]);
        return 1;
    }

    return 0;
}
