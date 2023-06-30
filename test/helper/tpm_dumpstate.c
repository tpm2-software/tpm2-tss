/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include "tss2_tctildr.h"
#include "tss2_sys.h"
#include "tss2_mu.h"

#define LOGMODULE test
#include "util/log.h"
#include "test-common.h"

#define TAB_SIZE(x) (sizeof(x)/sizeof(x[0]))

/* NOTE: CAP_PCRS and CAP_HANDLES->HR_PCR do not change until a reboot is
  triggered. This should be improved if an approach is found. */
struct {
    TPM2_CAP cap;
    UINT32 prop;
    UINT32 count;
} capabilities[] = {
    { TPM2_CAP_PCRS, 0, 10 },
    { TPM2_CAP_HANDLES, TPM2_HR_PCR, TPM2_MAX_CAP_HANDLES },
    { TPM2_CAP_HANDLES, TPM2_HR_HMAC_SESSION, TPM2_MAX_CAP_HANDLES },
    { TPM2_CAP_HANDLES, TPM2_HR_POLICY_SESSION, TPM2_MAX_CAP_HANDLES },
    { TPM2_CAP_HANDLES, TPM2_HR_TRANSIENT, TPM2_MAX_CAP_HANDLES },
    { TPM2_CAP_HANDLES, TPM2_HR_PERSISTENT, TPM2_MAX_CAP_HANDLES },
    { TPM2_CAP_HANDLES, TPM2_HR_NV_INDEX, TPM2_MAX_CAP_HANDLES },
};

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

    for (size_t i = 0; i < TAB_SIZE(capabilities); i++) {
        TPMS_CAPABILITY_DATA caps;
        uint8_t buffer[sizeof(caps)];
        size_t off = 0;

        rc = Tss2_Sys_GetCapability(sys_context, NULL, capabilities[i].cap,
                                    capabilities[i].prop,
                                    capabilities[i].count, NULL,
                                    &caps, NULL);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR("TPM GetCapabilities FAILED: 0x%"PRIx32, rc);
            exit(1);
        }

        rc = Tss2_MU_TPMS_CAPABILITY_DATA_Marshal(&caps, &buffer[off],
                                                  sizeof(buffer) - off - 1,
                                                  &off);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR("Marshaling FAILED: 0x%"PRIx32, rc);
            exit(1);
        }

        buffer[off++] = '\0';

        printf("cap%zi: ", i);
        for (size_t j = 0; j < off; j++)
            printf("%02"PRIx8, buffer[j]);
        printf("\n");
    }

    Tss2_Sys_Finalize(sys_context);
    free(sys_context);
    Tss2_TctiLdr_Finalize(&tcti_context);

    return 0;
}
