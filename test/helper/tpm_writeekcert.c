/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
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
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {
        .auths = {{ .sessionHandle = TPM2_RH_PW }},
        .count = 1
    };
    TPMI_RH_NV_INDEX nvIndex;
    size_t size;
    char *name_conf;

    if (argv[1])
        nvIndex = strtol(argv[1], NULL, 16);
    else
        nvIndex = 0x01c00002;

    TPM2B_AUTH nv_auth = { 0 };
    TPM2B_NV_PUBLIC public_info = {
        .nvPublic = {
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = TPMA_NV_PPWRITE | TPMA_NV_AUTHREAD | TPMA_NV_OWNERREAD |
                TPMA_NV_PLATFORMCREATE | TPMA_NV_NO_DA,
            .dataSize = 0,
            .nvIndex = nvIndex,
        },
    };

    TSS2L_SYS_AUTH_RESPONSE auth_rsp = {
        .count = 0
    };
    TPM2B_MAX_NV_BUFFER buf1 = { 0 };
    TPM2B_MAX_NV_BUFFER buf2 = { 0 };

    buf1.size += fread(&buf1.buffer[buf1.size], sizeof(buf1.buffer[0]),
                       sizeof(buf1.buffer) - buf1.size, stdin);
    if (buf1.size >= sizeof(buf1.buffer)) {
        LOG_ERROR("input to large");
        exit(1);
    }

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

    /* First make sure that not EK certificate is currently loaded */
    LOG_WARNING("Cert input size is %"PRIu16, buf1.size);
    public_info.nvPublic.dataSize = buf1.size;

    LOG_WARNING("Define NV cert with nv index: %x", public_info.nvPublic.nvIndex);

    rc = Tss2_Sys_NV_DefineSpace(sys_context, TPM2_RH_PLATFORM, &auth_cmd,
                                 &nv_auth, &public_info, &auth_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM NV DefineSpace FAILED: 0x%"PRIx32, rc);
        exit(1);
    }

    /* Split the input buffer into 2 chunks */
    buf2.size = buf1.size;
    buf1.size /= 2;
    buf2.size -= buf1.size;
    memcpy(&buf2.buffer[0], &buf1.buffer[buf1.size], buf2.size);

    rc = Tss2_Sys_NV_Write(sys_context, TPM2_RH_PLATFORM, nvIndex, &auth_cmd,
                           &buf1, 0, &auth_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM NV Write FAILED: 0x%"PRIx32, rc);
        exit(1);
    }

    rc = Tss2_Sys_NV_Write(sys_context, TPM2_RH_PLATFORM, nvIndex, &auth_cmd,
                           &buf2, buf1.size, &auth_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM NV Write FAILED: 0x%"PRIx32, rc);
        exit(1);
    }

    Tss2_Sys_Finalize(sys_context);
    free(sys_context);
    Tss2_TctiLdr_Finalize(&tcti_context);

    return 0;
}
