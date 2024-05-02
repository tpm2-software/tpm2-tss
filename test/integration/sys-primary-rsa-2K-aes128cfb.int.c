/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>         // for PRIx32

#define LOGMODULE test
#include "sys-util.h"         // for create_primary_rsa_2048_aes_128_cfb
#include "test.h"             // for test_invoke
#include "tss2_common.h"      // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_sys.h"         // for Tss2_Sys_FlushContext, TSS2_SYS_CONTEXT
#include "tss2_tpm2_types.h"  // for TPM2_HANDLE
#include "util/log.h"         // for LOG_ERROR

int
test_invoke (TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    TPM2_HANDLE handle;

    rc = create_primary_rsa_2048_aes_128_cfb (sys_context, &handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary failed with 0x%"PRIx32, rc);
        return 1;
    }

    rc = Tss2_Sys_FlushContext(sys_context, handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Tss2_Sys_FlushContext failed with 0x%"PRIx32, rc);
        return 99; /* fatal error */
    }

    return 0;
}
