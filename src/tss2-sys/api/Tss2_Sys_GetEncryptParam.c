/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stddef.h>            // for size_t
#include <stdint.h>            // for uint8_t

#include "sysapi_util.h"       // for _TSS2_SYS_CONTEXT_BLOB, resp_header_fr...
#include "tss2_common.h"       // for UINT8, TSS2_SYS_RC_NO_ENCRYPT_PARAM
#include "tss2_sys.h"          // for TSS2_SYS_CONTEXT, Tss2_Sys_GetEncryptP...
#include "tss2_tpm2_types.h"   // for TPM2_HANDLE, TPM2_PARAMETER_SIZE, TPM2...
#include "util/tss2_endian.h"  // for BE_TO_HOST_16

TSS2_RC Tss2_Sys_GetEncryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *encryptParamSize,
    const uint8_t **encryptParamBuffer)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    uint8_t *offset;

    if (!encryptParamSize || !encryptParamBuffer || !ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->encryptAllowed == 0)
        return TSS2_SYS_RC_NO_ENCRYPT_PARAM;

    if (ctx->previousStage != CMD_STAGE_RECEIVE_RESPONSE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (BE_TO_HOST_16(resp_header_from_cxt(ctx)->tag) == TPM2_ST_NO_SESSIONS)
        return TSS2_SYS_RC_NO_ENCRYPT_PARAM;

    /* Get first parameter, interpret it as a TPM2B and return its size field
     * and a pointer to its buffer area. */
    offset = ctx->cmdBuffer
            + sizeof(TPM20_Header_Out)
            + ctx->numResponseHandles * sizeof(TPM2_HANDLE)
            + sizeof(TPM2_PARAMETER_SIZE);

    *encryptParamSize = BE_TO_HOST_16(*((UINT16 *)offset));
    *encryptParamBuffer = offset + sizeof(UINT16);

    return TSS2_RC_SUCCESS;
}
