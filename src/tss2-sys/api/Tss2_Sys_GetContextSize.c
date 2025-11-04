/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stddef.h>           // for size_t

#include "sysapi_util.h"      // for TPM20_Header_In, _TSS2_SYS_CONTEXT_BLOB
#include "tss2_sys.h"         // for Tss2_Sys_GetContextSize
#include "tss2_tpm2_types.h"  // for TPM2_MAX_COMMAND_SIZE

size_t Tss2_Sys_GetContextSize(size_t maxCommandSize)
{
    if (maxCommandSize == 0) {
        return sizeof(TSS2_SYS_CONTEXT_BLOB) + TPM2_MAX_COMMAND_SIZE;
    } else {
        return sizeof(TSS2_SYS_CONTEXT_BLOB) +
                     ((maxCommandSize > sizeof(TPM20_Header_In)) ?
                       maxCommandSize : sizeof(TPM20_Header_In));
    }
}
