/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"

#ifdef CONFIGURATOR
#include "configurator.h"
#endif

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_GETCONTEXTSIZE)
size_t Tss2_Sys_GetContextSize(size_t maxCommandSize)
{
    if (maxCommandSize == 0) {
        return sizeof(_TSS2_SYS_CONTEXT_BLOB) + TPM2_MAX_COMMAND_SIZE;
    } else {
        return sizeof(_TSS2_SYS_CONTEXT_BLOB) +
                     ((maxCommandSize > sizeof(TPM20_Header_In)) ?
                       maxCommandSize : sizeof(TPM20_Header_In));
    }
}
#endif
