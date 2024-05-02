/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "tss2_sys.h"       // for TSS2_SYS_CONTEXT, Tss2_Sys_Finalize
#include "util/aux_util.h"  // for UNUSED

void Tss2_Sys_Finalize(
    TSS2_SYS_CONTEXT *sysContext)
{
    UNUSED(sysContext);
}
