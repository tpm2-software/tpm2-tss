/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 */
#ifndef TCTILDR_H
#define TCTILDR_H

#include "tss2_tpm2_types.h"
#include "tss2_tcti.h"

TSS2_RC
tcti_from_init(TSS2_TCTI_INIT_FUNC init,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti);
TSS2_RC
tcti_from_info(TSS2_TCTI_INFO_FUNC infof,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti);

#endif /* TCTILDR_H */
