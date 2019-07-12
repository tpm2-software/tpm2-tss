/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2019, Intel Corporation
 */
#ifndef TCTILDR_DL_H
#define TCTILDR_DL_H

#include "tss2_tpm2_types.h"
#include "tss2_tcti.h"

TSS2_RC
tcti_from_file(const char *file,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti,
               void **dlhandle);

#endif /* TCTILDR_DL_H */
