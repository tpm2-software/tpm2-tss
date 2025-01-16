/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 Juergen Repp
 * All rights reserved.
 */

#ifndef TCTI_NULL_H
#define TCTI_NULL_H

#include "tcti-common.h"
#include "tss2_tcti.h"

#define TCTI_NULL_MAGIC 0x9af45c5d7d9d0d3fULL

typedef struct {
    const char *child_tcti;
} tcti_null_conf_t;

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
} TSS2_TCTI_NULL_CONTEXT;

#endif /* TCTI_NULL_H */
