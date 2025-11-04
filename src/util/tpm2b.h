/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef TPM2B_H
#define TPM2B_H

#include "tss2_common.h"  // for BYTE, UINT16

typedef struct {
    UINT16 size;
    BYTE buffer[];
} TPM2B;

#endif /* TPM2B_H */
