/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 Infineon Technologies AG
 */
#ifndef TSS2_TCTI_SPIDEV_H
#define TSS2_TCTI_SPIDEV_H

#include <stdbool.h>
#include "tss2_tcti.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC Tss2_Tcti_Spidev_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *config);


#ifdef __cplusplus
}
#endif

#endif /* TSS2_TCTI_SPIDEV_H */
