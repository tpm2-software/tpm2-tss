/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */
#ifndef TCTI_I2C_HELPER_H
#define TCTI_I2C_HELPER_H
#include <stdbool.h>               // for bool

#include "tcti-common.h"           // for TSS2_TCTI_COMMON_CONTEXT
#include "tcti-helper-common.h"    // for TSS2_TCTI_HELPER_COMMON_CONTEXT
#include "tss2_tcti_i2c_helper.h"  // for TSS2_TCTI_I2C_HELPER_PLATFORM

#define TCTI_I2C_HELPER_MAGIC 0x392452ED67A5D511ULL

#define TCTI_I2C_HELPER_RETRY                           50

#define TCTI_I2C_HELPER_REG_TPM_ACCESS                  0x04
#define TCTI_I2C_HELPER_REG_TPM_STS                     0x18
#define TCTI_I2C_HELPER_REG_TPM_DATA_FIFO               0x24
#define TCTI_I2C_HELPER_REG_TPM_I2C_INTF_CAP            0x30
#define TCTI_I2C_HELPER_REG_TPM_DATA_CSUM_ENABLE        0x40
#define TCTI_I2C_HELPER_REG_TPM_DATA_CSUM               0x44
#define TCTI_I2C_HELPER_REG_TPM_DID_VID                 0x48
#define TCTI_I2C_HELPER_REG_TPM_RID                     0x4C

enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE {
    TCTI_I2C_HELPER_REGISTER_WRITE = 0,
    TCTI_I2C_HELPER_REGISTER_READ = 1
};

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TCTI_HELPER_COMMON_CONTEXT helper_common;
    TSS2_TCTI_I2C_HELPER_PLATFORM platform;
} TSS2_TCTI_I2C_HELPER_CONTEXT;

#endif /* TCTI_I2C_HELPER_H */
