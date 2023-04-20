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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "tcti-common.h"

#define TCTI_I2C_HELPER_MAGIC 0x392452ED67A5D511ULL

#define TCTI_I2C_HELPER_RESP_HEADER_SIZE 6

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TSS2_TCTI_I2C_HELPER_PLATFORM platform;
    bool guard_time_read;
    bool guard_time_write;
    int  guard_time;
    char header[TCTI_I2C_HELPER_RESP_HEADER_SIZE];
} TSS2_TCTI_I2C_HELPER_CONTEXT;

#define TCTI_I2C_HELPER_RETRY                           50
#define TCTI_I2C_HELPER_DEFAULT_GUARD_TIME_US           250

#define TCTI_I2C_HELPER_TPM_ACCESS_REG                  0x04
#define TCTI_I2C_HELPER_TPM_STS_REG                     0x18
#define TCTI_I2C_HELPER_TPM_DATA_FIFO_REG               0x24
#define TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_REG    0x30
#define TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG        0x40
#define TCTI_I2C_HELPER_TPM_DATA_CSUM_REG               0x44
#define TCTI_I2C_HELPER_TPM_DID_VID_REG                 0x48
#define TCTI_I2C_HELPER_TPM_RID_REG                     0x4C

#define TCTI_I2C_HELPER_TPM_GUARD_TIME_SR_MASK          0x40000000
#define TCTI_I2C_HELPER_TPM_GUARD_TIME_RR_MASK          0x00100000
#define TCTI_I2C_HELPER_TPM_GUARD_TIME_RW_MASK          0x00080000
#define TCTI_I2C_HELPER_TPM_GUARD_TIME_WR_MASK          0x00040000
#define TCTI_I2C_HELPER_TPM_GUARD_TIME_WW_MASK          0x00020000
#define TCTI_I2C_HELPER_TPM_GUARD_TIME_MASK             0x0001FE00
#define TCTI_I2C_HELPER_TPM_BURST_COUNT_STATIC_MASK     0x20000000
#define TCTI_I2C_HELPER_TPM_GUARD_TIME_SHIFT            9

#define TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_ZERO   0x80000000
#define TCTI_I2C_HELPER_TPM_STS_ZERO                    0x23
#define TCTI_I2C_HELPER_TPM_ACCESS_ZERO                 0x48

enum TCTI_I2C_HELPER_TPM_ACCESS {
    TCTI_I2C_HELPER_TPM_ACCESS_VALID = (1 << 7),
    TCTI_I2C_HELPER_TPM_ACCESS_ACTIVE_LOCALITY = (1 << 5),
    TCTI_I2C_HELPER_TPM_ACCESS_REQUEST_USE = (1 << 1)
};

enum TCTI_I2C_HELPER_TPM_STATUS {
    TCTI_I2C_HELPER_TPM_STS_BURST_COUNT_SHIFT = 8,
    TCTI_I2C_HELPER_TPM_STS_BURST_COUNT_MASK = (0xFFFF << TCTI_I2C_HELPER_TPM_STS_BURST_COUNT_SHIFT),
    TCTI_I2C_HELPER_TPM_STS_VALID = (1 << 7),
    TCTI_I2C_HELPER_TPM_STS_COMMAND_READY = (1 << 6),
    TCTI_I2C_HELPER_TPM_STS_GO = (1 << 5),
    TCTI_I2C_HELPER_TPM_STS_DATA_AVAIL = (1 << 4),
    TCTI_I2C_HELPER_TPM_STS_DATA_EXPECT = (1 << 3)
};

enum TCTI_I2C_HELPER_FIFO_TRANSFER_DIRECTION {
    TCTI_I2C_HELPER_FIFO_TRANSMIT = 0,
    TCTI_I2C_HELPER_FIFO_RECEIVE = 1
};

enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE {
    TCTI_I2C_HELPER_REGISTER_WRITE = 0,
    TCTI_I2C_HELPER_REGISTER_READ = 1
};

#endif /* TCTI_I2C_HELPER_H */
