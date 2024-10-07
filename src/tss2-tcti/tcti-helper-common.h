/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Infineon Technologies AG
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

#ifndef TCTI_HELPER_COMMON_H
#define TCTI_HELPER_COMMON_H
#include "tss2_tcti.h"

#define TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE (sizeof (TPM2_ST) + sizeof (UINT32))

#define POLLING_INTERVAL_MS 8

/* The default timeout value in milliseconds as specified in the TCG spec */
#define TIMEOUT_A 750
#define TIMEOUT_B 2000

#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_US_DEFAULT       250

#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_SR_MASK          0x40000000
#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_RR_MASK          0x00100000
#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_RW_MASK          0x00080000
#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_WR_MASK          0x00040000
#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_WW_MASK          0x00020000
#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_MASK             0x0001FE00
#define TCTI_HELPER_COMMON_I2C_GUARD_TIME_SHIFT            9

#define TCTI_HELPER_COMMON_TPM_I2C_INTF_CAP_ZERO_MASK      0x80000000
#define TCTI_HELPER_COMMON_TPM_STS_ZERO_MASK               0x23
#define TCTI_HELPER_COMMON_TPM_ACCESS_ZERO_MASK            0x48

enum TCTI_HELPER_COMMON_TPM_ACCESS {
    TCTI_HELPER_COMMON_TPM_ACCESS_VALID = (1 << 7),
    TCTI_HELPER_COMMON_TPM_ACCESS_ACTIVE_LOCALITY = (1 << 5),
    TCTI_HELPER_COMMON_TPM_ACCESS_REQUEST_USE = (1 << 1)
};

enum TCTI_HELPER_COMMON_TPM_STATUS {
    TCTI_HELPER_COMMON_TPM_STS_BURST_COUNT_SHIFT = 8,
    TCTI_HELPER_COMMON_TPM_STS_BURST_COUNT_MASK = (0xFFFF << TCTI_HELPER_COMMON_TPM_STS_BURST_COUNT_SHIFT),
    TCTI_HELPER_COMMON_TPM_STS_VALID = (1 << 7),
    TCTI_HELPER_COMMON_TPM_STS_COMMAND_READY = (1 << 6),
    TCTI_HELPER_COMMON_TPM_STS_GO = (1 << 5),
    TCTI_HELPER_COMMON_TPM_STS_DATA_AVAIL = (1 << 4),
    TCTI_HELPER_COMMON_TPM_STS_DATA_EXPECT = (1 << 3)
};

enum TCTI_HELPER_COMMON_REG {
    TCTI_HELPER_COMMON_REG_TPM_STS = 0,
    TCTI_HELPER_COMMON_REG_TPM_ACCESS,
    TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
    TCTI_HELPER_COMMON_REG_TPM_DID_VID,
    TCTI_HELPER_COMMON_REG_TPM_RID,
    TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM,
    TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM_ENABLE,
    TCTI_HELPER_COMMON_REG_TPM_I2C_INTF_CAP,
};

enum TCTI_HELPER_COMMON_FIFO_TRANSFER_DIRECTION {
    TCTI_HELPER_COMMON_FIFO_TRANSMIT_1 = 0,
    TCTI_HELPER_COMMON_FIFO_TRANSMIT_2,
    TCTI_HELPER_COMMON_FIFO_RECEIVE,
};

typedef TSS2_RC (*TCTI_HELPER_COMMON_SLEEP_MS_FUNC) (void *data, int milliseconds);
typedef TSS2_RC (*TCTI_HELPER_COMMON_START_TIMEOUT_FUNC) (void *data, int milliseconds);
typedef TSS2_RC (*TCTI_HELPER_COMMON_TIMEOUT_EXPIRED_FUNC) (void *data, bool *result);
typedef TSS2_RC (*TCTI_HELPER_COMMON_READ_REG_FUNC) (void *data, enum TCTI_HELPER_COMMON_REG reg, void *buffer, size_t cnt);
typedef TSS2_RC (*TCTI_HELPER_COMMON_WRITE_REG_FUNC) (void *data, enum TCTI_HELPER_COMMON_REG reg, const void *buffer, size_t cnt);

typedef struct {
    uint8_t header[TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE];
    uint32_t response_size;

    bool is_i2c;
    bool i2c_guard_time_read;
    bool i2c_guard_time_write;
    uint8_t  i2c_guard_time;

    void *data;
    TCTI_HELPER_COMMON_SLEEP_MS_FUNC sleep_ms;
    TCTI_HELPER_COMMON_START_TIMEOUT_FUNC start_timeout;
    TCTI_HELPER_COMMON_TIMEOUT_EXPIRED_FUNC timeout_expired;
    TCTI_HELPER_COMMON_READ_REG_FUNC read_reg;
    TCTI_HELPER_COMMON_WRITE_REG_FUNC write_reg;
} TCTI_HELPER_COMMON_CONTEXT;

TSS2_RC Tcti_Helper_Common_Init (TCTI_HELPER_COMMON_CONTEXT *ctx, bool is_i2c);
TSS2_RC Tcti_Helper_Common_Transmit (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t size, const uint8_t *cmd_buf);
TSS2_RC Tcti_Helper_Common_Receive (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t *response_size, unsigned char *response_buffer, int32_t timeout);

#endif /* TCTI_HELPER_COMMON_H */
