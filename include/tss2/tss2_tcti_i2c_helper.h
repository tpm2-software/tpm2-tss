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
#ifndef TSS2_TCTI_I2C_HELPER_HELPER_H
#define TSS2_TCTI_I2C_HELPER_HELPER_H

#include <stdbool.h>
#include "tss2_tcti.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward declaration
 */
typedef struct TSS2_TCTI_I2C_HELPER_PLATFORM TSS2_TCTI_I2C_HELPER_PLATFORM;

/*
 * Sleeps for the specified amount of microseconds
 */
typedef TSS2_RC (*TSS2_TCTI_I2C_HELPER_PLATFORM_SLEEP_US_FUNC) (void* user_data, int microseconds);

/*
 * Sleeps for the specified amount of milliseconds
 */
typedef TSS2_RC (*TSS2_TCTI_I2C_HELPER_PLATFORM_SLEEP_MS_FUNC) (void* user_data, int milliseconds);

/*
 * Starts a timeout timer which expires in the specified amount of milliseconds.
 * This can be done by storing the expire time (now + milliseconds) in the userdata.
 */
typedef TSS2_RC (*TSS2_TCTI_I2C_HELPER_PLATFORM_START_TIMEOUT_FUNC) (void* user_data, int milliseconds);

/*
 * Returns true if the timeout started previously by START_TIMEOUT_FUNC already has expired, false otherwise.
 * This can be done e.g. by comparing the current time and the stored timer expire time.
 * This method will be called often when waiting for timeouts and should be fast.
 */
typedef TSS2_RC (*TSS2_TCTI_I2C_HELPER_PLATFORM_TIMEOUT_EXPIRED_FUNC) (void* user_data, bool *result);

/*
 * Writes cnt bytes from data buffer to the I2C slave.
 */
typedef TSS2_RC (*TSS2_TCTI_I2C_HELPER_PLATFORM_I2C_WRITE_FUNC) (void* user_data, uint8_t reg_addr, const void *data, size_t cnt);

/*
 * Reads cnt bytes from the I2C slave to data buffer.
 */
typedef TSS2_RC (*TSS2_TCTI_I2C_HELPER_PLATFORM_I2C_READ_FUNC) (void* user_data, uint8_t reg_addr, void *data, size_t cnt);

/*
 * Is called by Tss2_Tcti_Finalize right before the TCTI context is destroyed and
 * should free user_data and all resources inside like e.g. I2C device handles.
 */
typedef void (*TSS2_TCTI_I2C_HELPER_PLATFORM_FINALIZE) (void* user_data);

/*
 * Contains user implemented platform methods for the I2C TCTI.
 */
struct TSS2_TCTI_I2C_HELPER_PLATFORM {
    void* user_data;
    TSS2_TCTI_I2C_HELPER_PLATFORM_SLEEP_US_FUNC sleep_us;
    TSS2_TCTI_I2C_HELPER_PLATFORM_SLEEP_MS_FUNC sleep_ms;
    TSS2_TCTI_I2C_HELPER_PLATFORM_START_TIMEOUT_FUNC start_timeout;
    TSS2_TCTI_I2C_HELPER_PLATFORM_TIMEOUT_EXPIRED_FUNC timeout_expired;
    TSS2_TCTI_I2C_HELPER_PLATFORM_I2C_WRITE_FUNC i2c_write;
    TSS2_TCTI_I2C_HELPER_PLATFORM_I2C_READ_FUNC i2c_read;
    TSS2_TCTI_I2C_HELPER_PLATFORM_FINALIZE finalize;
};

/*
 * Initializes the I2C TCTI with a context pointer and platform methods.
 * When the tctiContext pointer is NULL, the needed buffer size is written to *size.
 * platform_conf contains platform methods implemented by the user for I2C
 * communication and timeout handling.
 */
TSS2_RC Tss2_Tcti_I2c_Helper_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    TSS2_TCTI_I2C_HELPER_PLATFORM *platform_conf);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TCTI_I2C_HELPER_HELPER_H */
