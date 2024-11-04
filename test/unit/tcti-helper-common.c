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
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>                   // for uint8_t, int32_t
#include <stdbool.h>                    // for false, bool, true
#include <stdio.h>                      // for NULL, size_t
#include <stdlib.h>                     // for free, calloc, malloc
#include <string.h>                     // for memcpy, strncmp

#include "../helper/cmocka_all.h"                     // for assert_int_equal, assert_stri...
#include "tss2-tcti/tcti-common.h"      // for TCTI_STATE_RECEIVE, TCTI_VERSION
#include "tss2-tcti/tcti-helper-common.h"
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC, TSS...
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT, TSS2_TCTI_...

typedef struct {
    void *func;
    enum TCTI_HELPER_COMMON_REG reg;
    char *buffer;
    union {
        size_t size; /* for callback_read_reg, callback_write_reg */
        int ms; /* for callback_sleep_ms, callback_start_timeout */
        bool is_expired; /* for callback_timeout_expired */
    } u;
} struct_audit;

typedef struct {
    TCTI_HELPER_COMMON_CONTEXT helper_common;
    int audit_step;
    struct_audit *audit;
} tester_context;

static TSS2_RC callback_sleep_ms (void *data, int milliseconds);
static TSS2_RC callback_start_timeout (void *data, int milliseconds);
static TSS2_RC callback_timeout_expired (void *data, bool *result);
static TSS2_RC callback_read_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, void *buffer, size_t cnt);
static TSS2_RC callback_write_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, const void *buffer, size_t cnt);

/* TPM2_Startup command and response */
static const unsigned char TPM2_STARTUP_CMD[] =
    { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
static const unsigned char TPM2_STARTUP_RESP[] =
    { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00 };

/*
 * The goal is to verify the TPM 2.0 FIFO communication protocol implementation by checking the order
 * in which the callbacks are invoked. The audit arrays (audit_init, audit_transmission, audit_receive)
 * contain this information. Each entry specifies the expected callback to be invoked, the command to
 * be received, or the response to be written back in a specific order. The tester_context.audit_step
 * (audit array index) variable keeps track of the sequence of these operations.
 *
 * The audit arrays are implementated based on the TCG PC Client Device Driver Design Principles for TPM 2.0:
 * - Send Command using the FIFO Protocol
 * - Receive Response using the FIFO Protocol
 *
 * Clarification:
 * - callback_read_reg: Host library read data from a TPM register
 * - callback_write_reg: Host library write data to a TPM register
 */

static struct_audit audit_spi_init[] = {
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DID_VID, "\x00\x00\x00\x00", 4 }, /* Return TPM_DID_VID = 0x00000000 */
    { callback_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DID_VID, "\xd1\x15\x1b\x00", 4 }, /* Return TPM_DID_VID = 0xD1151B00 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_ACCESS, "\x80", 1 }, /* Return tpmRegValidSts = 1 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_ACCESS, "\x02", 1 }, /* Verify requestUse == 1 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_ACCESS, "\xA0", 1 }, /* Return tpmRegValidSts = 1, activeLocality = 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_B },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x00\x00\x00\x00", 4 }, /* Return commandReady = 0 */
    { callback_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { callback_timeout_expired, 0, NULL, true }, /* timeout occurred */

    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Verify commandReady == 1*/

    { callback_start_timeout, 0, NULL, TIMEOUT_B },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Return commandReady = 1 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_RID, "\x00", 1 }, /* Return TPM_RID */

    { 0 },
};

static struct_audit audit_i2c_init[] = {
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DID_VID, "\x00\x00\x00\x00", 4 }, /* Return TPM_DID_VID = 0x00000000 */
    { callback_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DID_VID, "\xd1\x15\x1b\x00", 4 }, /* Return TPM_DID_VID = 0xD1151B00 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_I2C_INTF_CAP,
      "\x00\xf4\x1f\x00", 4 }, /* Return GUARD_TIME = TCTI_I2C_HELPER_DEFAULT_GUARD_TIME_US, RR = RW = WR = WW = 1 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM_ENABLE, "\x00", 1 }, /* Return dataCSumEnable = 0 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM_ENABLE, "\x01", 1 }, /* Return dataCSumEnable = 1 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_ACCESS, "\x80", 1 }, /* Return tpmRegValidSts = 1 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_ACCESS, "\x02", 1 }, /* Verify requestUse == 1 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_ACCESS, "\xA0", 1 }, /* Return tpmRegValidSts = 1, activeLocality = 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_B },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x00\x00\x00\x00", 4 }, /* Return commandReady = 0 */
    { callback_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { callback_timeout_expired, 0, NULL, true }, /* timeout occurred */

    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Verify commandReady == 1*/

    { callback_start_timeout, 0, NULL, TIMEOUT_B },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Return commandReady = 1 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_RID, "\x00", 1 }, /* Return TPM_RID */

    { 0 },
};

static struct_audit audit_spi_transmission[] = {
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Verify commandReady == 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_B },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Return commandReady = 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x00\xFF\x00\x00", 4 }, /* Return burstCount = 0x00FF */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
      (char *)TPM2_STARTUP_CMD, 1 }, /* Verify incoming TPM_DATA_FIFO (1st byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\x00\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount = 0 */
    { callback_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { callback_timeout_expired, 0, NULL, false }, /* To retry without a timeout occurring */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\x01\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount  = 1 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_CMD + 1, 1 }, /* Verify incoming TPM_DATA_FIFO (2nd byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\xFF\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount  = 255 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_CMD + 2,
      sizeof (TPM2_STARTUP_CMD) - 3 }, /* Verify incoming TPM_DATA_FIFO (all but the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\xFF\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount  = 255 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
      (char *)TPM2_STARTUP_CMD + sizeof (TPM2_STARTUP_CMD) - 1, 1 }, /* Verify incoming TPM_DATA_FIFO (the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x80\x00\x00\x00", 4 }, /* Return stsValid = 1, Expect = 0 */

    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x20\x00\x00\x00", 4 }, /* Verify tpmGo == 1 */

    { 0 },
};

static struct_audit audit_i2c_transmission[] = {
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Verify commandReady == 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_B },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Return commandReady = 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x00\xFF\x00\x00", 4 }, /* Return burstCount = 0x00FF */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_CMD, 1 }, /* Verify incoming TPM_DATA_FIFO (1st byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\x00\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount = 0 */
    { callback_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { callback_timeout_expired, 0, NULL, false }, /* To retry without a timeout occurring */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\x01\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount  = 1 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_CMD + 1, 1 }, /* Verify incoming TPM_DATA_FIFO (2nd byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\xFF\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount  = 255 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_CMD + 2,
      sizeof (TPM2_STARTUP_CMD) - 3 }, /* Verify incoming TPM_DATA_FIFO (all but the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x88\xFF\x00\x00", 4 }, /* Return stsValid = 1, Expect = 1, burstCount  = 255 */
    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
      (char *)TPM2_STARTUP_CMD + sizeof (TPM2_STARTUP_CMD) - 1, 1 }, /* Verify incoming TPM_DATA_FIFO (the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x80\x00\x00\x00", 4 }, /* Return stsValid = 1, Expect = 0 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM, "\x33\x67", 2 }, /* Return CRC-16/KERMIT value of TPM2_STARTUP_CMD */

    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x20\x00\x00\x00", 4 }, /* Verify tpmGo == 1 */

    { 0 },
};

static struct_audit audit_spi_receive[] = {
    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x00\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x02\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 2 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP, 2 }, /* Return TPM_DATA_FIFO (first 2 bytes) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\xFF\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 255 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP + 2,
      TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE - 2 }, /* Return TPM_DATA_FIFO (next 4 bytes) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x34\x12\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 4660 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP + TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE,
      sizeof (TPM2_STARTUP_RESP) - TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE - 1 }, /* Return TPM_DATA_FIFO (all but the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x34\x12\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 4660 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP + sizeof (TPM2_STARTUP_RESP) - 1,
      1 }, /* Return TPM_DATA_FIFO (the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x80\x00\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 0 */

    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Verify commandReady == 1 */

    { 0 },
};

static struct_audit audit_i2c_receive[] = {
    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x00\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 1 */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x02\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 2 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP, 2 }, /* Return TPM_DATA_FIFO (first 2 bytes) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\xFF\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 255 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP + 2,
      TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE - 2 }, /* Return TPM_DATA_FIFO (next 4 bytes) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x34\x12\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 4660 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP + TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE,
      sizeof (TPM2_STARTUP_RESP) - TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE - 1 }, /* Return TPM_DATA_FIFO (all but the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x90\x34\x12\x00", 4 }, /* Return stsValid = 1, dataAvail = 1, burstCount = 4660 */
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP + sizeof (TPM2_STARTUP_RESP) - 1,
      1 }, /* Return TPM_DATA_FIFO (the last byte) */

    { callback_start_timeout, 0, NULL, TIMEOUT_A },
    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x80\x00\x00\x00", 4 }, /* Return stsValid = 1, dataAvail = 0 */

    { callback_read_reg, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM, "\xa3\xa3", 2 }, /* Return CRC-16/KERMIT value of TPM2_STARTUP_RESP */

    { callback_write_reg, TCTI_HELPER_COMMON_REG_TPM_STS, "\x40\x00\x00\x00", 4 }, /* Verify commandReady == 1 */

    { 0 },
};

static TSS2_RC callback_sleep_ms (void *data, int milliseconds)
{
    tester_context *ctx = (tester_context *)data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;

    assert_ptr_equal (callback_sleep_ms, ctx->audit[i].func);
    assert_int_equal (milliseconds, ctx->audit[i].u.ms);

    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC callback_start_timeout (void *data, int milliseconds)
{
    tester_context *ctx = (tester_context *)data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;

    assert_ptr_equal (callback_start_timeout, ctx->audit[i].func);
    assert_int_equal (milliseconds, ctx->audit[i].u.ms);

    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC callback_timeout_expired (void *data, bool *result)
{
    tester_context *ctx = (tester_context *)data;
    int i;

    assert_non_null (ctx);
    assert_non_null (result);
    i = ctx->audit_step;

    assert_ptr_equal (callback_timeout_expired, ctx->audit[i].func);

    *result = ctx->audit[i].u.is_expired;

    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC callback_read_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, void *buffer, size_t cnt)
{
    tester_context *ctx = (tester_context *)data;
    int i;

    assert_non_null (ctx);
    assert_non_null (buffer);
    i = ctx->audit_step;

    assert_ptr_equal (callback_read_reg, ctx->audit[i].func);
    assert_int_equal (reg, ctx->audit[i].reg);
    assert_int_equal (cnt, ctx->audit[i].u.size);
    memcpy (buffer, ctx->audit[i].buffer, cnt);

    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC callback_write_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, const void *buffer, size_t cnt)
{
    tester_context *ctx = (tester_context *)data;
    int i;

    assert_non_null (ctx);
    assert_non_null (buffer);
    i = ctx->audit_step;

    assert_ptr_equal (callback_write_reg, ctx->audit[i].func);
    assert_int_equal (reg, ctx->audit[i].reg);
    assert_int_equal (cnt, ctx->audit[i].u.size);
    assert_true (!memcmp (buffer, ctx->audit[i].buffer, cnt));

    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

static void
tcti_generic_test (void **state, bool is_i2c)
{
    TSS2_RC rc;
    tester_context tester_ctx = { 0 };
    size_t size = sizeof (TPM2_STARTUP_RESP) + 1;
    unsigned char buffer[sizeof (TPM2_STARTUP_RESP) + 1] = { 0 };

    /* Reset test */
    if (is_i2c) {
        tester_ctx.audit = audit_i2c_init;
    } else {
        tester_ctx.audit = audit_spi_init;
    }
    tester_ctx.audit_step = 0;

    /* Register the callback functions before using the Tcti_Helper_Common_ functions */
    TCTI_HELPER_COMMON_CONTEXT helper_common = {
        .response_size = 0,
        .data = (void *)&tester_ctx,
        .sleep_ms = callback_sleep_ms,
        .start_timeout = callback_start_timeout,
        .timeout_expired = callback_timeout_expired,
        .read_reg = callback_read_reg,
        .write_reg = callback_write_reg,
    };
    tester_ctx.helper_common = helper_common;

    rc = Tcti_Helper_Common_Init (&tester_ctx.helper_common, is_i2c);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Reset test */
    if (is_i2c) {
        tester_ctx.audit = audit_i2c_transmission;
    } else {
        tester_ctx.audit = audit_spi_transmission;
    }
    tester_ctx.audit_step = 0;

    rc = Tcti_Helper_Common_Transmit (&tester_ctx.helper_common, sizeof (TPM2_STARTUP_CMD), TPM2_STARTUP_CMD);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Reset test */
    if (is_i2c) {
        tester_ctx.audit = audit_i2c_receive;
    } else {
        tester_ctx.audit = audit_spi_receive;
    }
    tester_ctx.audit_step = 0;

    rc = Tcti_Helper_Common_Receive (&tester_ctx.helper_common, &size, buffer, 0);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (size, sizeof (TPM2_STARTUP_RESP));
    assert_true (!memcmp (buffer, TPM2_STARTUP_RESP, sizeof (TPM2_STARTUP_RESP)));
}

static void
tcti_spi_test (void **state)
{
    tcti_generic_test (state, false);
}

static void
tcti_i2c_test (void **state)
{
    tcti_generic_test (state, true);
}

int
main (int   argc,
      char *argv[])
{
    (void) argc;
    (void) argv;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_test),
        cmocka_unit_test (tcti_i2c_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
