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
#include "tss2-tcti/tcti-i2c-helper.h"  // for TCTI_I2C_HELPER_TPM_STS_REG
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC, TSS...
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT, TSS2_TCTI_...
#include "tss2_tcti_i2c_helper.h"       // for TSS2_TCTI_I2C_HELPER_PLATFORM

/*
 * The goal is to verify the I2C communication protocol implementation by checking
 * the order in which platform functions are invoked when using functions in the
 * TCTI_HELPER_COMMON_CONTEXT (such as sleep_ms, start_timeout, timeout_expired,
 * read_reg, and write_reg).
 *
 * The audit arrays (e.g., audit_general, audit_write_reg) contain this
 * information. Each entry specifies the expected platform function to be invoked,
 * the command to be received, or the response to be written back in a specific order.
 * The tester_context.audit_step (audit array index) variable keeps track of the
 * sequence of these operations.
 */

typedef struct {
    void *func;
    uint8_t reg_addr;
    char *data;
    union {
        size_t size; /* for platform_i_transfer */
        int us; /* for platform_sleep_us */
        int ms; /* for platform_sleep_ms, platform_start_timeout */
        bool is_expired; /* for platform_timeout_expired */
    } u;
} struct_audit;

typedef struct {
    bool with_waitstate;
    int audit_step;
    struct_audit *audit;
} tester_context;

static const unsigned char TPM_DID_VID[] = { 0xD1, 0x15, 0x1B, 0x00 };
static const unsigned char TPM_RID[] = { 0x55 };
static const unsigned char TPM_ACCESS[] = { 0x80 }; /* tpmRegValidSts = 1 */
static const unsigned char TPM_STS_VALID[] = { 0x80, 0x00, 0x00, 0x00 }; /* stsValid = 1 */
static const unsigned char TPM_STS_GO[] = { 0x20, 0x00, 0x00, 0x00 }; /* tpmGo = 1 */

static const unsigned char TPM2_STARTUP_CMD[] =
    { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
static const unsigned char TPM2_STARTUP_RESP[] =
    { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00 };

TSS2_RC platform_sleep_ms (void *user_data, int32_t milliseconds)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_sleep_ms, ctx->audit[i].func);
    assert_int_equal (milliseconds, ctx->audit[i].u.ms);
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_sleep_us (void *user_data, int32_t microseconds)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_sleep_us, ctx->audit[i].func);
    assert_int_equal (microseconds, ctx->audit[i].u.us);
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_start_timeout (void *user_data, int32_t milliseconds)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_start_timeout, ctx->audit[i].func);
    assert_int_equal (milliseconds, ctx->audit[i].u.ms);
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_timeout_expired (void *user_data, bool *is_timeout_expired)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_timeout_expired, ctx->audit[i].func);
    *is_timeout_expired = ctx->audit[i].u.is_expired;
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_i2c_write (void *user_data, uint8_t reg_addr, const void *data, size_t cnt)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_i2c_write, ctx->audit[i].func);
    assert_int_equal (cnt, ctx->audit[i].u.size);
    assert_int_equal (reg_addr, ctx->audit[i].reg_addr);

    assert_non_null (data);
    assert_true (!memcmp (data, ctx->audit[i].data, cnt));
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_i2c_read (void *user_data, uint8_t reg_addr, void *data, size_t cnt)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_i2c_read, ctx->audit[i].func);
    assert_int_equal (cnt, ctx->audit[i].u.size);
    assert_int_equal (reg_addr, ctx->audit[i].reg_addr);

    assert_non_null (data);
    memcpy (data, ctx->audit[i].data, cnt);
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

void
platform_finalize (void *user_data)
{
    assert_non_null (user_data);
    free (user_data);
}

static struct_audit audit_general[] = {
    { platform_sleep_ms, 0, NULL, POLLING_INTERVAL_MS },
    { platform_start_timeout, 0, NULL, TIMEOUT_A },
    { platform_timeout_expired, 0, NULL, true },
    { 0 },
};

static struct_audit audit_write_reg[] = {
    { platform_i2c_write, TCTI_I2C_HELPER_REG_TPM_DID_VID, (char *)TPM_DID_VID, sizeof (TPM_DID_VID) },
    { platform_i2c_write, TCTI_I2C_HELPER_REG_TPM_RID, (char *)TPM_RID, sizeof (TPM_RID) },
    { platform_i2c_write, TCTI_I2C_HELPER_REG_TPM_ACCESS, (char *)TPM_ACCESS, sizeof (TPM_ACCESS) },
    { platform_i2c_write, TCTI_I2C_HELPER_REG_TPM_STS, (char *)TPM_STS_GO, sizeof (TPM_STS_GO) },
    { platform_i2c_write, TCTI_I2C_HELPER_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_CMD, sizeof (TPM2_STARTUP_CMD) },
    { 0 },
};

static struct_audit audit_read_reg[] = {
    { platform_i2c_read, TCTI_I2C_HELPER_REG_TPM_DID_VID, (char *)TPM_DID_VID, sizeof (TPM_DID_VID) },
    { platform_i2c_read, TCTI_I2C_HELPER_REG_TPM_RID, (char *)TPM_RID, sizeof (TPM_RID) },
    { platform_i2c_read, TCTI_I2C_HELPER_REG_TPM_ACCESS, (char *)TPM_ACCESS, sizeof (TPM_ACCESS) },
    { platform_i2c_read, TCTI_I2C_HELPER_REG_TPM_STS, (char *)TPM_STS_VALID, sizeof (TPM_STS_VALID) },
    { platform_i2c_read, TCTI_I2C_HELPER_REG_TPM_DATA_FIFO, (char *)TPM2_STARTUP_RESP, sizeof (TPM2_STARTUP_RESP) },
    { 0 },
};

static struct_audit audit_post_init[] = {
    { 0 },
};

static struct_audit audit_post_transmit[] = {
    { 0 },
};

static struct_audit audit_post_receive[] = {
    { 0 },
};

TSS2_RC __wrap_Tcti_Helper_Common_Init (TCTI_HELPER_COMMON_CONTEXT *ctx, bool is_i2c)
{
    (void) is_i2c;
    bool is_timeout_expired = false;
    uint8_t response[128] = { 0 };
    TSS2_TCTI_I2C_HELPER_CONTEXT *i2c_helper_ctx;
    TSS2_TCTI_I2C_HELPER_PLATFORM *i2c_helper_platform;
    tester_context *tester_ctx;

    assert_non_null (ctx);
    assert_non_null (ctx->sleep_ms);
    assert_non_null (ctx->start_timeout);
    assert_non_null (ctx->timeout_expired);
    assert_non_null (ctx->write_reg);
    assert_non_null (ctx->read_reg);

    i2c_helper_ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *)ctx->data;
    assert_non_null (i2c_helper_ctx);

    i2c_helper_platform = &i2c_helper_ctx->platform;
    assert_non_null (i2c_helper_platform);

    tester_ctx = (tester_context *)i2c_helper_platform->user_data;
    assert_non_null (tester_ctx);

    /* Testing TCTI_HELPER_COMMON_CONTEXT's sleep_ms, start_timout, timeout_expired */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_general;

    assert_int_equal (ctx->sleep_ms (ctx->data, POLLING_INTERVAL_MS), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->start_timeout (ctx->data, TIMEOUT_A), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->timeout_expired (ctx->data, &is_timeout_expired), TSS2_RC_SUCCESS);
    assert_true (is_timeout_expired);

    /* Testing TCTI_HELPER_COMMON_CONTEXT's write_reg (TPM_DID_VID, TPM_RID, TPM_ACCESS, TPM_STS, TPM_DATA_FIFO) */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_write_reg;

    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DID_VID,
        TPM_DID_VID, sizeof (TPM_DID_VID)), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_RID,
        TPM_RID, sizeof (TPM_RID)), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_ACCESS,
        TPM_ACCESS, sizeof (TPM_ACCESS)), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_STS,
        TPM_STS_GO, sizeof (TPM_STS_GO)), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
        TPM2_STARTUP_CMD, sizeof (TPM2_STARTUP_CMD)), TSS2_RC_SUCCESS);

    /* Testing TCTI_HELPER_COMMON_CONTEXT's read_reg (TPM_DID_VID, TPM_RID, TPM_ACCESS, TPM_STS, TPM_DATA_FIFO) */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_read_reg;

    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DID_VID,
        response, sizeof (TPM_DID_VID)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM_DID_VID, sizeof (TPM_DID_VID)));
    memset (response, 0, sizeof (response));

    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_RID,
        response, sizeof (TPM_RID)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM_RID, sizeof (TPM_RID)));
    memset (response, 0, sizeof (response));

    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_ACCESS,
        response, sizeof (TPM_ACCESS)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM_ACCESS, sizeof (TPM_ACCESS)));
    memset (response, 0, sizeof (response));

    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_STS,
        response, sizeof (TPM_STS_VALID)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM_STS_VALID, sizeof (TPM_STS_VALID)));
    memset (response, 0, sizeof (response));

    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
        response, sizeof (TPM2_STARTUP_RESP)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM2_STARTUP_RESP, sizeof (TPM2_STARTUP_RESP)));
    memset (response, 0, sizeof (response));

    /* Post-init test */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_post_init;

    return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Tcti_Helper_Common_Transmit (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t size,
    const uint8_t *cmd_buf)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *i2c_helper_ctx;
    TSS2_TCTI_I2C_HELPER_PLATFORM *i2c_helper_platform;
    tester_context *tester_ctx;

    assert_non_null (ctx);
    assert_int_equal (size, sizeof (TPM2_STARTUP_CMD));
    assert_ptr_equal (cmd_buf, TPM2_STARTUP_CMD);

    i2c_helper_ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *)ctx->data;
    assert_non_null (i2c_helper_ctx);

    i2c_helper_platform = &i2c_helper_ctx->platform;
    assert_non_null (i2c_helper_platform);

    tester_ctx = (tester_context *)i2c_helper_platform->user_data;
    assert_non_null (tester_ctx);

    /* Post-transmit test */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_post_transmit;

    return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Tcti_Helper_Common_Receive (TCTI_HELPER_COMMON_CONTEXT *ctx,
    size_t *response_size, unsigned char *response_buffer, int32_t timeout)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *i2c_helper_ctx;
    TSS2_TCTI_I2C_HELPER_PLATFORM *i2c_helper_platform;
    tester_context *tester_ctx;

    assert_int_equal (timeout, TIMEOUT_A);
    assert_non_null (ctx);
    assert_non_null (response_size);

    if (!response_buffer) {
        *response_size = sizeof (TPM2_STARTUP_RESP);
    } else {
        assert_int_equal (*response_size, sizeof (TPM2_STARTUP_RESP));
        memcpy (response_buffer, TPM2_STARTUP_RESP, sizeof (TPM2_STARTUP_RESP));
    }

    i2c_helper_ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *)ctx->data;
    assert_non_null (i2c_helper_ctx);

    i2c_helper_platform = &i2c_helper_ctx->platform;
    assert_non_null (i2c_helper_platform);

    tester_ctx = (tester_context *)i2c_helper_platform->user_data;
    assert_non_null (tester_ctx);

    /* Post-receive test */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_post_receive;

    return TSS2_RC_SUCCESS;
}

static TSS2_TCTI_I2C_HELPER_PLATFORM
create_tcti_i2c_helper_platform (void)
{
    TSS2_TCTI_I2C_HELPER_PLATFORM platform = { 0 };

    /* Create tester context */
    tester_context *tester_ctx = calloc (1, sizeof (tester_context));

    /* Create TCTI I2C platform struct with custom platform methods */
    platform.user_data = (void *)tester_ctx;
    platform.sleep_us = platform_sleep_us;
    platform.sleep_ms = platform_sleep_ms;
    platform.start_timeout = platform_start_timeout;
    platform.timeout_expired = platform_timeout_expired;
    platform.i2c_write = platform_i2c_write;
    platform.i2c_read = platform_i2c_read;
    platform.finalize = platform_finalize;

    return platform;
}

static void
tcti_i2c_generic_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    uint8_t response[sizeof (TPM2_STARTUP_RESP)] = { 0 };
    TSS2_TCTI_I2C_HELPER_PLATFORM tcti_platform = { 0 };
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_I2c_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    tcti_platform = create_tcti_i2c_helper_platform ();
    rc = Tss2_Tcti_I2c_Helper_Init (tcti_ctx, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Verify the TCTI core functions */

    assert_int_equal (TSS2_TCTI_MAGIC (tcti_ctx), TCTI_I2C_HELPER_MAGIC);
    assert_int_equal (TSS2_TCTI_VERSION (tcti_ctx), TCTI_VERSION);
    assert_int_equal (
        TSS2_TCTI_TRANSMIT (tcti_ctx) (
            tcti_ctx, sizeof (TPM2_STARTUP_CMD), TPM2_STARTUP_CMD
        ),
        TSS2_RC_SUCCESS
    );
    size = 0;
    assert_int_equal (
        TSS2_TCTI_RECEIVE (tcti_ctx) (
            tcti_ctx, &size, NULL, TIMEOUT_A
        ),
        TSS2_RC_SUCCESS
    );
    assert_int_equal (size, sizeof (TPM2_STARTUP_RESP));
    assert_int_equal (
        TSS2_TCTI_RECEIVE (tcti_ctx) (
            tcti_ctx, &size, response, TIMEOUT_A
        ),
        TSS2_RC_SUCCESS
    );
    assert_true (!memcmp (response, TPM2_STARTUP_RESP, sizeof (TPM2_STARTUP_RESP)));
    assert_int_equal (TSS2_TCTI_CANCEL (tcti_ctx) (NULL), TSS2_TCTI_RC_NOT_IMPLEMENTED);
    assert_int_equal (TSS2_TCTI_GET_POLL_HANDLES (tcti_ctx) (NULL, NULL, NULL), TSS2_TCTI_RC_NOT_IMPLEMENTED);
    assert_int_equal (TSS2_TCTI_SET_LOCALITY (tcti_ctx) (NULL, 0), TSS2_TCTI_RC_NOT_IMPLEMENTED);
    assert_int_equal (TSS2_TCTI_MAKE_STICKY (tcti_ctx) (NULL, NULL, 0), TSS2_TCTI_RC_NOT_IMPLEMENTED);

    /* Clean up */
    TSS2_TCTI_FINALIZE (tcti_ctx) (tcti_ctx);
    free (tcti_ctx);
}

static void
tcti_i2c_bad_callbacks_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_I2C_HELPER_PLATFORM tcti_platform = {};
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_I2c_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    tcti_platform = create_tcti_i2c_helper_platform ();
    tcti_platform.sleep_us = NULL;
    tcti_platform.sleep_ms = NULL;
    rc = Tss2_Tcti_I2c_Helper_Init (tcti_ctx, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);

    /* Clean up */
    free (tcti_platform.user_data);
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_i2c_generic_test),
        cmocka_unit_test (tcti_i2c_bad_callbacks_test),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
