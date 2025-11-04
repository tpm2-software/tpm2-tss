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
#include "tss2-tcti/tcti-i2c-helper.h"  // for TCTI_I2C_HELPER_TPM_STS_REG
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC, TSS...
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT, TSS2_TCTI_...
#include "tss2_tcti_i2c_helper.h"       // for TSS2_TCTI_I2C_HELPER_PLATFORM

#define DUMMY_PLATFORM_DATA "my platform data"

typedef enum {
    /* Tss2_Tcti_I2c_Helper_Init () */
    R_TPM_DID_VID = 0,
    R_TPM_INTERFACE_CAP,
    R_TPM_ACCESS,
    R_TPM_CSUM_ENABLE,
    W_TPM_CSUM_ENABLE,
    R_TPM_STS_00,
    R_TPM_RID,
    /* TSS2_TCTI_TRANSMIT () */
    W_TPM_STS_00,
    R_TPM_STS_01,
    R_TPM_STS_02,
    W_TPM_FIFO,
    R_TPM_CSUM_00,
    W_TPM_STS_01,
    /* TSS2_TCTI_RECEIVE (); is_timeout_blocked == true */
    R_TPM_STS_03,
    R_TPM_STS_04,
    R_TPM_FIFO_00,
    R_TPM_STS_05,
    R_TPM_FIFO_01,
    R_TPM_STS_06,
    R_TPM_FIFO_02,
    R_TPM_STS_07,
    R_TPM_CSUM_01,
    W_TPM_STS_02,
    /* TSS2_TCTI_RECEIVE (); is_timeout_blocked == false */
    R_TPM_STS_08
} tpm_state_t;

static const uint8_t R_TPM_DID_VID_DATA[] = {0xd1, 0x15, 0x1b, 0x00};
static const uint8_t R_TPM_INTERFACE_CAP_DATA[] = {0x82, 0x00, 0xe0, 0x1a};
static const uint8_t R_TPM_ACCESS_DATA[] = {0xa1};
static const uint8_t R_TPM_CSUM_ENABLE_DATA[] = {0x00};
static const uint8_t R_TPM_RID_DATA[] = {0x00};
static const uint8_t R_TPM_STS_00_01_DATA[] = {TCTI_I2C_HELPER_TPM_STS_COMMAND_READY, 0x00, 0x00, 0x00};
static const uint8_t R_TPM_STS_02_05_DATA[] = {0x00, 0x40, 0x00, 0x00};
static const uint8_t R_TPM_STS_04_06_DATA[] = {TCTI_I2C_HELPER_TPM_STS_VALID | TCTI_I2C_HELPER_TPM_STS_DATA_AVAIL,
                                               0x00, 0x00, 0x00};
static const uint8_t R_TPM_CSUM_DATA[] = {0xf7, 0x4b}; /* CRC-16 (KERMIT) of RW_TPM_FIFO_DATA */
static const uint8_t R_TPM_STS_03_07_08_DATA[] = {TCTI_I2C_HELPER_TPM_STS_VALID, 0x00, 0x00, 0x00};
static const uint8_t W_TPM_STS_00_02_DATA[] = {TCTI_I2C_HELPER_TPM_STS_COMMAND_READY, 0x00, 0x00, 0x00};
static const uint8_t W_TPM_STS_01_DATA[] = {TCTI_I2C_HELPER_TPM_STS_GO, 0x00, 0x00, 0x00};
static const uint8_t W_TPM_CSUM_ENABLE_DATA[] = {0x01};
static const uint8_t RW_TPM_FIFO_DATA[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xde, 0xad, 0xbe, 0xef};

static tpm_state_t tpm_state;
static bool is_timeout_blocked;

TSS2_RC
platform_sleep_us (void* user_data, int32_t microseconds)
{
    (void) microseconds;
    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_sleep_ms (void* user_data, int32_t milliseconds)
{
    (void) milliseconds;
    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_start_timeout (void* user_data, int32_t milliseconds)
{
    (void) milliseconds;
    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_timeout_expired (void* user_data, bool *is_timeout_expired)
{
    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    *is_timeout_expired = (is_timeout_blocked) ? false : true;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_i2c_write (void *user_data, uint8_t reg_addr, const void *data, size_t cnt)
{
    size_t data_len = 0;

    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    assert_non_null (data);

    switch (tpm_state++) {
    case W_TPM_CSUM_ENABLE:
        data_len = sizeof (W_TPM_CSUM_ENABLE_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG);
        assert_int_equal (strncmp ((const void *)W_TPM_CSUM_ENABLE_DATA, data, data_len), 0);
        break;
    case W_TPM_STS_00:
    case W_TPM_STS_02:
        data_len = sizeof (W_TPM_STS_00_02_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_STS_REG);
        assert_int_equal (strncmp ((const void *)W_TPM_STS_00_02_DATA, data, data_len), 0);
        break;
    case W_TPM_STS_01:
        data_len = sizeof (W_TPM_STS_01_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_STS_REG);
        assert_int_equal (strncmp ((const void *)W_TPM_STS_01_DATA, data, data_len), 0);
        break;
    case W_TPM_FIFO:
        data_len = sizeof (RW_TPM_FIFO_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG);
        assert_int_equal (strncmp ((const void *)RW_TPM_FIFO_DATA, data, data_len), 0);
        break;
    default:
        assert_true (false);
    }

    assert_int_equal (cnt, data_len);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_i2c_read (void* user_data, uint8_t reg_addr, void *data, size_t cnt)
{
    size_t data_len = 0;

    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    assert_non_null (data);

    switch (tpm_state++) {
    case R_TPM_DID_VID:
        data_len = sizeof (R_TPM_DID_VID_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DID_VID_REG);
        memcpy (data, R_TPM_DID_VID_DATA, data_len);
        break;
    case R_TPM_INTERFACE_CAP:
        data_len = sizeof (R_TPM_INTERFACE_CAP_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_REG);
        memcpy (data, R_TPM_INTERFACE_CAP_DATA, data_len);
        break;
    case R_TPM_ACCESS:
        data_len = sizeof (R_TPM_ACCESS_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_ACCESS_REG);
        memcpy (data, R_TPM_ACCESS_DATA, data_len);
        break;
    case R_TPM_CSUM_ENABLE:
        data_len = sizeof (R_TPM_CSUM_ENABLE_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG);
        memcpy (data, R_TPM_CSUM_ENABLE_DATA, data_len);
        break;
    case R_TPM_RID:
        data_len = sizeof (R_TPM_RID_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_RID_REG);
        memcpy (data, R_TPM_RID_DATA, data_len);
        break;
    case R_TPM_STS_00:
    case R_TPM_STS_01:
        data_len = sizeof (R_TPM_STS_00_01_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_STS_REG);
        memcpy (data, R_TPM_STS_00_01_DATA, data_len);
        break;
    case R_TPM_STS_02:
    case R_TPM_STS_05:
        data_len = sizeof (R_TPM_STS_02_05_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_STS_REG);
        memcpy (data, R_TPM_STS_02_05_DATA, data_len);
        break;
    case R_TPM_STS_04:
    case R_TPM_STS_06:
        data_len = sizeof (R_TPM_STS_04_06_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_STS_REG);
        memcpy (data, R_TPM_STS_04_06_DATA, data_len);
        break;
    case R_TPM_STS_03:
    case R_TPM_STS_07:
    case R_TPM_STS_08:
        data_len = sizeof (R_TPM_STS_03_07_08_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_STS_REG);
        memcpy (data, R_TPM_STS_03_07_08_DATA, data_len);
        break;
    case R_TPM_FIFO_00:
        data_len = TCTI_I2C_HELPER_RESP_HEADER_SIZE;
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG);
        memcpy (data, RW_TPM_FIFO_DATA, data_len);
        break;
    case R_TPM_FIFO_01:
        data_len = sizeof (RW_TPM_FIFO_DATA) - 1 - TCTI_I2C_HELPER_RESP_HEADER_SIZE;
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG);
        memcpy (data, RW_TPM_FIFO_DATA + TCTI_I2C_HELPER_RESP_HEADER_SIZE, data_len);
        break;
    case R_TPM_FIFO_02:
        data_len = 1;
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG);
        memcpy (data, RW_TPM_FIFO_DATA + sizeof (RW_TPM_FIFO_DATA) - 1, 1);
        break;
    case R_TPM_CSUM_00:
    case R_TPM_CSUM_01:
        data_len = sizeof (R_TPM_CSUM_DATA);
        assert_int_equal (reg_addr, TCTI_I2C_HELPER_TPM_DATA_CSUM_REG);
        memcpy (data, R_TPM_CSUM_DATA, data_len);
        break;
    default:
        assert_true (false);
    }

    assert_int_equal (cnt, data_len);

    return TSS2_RC_SUCCESS;
}

void
platform_finalize (void* user_data)
{
    assert_string_equal ((const char *) user_data, DUMMY_PLATFORM_DATA);
    free(user_data);
}

TSS2_TCTI_I2C_HELPER_PLATFORM
create_tcti_i2c_helper_platform (void)
{
    TSS2_TCTI_I2C_HELPER_PLATFORM platform = {};

    // Create dummy platform user data
    char *platform_data = malloc (sizeof (DUMMY_PLATFORM_DATA));
    memcpy (platform_data, DUMMY_PLATFORM_DATA, sizeof (DUMMY_PLATFORM_DATA));

    // Create TCTI I2C platform struct with custom platform methods
    platform.user_data = platform_data;
    platform.sleep_us = platform_sleep_us;
    platform.sleep_ms = platform_sleep_ms;
    platform.start_timeout = platform_start_timeout;
    platform.timeout_expired = platform_timeout_expired;
    platform.i2c_write = platform_i2c_write;
    platform.i2c_read = platform_i2c_read;
    platform.finalize = platform_finalize;

    return platform;
}

/*
 * The test will call Tss2_Tcti_I2c_Helper_Init(),
 * which will perform several tasks including reading
 * the TPM_DID_VID, checking locality, reading TPM_STS,
 * and reading TPM_RID before exiting the Init function.
 * The TSS2_TCTI_CONTEXT core functions will be tested as well.
 * For testing purposes, the TPM responses are hardcoded.
 */
static void
tcti_i2c_generic_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    uint8_t response[10] = {0};

    TSS2_TCTI_I2C_HELPER_PLATFORM tcti_platform = {};
    TSS2_TCTI_CONTEXT* tcti_ctx;

    tpm_state = R_TPM_DID_VID;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_I2c_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
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
            tcti_ctx, sizeof (RW_TPM_FIFO_DATA), RW_TPM_FIFO_DATA
        ),
        TSS2_RC_SUCCESS
    );
    size = 0;
    is_timeout_blocked = true;
    assert_int_equal (
        TSS2_TCTI_RECEIVE (tcti_ctx) (
            tcti_ctx, &size, NULL, 200
        ),
        TSS2_RC_SUCCESS
    );
    assert_int_equal (size, sizeof (RW_TPM_FIFO_DATA));
    assert_int_equal (
        TSS2_TCTI_RECEIVE (tcti_ctx) (
            tcti_ctx, &size, response, 200
        ),
        TSS2_RC_SUCCESS
    );
    assert_int_equal (TSS2_TCTI_CANCEL (tcti_ctx) (NULL), TSS2_TCTI_RC_NOT_IMPLEMENTED);
    assert_int_equal (TSS2_TCTI_GET_POLL_HANDLES (tcti_ctx) (NULL, NULL, NULL), TSS2_TCTI_RC_NOT_IMPLEMENTED);
    assert_int_equal (TSS2_TCTI_SET_LOCALITY (tcti_ctx) (NULL, 0), TSS2_TCTI_RC_NOT_IMPLEMENTED);
    assert_int_equal (TSS2_TCTI_MAKE_STICKY (tcti_ctx) (NULL, NULL, 0), TSS2_TCTI_RC_NOT_IMPLEMENTED);

    /* Test the behavior of TSS2_TCTI_RECEIVE() in a timeout condition */
    size = 0;
    is_timeout_blocked = false;
    ((TSS2_TCTI_I2C_HELPER_CONTEXT*)tcti_ctx)->common.state = TCTI_STATE_RECEIVE;
    assert_int_equal (
        TSS2_TCTI_RECEIVE (tcti_ctx) (
            tcti_ctx, &size, NULL, 200
        ),
        TSS2_TCTI_RC_TRY_AGAIN
    );

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
    TSS2_TCTI_CONTEXT* tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_I2c_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
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
