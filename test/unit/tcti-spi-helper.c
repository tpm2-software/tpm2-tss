/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2022, Infineon Technologies AG
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>              // for int32_t
#include <stdbool.h>               // for false, true, bool
#include <stdio.h>                 // for NULL, size_t
#include <stdlib.h>                // for free, calloc, malloc
#include <string.h>                // for memcpy, memcmp

#include "../helper/cmocka_all.h"                // for assert_int_equal, assert_true, ass...
#include "tss2-tcti/tcti-common.h"      // for TCTI_STATE_RECEIVE, TCTI_VERSION
#include "tss2-tcti/tcti-helper-common.h"
#include "tss2-tcti/tcti-spi-helper.h"
#include "tss2_common.h"           // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_TCT...
#include "tss2_tcti.h"             // for TSS2_TCTI_CONTEXT
#include "tss2_tcti_spi_helper.h"  // for Tss2_Tcti_Spi_Helper_Init, TSS2_TC...

/*
 * The goal is to verify the SPI communication protocol implementation by checking
 * the order in which platform functions are invoked when using functions in the
 * TCTI_HELPER_COMMON_CONTEXT (such as sleep_ms, start_timeout, timeout_expired,
 * read_reg, and write_reg).
 *
 * The audit arrays (e.g., audit_general, audit_no_wait_state_write_reg) contain this
 * information. Each entry specifies the expected platform function to be invoked,
 * the command to be received, or the response to be written back in a specific order.
 * The tester_context.audit_step (audit array index) variable keeps track of the
 * sequence of these operations.
 */

typedef struct {
    void *func;
    char *spi_mosi;
    char *spi_miso;
    union {
        size_t size; /* for platform_spi_transfer */
        int ms; /* for platform_sleep_ms, platform_start_timeout */
        bool is_expired; /* for platform_timeout_expired */
    } u;
} struct_audit;

typedef struct {
    bool with_waitstate;
    int audit_step;
    struct_audit *audit;
} tester_context;

static const unsigned char MISO_NO_WAIT[] = { 0x00, 0x00, 0x00, 0x01 };
static const unsigned char MISO_INSERT_WAIT[] = { 0x00, 0x00, 0x00, 0x00 };

static const unsigned char WRITE_TPM_ACCESS_MOSI[] =
    { 0x00, 0xD4, 0x00, 0x00, 0x82 }; /* tpmRegValidSts = 1, requestUse = 1 */
static const unsigned char WRITE_TPM_STS_MOSI[] =
    { 0x03, 0xD4, 0x00, 0x18, 0x90, 0x00, 0x00, 0x00 }; /* stsValid = 1, dataAvail = 1 */
static const unsigned char WRITE_TPM_DATA_FIFO_MOSI[] =
    { 0x0B, 0xD4, 0x00, 0x24, 0x80, 0x01, 0x00, 0x00,
      0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 }; /* Based on TPM2_Startup command */

static const unsigned char READ_TPM_ACCESS_MOSI[] = { 0x80, 0xD4, 0x00, 0x00, 0x00 };
static const unsigned char READ_TPM_ACCESS_MISO[] = { 0x00, 0x00, 0x00, 0x01, 0x80 }; /* tpmRegValidSts = 1 */

static const unsigned char READ_TPM_STS_MOSI[] =
    { 0x83, 0xD4, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char READ_TPM_STS_MISO[] =
    { 0x00, 0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00 }; /* stsValid = 1, dataAvail = 1 */

static const unsigned char READ_TPM_DATA_FIFO_MOSI[] =
    { 0x89, 0xD4, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char READ_TPM_DATA_FIFO_MISO[] =
    { 0x00, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x24, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00 }; /* Based on TPM2_Startup response */

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

TSS2_RC platform_start_timeout (void *user_data, int32_t milliseconds)
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

TSS2_RC platform_timeout_expired (void *user_data, bool *is_timeout_expired)
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

TSS2_RC platform_spi_acquire (void *user_data)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_spi_acquire, ctx->audit[i].func);
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC platform_spi_release (void *user_data)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_spi_release, ctx->audit[i].func);
    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

TSS2_RC platform_spi_transfer (void *user_data, const void *data_out, void *data_in, size_t cnt)
{
    tester_context *ctx = (tester_context *)user_data;
    int i;

    assert_non_null (ctx);
    i = ctx->audit_step;
    assert_ptr_equal (platform_spi_transfer, ctx->audit[i].func);
    assert_int_equal (cnt, ctx->audit[i].u.size);
    if (ctx->audit[i].spi_mosi) {
        assert_non_null (data_out);
        assert_true (!memcmp (data_out, ctx->audit[i].spi_mosi, cnt));
    } else {
        assert_null (data_out);
    }

    if (ctx->audit[i].spi_miso) {
        assert_non_null (data_in);
        memcpy (data_in, ctx->audit[i].spi_miso, cnt);
    } else {
        assert_null (data_in);
    }

    ctx->audit_step++;

    return TSS2_RC_SUCCESS;
}

void platform_finalize(void *user_data)
{
    assert_non_null (user_data);
    free (user_data);
}

static struct_audit audit_general[] = {
    { platform_sleep_ms, NULL, NULL, POLLING_INTERVAL_MS },
    { platform_start_timeout, NULL, NULL, TIMEOUT_A },
    { platform_timeout_expired, NULL, NULL, true },
    { 0 },
};

static struct_audit audit_no_wait_state_write_reg[] = {
    { platform_spi_transfer, (char *)WRITE_TPM_ACCESS_MOSI, NULL, sizeof (WRITE_TPM_ACCESS_MOSI) },
    { platform_spi_transfer, (char *)WRITE_TPM_STS_MOSI, NULL, sizeof (WRITE_TPM_STS_MOSI) },
    { platform_spi_transfer, (char *)WRITE_TPM_DATA_FIFO_MOSI, NULL, sizeof (WRITE_TPM_DATA_FIFO_MOSI) },
    { 0 },
};

static struct_audit audit_wait_state_write_reg[] = {
    /* TPM_ACCESS */
    { platform_spi_acquire, NULL, NULL, false },
    { platform_spi_transfer, (char *)WRITE_TPM_ACCESS_MOSI, (char *)MISO_INSERT_WAIT, 4 },
    { platform_spi_transfer, "\x00", "\x00", 1 }, /* Insert wait */
    { platform_sleep_ms, NULL, NULL, 1 },
    { platform_spi_transfer, "\x00", "\x01", 1 }, /* Exit wait */
    { platform_spi_transfer, (char *)WRITE_TPM_ACCESS_MOSI + 4, NULL, sizeof (WRITE_TPM_ACCESS_MOSI) - 4 },
    { platform_spi_release, NULL, NULL, false },

    /* TPM_STS */
    { platform_spi_acquire, NULL, NULL, false },
    { platform_spi_transfer, (char *)WRITE_TPM_STS_MOSI, (char *)MISO_NO_WAIT, 4 },
    { platform_spi_transfer, (char *)WRITE_TPM_STS_MOSI + 4, NULL, sizeof (WRITE_TPM_STS_MOSI) - 4 },
    { platform_spi_release, NULL, NULL, false },

    /* TPM_DATA_FIFO */
    { platform_spi_acquire, NULL, NULL, false },
    { platform_spi_transfer, (char *)WRITE_TPM_DATA_FIFO_MOSI, (char *)MISO_NO_WAIT, 4 },
    { platform_spi_transfer, (char *)WRITE_TPM_DATA_FIFO_MOSI + 4, NULL, sizeof (WRITE_TPM_DATA_FIFO_MOSI) - 4 },
    { platform_spi_release, NULL, NULL, false },

    { 0 },
};

static struct_audit audit_no_wait_state_read_reg[] = {
    { platform_spi_transfer, (char *)READ_TPM_ACCESS_MOSI, (char *)READ_TPM_ACCESS_MISO, sizeof (READ_TPM_ACCESS_MOSI) },
    { platform_spi_transfer, (char *)READ_TPM_STS_MOSI, (char *)READ_TPM_STS_MISO, sizeof (READ_TPM_STS_MOSI) },
    { platform_spi_transfer, (char *)READ_TPM_DATA_FIFO_MOSI, (char *)READ_TPM_DATA_FIFO_MISO, sizeof (READ_TPM_DATA_FIFO_MOSI) },
    { 0 },
};

static struct_audit audit_wait_state_read_reg[] = {
    /* TPM_ACCESS */
    { platform_spi_acquire, NULL, NULL, false },
    { platform_spi_transfer, (char *)READ_TPM_ACCESS_MOSI, (char *)MISO_INSERT_WAIT, 4 },
    { platform_spi_transfer, "\x00", "\x00", 1 }, /* Insert wait */
    { platform_sleep_ms, NULL, NULL, 1 },
    { platform_spi_transfer, "\x00", "\x01", 1 }, /* Exit wait */
    { platform_spi_transfer, NULL, (char *)READ_TPM_ACCESS_MISO + 4, sizeof (READ_TPM_ACCESS_MISO) - 4 },
    { platform_spi_release, NULL, NULL, false },

    /* TPM_STS */
    { platform_spi_acquire, NULL, NULL, false },
    { platform_spi_transfer, (char *)READ_TPM_STS_MOSI, (char *)MISO_NO_WAIT, 4 },
    { platform_spi_transfer, NULL, (char *)READ_TPM_STS_MISO + 4, sizeof (READ_TPM_STS_MISO) - 4 },
    { platform_spi_release, NULL, NULL, false },

    /* TPM_DATA_FIFO */
    { platform_spi_acquire, NULL, NULL, false },
    { platform_spi_transfer, (char *)READ_TPM_DATA_FIFO_MOSI, (char *)MISO_NO_WAIT, 4 },
    { platform_spi_transfer, NULL, (char *)READ_TPM_DATA_FIFO_MISO + 4, sizeof (READ_TPM_DATA_FIFO_MISO) - 4 },
    { platform_spi_release, NULL, NULL, false },

    { 0 },
};

TSS2_RC __wrap_Tcti_Helper_Common_Init (TCTI_HELPER_COMMON_CONTEXT *ctx, bool is_i2c)
{
    (void) is_i2c;
    bool is_timeout_expired = false;
    uint8_t response[128] = { 0 };
    TSS2_TCTI_SPI_HELPER_CONTEXT *spi_helper_ctx;
    TSS2_TCTI_SPI_HELPER_PLATFORM *spi_helper_platform;
    tester_context *tester_ctx;

    assert_non_null (ctx);
    assert_non_null (ctx->sleep_ms);
    assert_non_null (ctx->start_timeout);
    assert_non_null (ctx->timeout_expired);
    assert_non_null (ctx->write_reg);
    assert_non_null (ctx->read_reg);

    spi_helper_ctx = (TSS2_TCTI_SPI_HELPER_CONTEXT *)ctx->data;
    assert_non_null (spi_helper_ctx);

    spi_helper_platform = &spi_helper_ctx->platform;
    assert_non_null (spi_helper_platform);

    tester_ctx = (tester_context *)spi_helper_platform->user_data;
    assert_non_null (tester_ctx);

    /* Testing TCTI_HELPER_COMMON_CONTEXT's sleep_ms, start_timout, timeout_expired */

    tester_ctx->audit_step = 0;
    tester_ctx->audit = audit_general;

    assert_int_equal (ctx->sleep_ms (ctx->data, POLLING_INTERVAL_MS), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->start_timeout (ctx->data, TIMEOUT_A), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->timeout_expired (ctx->data, &is_timeout_expired), TSS2_RC_SUCCESS);
    assert_true (is_timeout_expired);

    /* Testing TCTI_HELPER_COMMON_CONTEXT's write_reg (TPM_ACCESS, TPM_STS, TPM_DATA_FIFO) */

    tester_ctx->audit_step = 0;
    if (tester_ctx->with_waitstate) {
        tester_ctx->audit = audit_wait_state_write_reg;
    } else {
        tester_ctx->audit = audit_no_wait_state_write_reg;
    }

    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_ACCESS,
        &WRITE_TPM_ACCESS_MOSI[4], 1), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_STS,
        &WRITE_TPM_STS_MOSI[4], sizeof (WRITE_TPM_STS_MOSI) - 4), TSS2_RC_SUCCESS);
    assert_int_equal (ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO,
        &WRITE_TPM_DATA_FIFO_MOSI[4], sizeof (WRITE_TPM_DATA_FIFO_MOSI) - 4), TSS2_RC_SUCCESS);

    /* Testing TCTI_HELPER_COMMON_CONTEXT's read_reg (TPM_ACCESS, TPM_STS, TPM_DATA_FIFO) */

    tester_ctx->audit_step = 0;
    if (tester_ctx->with_waitstate) {
        tester_ctx->audit = audit_wait_state_read_reg;
    } else {
        tester_ctx->audit = audit_no_wait_state_read_reg;
    }

    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_ACCESS, response, 1), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, &READ_TPM_ACCESS_MISO[4], sizeof (READ_TPM_ACCESS_MISO) - 4));

    memset (response, 0, sizeof (response));
    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_STS, response,
        sizeof (READ_TPM_STS_MOSI) - 4), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, &READ_TPM_STS_MISO[4], sizeof (READ_TPM_STS_MISO) - 4));

    memset (response, 0, sizeof (response));
    assert_int_equal (ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, response,
        sizeof (READ_TPM_DATA_FIFO_MOSI) - 4), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, &READ_TPM_DATA_FIFO_MISO[4], sizeof (READ_TPM_DATA_FIFO_MISO) - 4));

    return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Tcti_Helper_Common_Transmit (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t size,
    const uint8_t *cmd_buf)
{
    assert_non_null (ctx);
    assert_int_equal (size, sizeof (TPM2_STARTUP_CMD));
    assert_ptr_equal (cmd_buf, TPM2_STARTUP_CMD);

    return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Tcti_Helper_Common_Receive (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t *response_size,
    unsigned char *response_buffer, int32_t timeout)
{
    assert_int_equal (timeout, TIMEOUT_A);
    assert_non_null (ctx);
    assert_non_null (response_size);

    if (!response_buffer) {
        *response_size = sizeof (TPM2_STARTUP_RESP);
    } else {
        assert_int_equal (*response_size, sizeof (TPM2_STARTUP_RESP));
        memcpy (response_buffer, TPM2_STARTUP_RESP, sizeof (TPM2_STARTUP_RESP));
    }

    return TSS2_RC_SUCCESS;
}

static TSS2_TCTI_SPI_HELPER_PLATFORM
create_tcti_spi_helper_platform (bool wait_state)
{
    TSS2_TCTI_SPI_HELPER_PLATFORM platform = {};

    /* Create tester context */
    tester_context *tester_ctx = calloc (1, sizeof (tester_context));
    tester_ctx->with_waitstate = wait_state;

    /* Create TCTI SPI platform struct with custom platform methods */
    platform.user_data = (void *) tester_ctx;
    platform.sleep_ms = platform_sleep_ms;
    platform.start_timeout = platform_start_timeout;
    platform.timeout_expired = platform_timeout_expired;
    if (wait_state) {
        platform.spi_acquire = platform_spi_acquire;
        platform.spi_release = platform_spi_release;
    } else {
        platform.spi_acquire = NULL;
        platform.spi_release = NULL;
    }
    platform.spi_transfer = platform_spi_transfer;
    platform.finalize = platform_finalize;

    return platform;
}

static void
tcti_spi_success_test (void **state, bool with_wait_state)
{
    TSS2_RC rc;
    size_t size;
    uint8_t response[sizeof (TPM2_STARTUP_RESP)] = { 0 };
    TSS2_TCTI_SPI_HELPER_PLATFORM tcti_platform = { 0 };
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    tcti_platform = create_tcti_spi_helper_platform (with_wait_state);
    rc = Tss2_Tcti_Spi_Helper_Init (tcti_ctx, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Verify the TCTI core functions */
    assert_int_equal (TSS2_TCTI_MAGIC (tcti_ctx), TCTI_SPI_HELPER_MAGIC);
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
tcti_spi_no_wait_state_success_test (void **state)
{
    tcti_spi_success_test (state, false);
}

static void
tcti_spi_with_wait_state_success_test (void **state)
{
    tcti_spi_success_test (state, true);
}

static void
tcti_spi_bad_callbacks_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_SPI_HELPER_PLATFORM tcti_platform = {};
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    tcti_platform = create_tcti_spi_helper_platform (false);
    tcti_platform.sleep_ms = NULL;
    rc = Tss2_Tcti_Spi_Helper_Init (tcti_ctx, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);

    free (tcti_platform.user_data);
    free (tcti_ctx);
}

static void
tcti_spi_wait_state_bad_callbacks_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_SPI_HELPER_PLATFORM tcti_platform = {};
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Helper_Init (NULL, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    tcti_platform = create_tcti_spi_helper_platform (true);
    tcti_platform.spi_acquire = NULL;
    rc = Tss2_Tcti_Spi_Helper_Init (tcti_ctx, &size, &tcti_platform);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);

    free (tcti_platform.user_data);
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_no_wait_state_success_test),
        cmocka_unit_test (tcti_spi_with_wait_state_success_test),
        cmocka_unit_test (tcti_spi_bad_callbacks_test),
        cmocka_unit_test (tcti_spi_wait_state_bad_callbacks_test)
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
