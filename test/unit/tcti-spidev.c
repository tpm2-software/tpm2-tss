/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2022, Infineon Technologies AG
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <fcntl.h>                      // for O_RDWR
#include <inttypes.h>                   // for uint8_t
#include <stdbool.h>                    // for false
#include <stdio.h>                      // for NULL, size_t
#include <stdlib.h>                     // for free, calloc
#include <string.h>                     // for memcpy, strncmp
#include <sys/select.h>                 // for fd_set, timeval
#include <sys/time.h>

#include "../helper/cmocka_all.h"                     // for assert_int_equal, assert_memo...

#include <linux/spi/spidev.h>           // for spi_ioc_transfer

#include "tss2-tcti/tcti-spi-helper.h"  // for TSS2_TCTI_SPI_HELPER_CONTEXT
#include "tss2-tcti/tcti-common.h"
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT
#include "tss2_tcti_spi_helper.h"       // for TSS2_TCTI_SPI_HELPER_PLATFORM
#include "tss2_tcti_spidev.h"           // for Tss2_Tcti_Spidev_Init

/*
 * The goal is to verify the spidev implementation by checking
 * the order in which file_operations functions are invoked when using functions in
 * the TSS2_TCTI_SPI_HELPER_PLATFORM (e.g., sleep_ms, start_timeout,
 * timeout_expired, spi_transfer).

 * The audit arrays (e.g., audit_general) contain this information. Each
 * entry specifies the expected function to be invoked, the command
 * to be received, or the response to be written back in a specific order.
 * The tester_context.audit_step (audit array index) variable tracks the
 * sequence of these operations.
 */

#define TIME_MS             450
#define DUMMY_FD            5
#define DUMMY_SPIDEV_PATH   "/dev/spidev0.1"

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TSS2_TCTI_SPI_HELPER_PLATFORM platform;
} TSS2_TCTI_SPI_LTT2GO_TEST_CONTEXT;

typedef struct {
    int nfds;
    void *readfds;
    void *writefds;
    void *exceptfds;
    struct timeval timeout;
} fn_select;

typedef struct {
    struct timeval tv;
    void *tz;
} fn_gettimeofday;

typedef struct {
    char *path;
    int flags;
    int fd;
} fn_open;

typedef struct {
    int fd;
} fn_close;

typedef struct {
    int fd;
    unsigned long request;
    struct spi_ioc_transfer tr;
} fn_ioctl;

typedef struct {
    void *func;
    union {
        fn_select select;
        fn_gettimeofday gtod;
        fn_open open;
        fn_close close;
        fn_ioctl ioctl;
    } args;
} struct_audit;

typedef struct {
    int audit_step;
    struct_audit *audit;
} tester_context;

static tester_context tester_ctx;
static unsigned char TPM2_STARTUP_CMD_MOSI[] =
    { 0x0B, 0xD4, 0x00, 0x24, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
static unsigned char TPM2_STARTUP_CMD_MISO[] =
    { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*
 * Mock function select
 */
int __wrap_select (int nfds, fd_set *readfds,
                   fd_set *writefds,
                   fd_set *exceptfds,
                   struct timeval *timeout)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_select, audit->func);
    assert_int_equal (nfds, audit->args.select.nfds);
    assert_int_equal (readfds, audit->args.select.readfds);
    assert_int_equal (writefds, audit->args.select.writefds);
    assert_int_equal (exceptfds, audit->args.select.exceptfds);
    assert_int_equal (timeout->tv_sec, audit->args.select.timeout.tv_sec);
    assert_int_equal (timeout->tv_usec, audit->args.select.timeout.tv_usec);

    return 0;
}

/*
 * Mock function gettimeofday
 */
int __wrap_gettimeofday (struct timeval *tv,
                         struct timezone *tz)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_gettimeofday, audit->func);
    assert_non_null (tv);
    assert_ptr_equal (tz, audit->args.gtod.tz);

    tv->tv_sec = audit->args.gtod.tv.tv_sec;
    tv->tv_usec = audit->args.gtod.tv.tv_usec;

    return 0;
}

int __real_open(const char *path, int flags);

int __wrap_open(const char *path, int flags)
{
    struct_audit *audit;

    assert_ptr_not_equal(path, NULL);

    if (!!strncmp(path, "/dev/spidev", sizeof("/dev/spidev") - 1))
        return __real_open(path, flags);

    audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_true (!memcmp (path, audit->args.open.path, strlen (DUMMY_SPIDEV_PATH)));
    assert_int_equal(flags, audit->args.open.flags);

    return audit->args.open.fd;
}

int __wrap_close(int fd)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_int_equal(fd, audit->args.close.fd);

    return 0;
}

int __wrap_ioctl(int fd, unsigned long request, struct spi_ioc_transfer *tr)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_int_equal(fd, audit->args.close.fd);
    assert_int_equal (request, audit->args.ioctl.request);

    assert_int_equal (tr->delay_usecs, audit->args.ioctl.tr.delay_usecs);
    assert_int_equal (tr->speed_hz, audit->args.ioctl.tr.speed_hz);
    assert_int_equal (tr->bits_per_word, audit->args.ioctl.tr.bits_per_word);
    assert_int_equal (tr->cs_change, audit->args.ioctl.tr.cs_change);
    assert_int_equal (tr->len, audit->args.ioctl.tr.len);

    if (tr->len) {
        assert_non_null (tr->tx_buf);
        assert_non_null (tr->rx_buf);
        assert_true (!memcmp ((void *)tr->tx_buf, (void *)audit->args.ioctl.tr.tx_buf, tr->len));
        memcpy ((void *)tr->rx_buf, (void *)audit->args.ioctl.tr.rx_buf, tr->len);
    }

    return 0;
}

static struct_audit audit_general[] = {
    /* Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, NULL) */
    { .func = __wrap_open, .args.open = { DUMMY_SPIDEV_PATH, O_RDWR, DUMMY_FD } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's sleep_ms */
    { .func = __wrap_select, .args.select =
      { 0, NULL, NULL, NULL, { (TIME_MS * 1000) / 1000000, (TIME_MS * 1000) % 1000000 } } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's start_timeout */
    { .func = __wrap_gettimeofday, .args.gtod = { { 0, 0 }, NULL } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's timeout_expired */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 1, 0 }, NULL } }, /* Return a value > TIME_MS to trigger a timeout event */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 0, (TIME_MS * 1000) }, NULL } }, /* Return a value <= TIME_MS, no timeout occured */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 0, (TIME_MS * 1000) + 1 }, NULL } }, /* Return a value > TIME_MS to trigger a timeout event */

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's spi_acquire */
    { .func = __wrap_ioctl, .args.ioctl = { DUMMY_FD, SPI_IOC_MESSAGE(1), .tr =
      { .delay_usecs = 0, .speed_hz = 5000000, .bits_per_word = 8, .cs_change = 1, .len = 0, } } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's spi_release */
    { .func = __wrap_ioctl, .args.ioctl = { DUMMY_FD, SPI_IOC_MESSAGE(1), .tr =
      { .delay_usecs = 0, .speed_hz = 5000000, .bits_per_word = 8, .cs_change = 0, .len = 0, } } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's spi_transfer */
    { .func = __wrap_ioctl, .args.ioctl = { DUMMY_FD, SPI_IOC_MESSAGE(1), .tr =
      { .delay_usecs = 0, .speed_hz = 5000000, .bits_per_word = 8, .cs_change = 1,
      .len = sizeof (TPM2_STARTUP_CMD_MOSI), .tx_buf = (unsigned long)TPM2_STARTUP_CMD_MOSI,
      .rx_buf = (unsigned long)TPM2_STARTUP_CMD_MISO } } },

    /* platform->finalize */
    { .func = __wrap_close, .args.close = { DUMMY_FD } },

    { 0 },
};

TSS2_RC __wrap_Tss2_Tcti_Spi_Helper_Init (TSS2_TCTI_CONTEXT *tcti_context,
    size_t *size, TSS2_TCTI_SPI_HELPER_PLATFORM *platform)
{
    void *data;
    bool is_expired = false;
    uint8_t response[sizeof (TPM2_STARTUP_CMD_MISO)] = { 0 };

    if (tcti_context == NULL) {
        *size = sizeof (TSS2_TCTI_SPI_LTT2GO_TEST_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    /* Test TSS2_TCTI_SPI_HELPER_PLATFORM's callbacks */

    data = platform->user_data;
    assert_non_null (data);

    assert_int_equal (platform->sleep_ms (data, TIME_MS), TSS2_RC_SUCCESS);
    assert_int_equal (platform->start_timeout (data, TIME_MS), TSS2_RC_SUCCESS);
    assert_int_equal (platform->timeout_expired (data, &is_expired), TSS2_RC_SUCCESS);
    assert_true (is_expired);
    assert_int_equal (platform->timeout_expired (data, &is_expired), TSS2_RC_SUCCESS);
    assert_false (is_expired);
    assert_int_equal (platform->timeout_expired (data, &is_expired), TSS2_RC_SUCCESS);
    assert_true (is_expired);
    assert_int_equal (platform->spi_acquire (data), TSS2_RC_SUCCESS);
    assert_int_equal (platform->spi_release (data), TSS2_RC_SUCCESS);
    assert_int_equal (platform->spi_transfer (data, TPM2_STARTUP_CMD_MOSI,
        response, sizeof (response)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM2_STARTUP_CMD_MISO, sizeof (response)));

    platform->finalize (data);

    return TSS2_RC_SUCCESS;
}

static void
tcti_spi_init_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT* tcti_ctx;

    /* Initialize tester context */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_general;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spidev_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    rc = Tss2_Tcti_Spidev_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_init_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
