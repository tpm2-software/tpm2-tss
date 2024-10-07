/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2023, Infineon Technologies AG
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdbool.h>                // for false
#include <stdio.h>                  // for NULL, size_t
#include <stdlib.h>                 // for free, malloc, calloc
#include <string.h>                 // for memcmp, memcpy
#include <sys/select.h>             // for fd_set, timeval

#include "../helper/cmocka_all.h"                 // for assert_int_equal, assert_ptr_equal
#include "tss2-tcti/mpsse/mpsse.h"  // for MPSSE_OK, GPIOL0, FIFTEEN_MHZ, MSB
#include "tss2-tcti/tcti-common.h"      // for TCTI_VERSION
#include "tss2-tcti/tcti-spi-ftdi.h"
#include "tss2-tcti/tcti-spi-helper.h"
#include "tss2_common.h"            // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_tcti.h"              // for TSS2_TCTI_CONTEXT, TSS2_TCTI_FINA...
#include "tss2_tcti_spi_ftdi.h"     // for Tss2_Tcti_Spi_Ftdi_Init

/*
 * The goal is to verify the FTDI SPI implementation by checking
 * the order in which libftdi functions are invoked when using functions in
 * the TSS2_TCTI_SPI_HELPER_PLATFORM (e.g., sleep_ms, start_timeout,
 * timeout_expired, spi_transfer).

 * The audit arrays (e.g., audit_general) contain this information. Each
 * entry specifies the expected libftdi function to be invoked, the command
 * to be received, or the response to be written back in a specific order.
 * The tester_context.audit_step (audit array index) variable tracks the
 * sequence of these operations.
 */

#define MPSSE_DUMMY_PTR       ((void *)0xA5A5A5A5)
#define TIME_MS               450

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TSS2_TCTI_SPI_HELPER_PLATFORM platform;
} TSS2_TCTI_SPI_FTDI_TEST_CONTEXT;

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
    enum modes mode;
    int freq;
    int endianess;
    void *ret;
} fn_mpsse;

typedef struct {
    void *mpsse;
} fn_start, fn_stop,
  fn_close;

typedef struct {
    void *mpsse;
    void *mosi;
    void *miso;
    size_t size;
} fn_transfer;

typedef struct {
    void *func;
    union {
        fn_select select;
        fn_gettimeofday gtod;
        fn_mpsse mpsse;
        fn_start start;
        fn_stop stop;
        fn_close close;
        fn_transfer transfer;
    } args;
} struct_audit;

typedef struct {
    int audit_step;
    struct_audit *audit;
} tester_context;

static tester_context tester_ctx;
static const unsigned char TPM2_STARTUP_CMD_MOSI[] =
    { 0x0B, 0xD4, 0x00, 0x24, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
static const unsigned char TPM2_STARTUP_CMD_MISO[] =
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

/*
 * Mock function MPSSE
 */
struct mpsse_context *__wrap_MPSSE (enum modes mode, int freq, int endianess)
{
    struct mpsse_context *ret;
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_MPSSE, audit->func);
    assert_int_equal (mode, audit->args.mpsse.mode);
    assert_int_equal (freq, audit->args.mpsse.freq);
    assert_int_equal (endianess, audit->args.mpsse.endianess);
    ret = (struct mpsse_context *)audit->args.mpsse.ret;

    return ret;
}

/*
 * Mock function Start
 */
int __wrap_Start (struct mpsse_context *mpsse)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_Start, audit->func);
    assert_ptr_equal (mpsse, audit->args.start.mpsse);

    return MPSSE_OK;
}

/*
 * Mock function Stop
 */
int __wrap_Stop (struct mpsse_context *mpsse)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];
    assert_ptr_equal (__wrap_Stop, audit->func);
    assert_ptr_equal (mpsse, audit->args.stop.mpsse);

    return MPSSE_OK;
}

/*
 * Mock function Close
 */
void __wrap_Close (struct mpsse_context *mpsse)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_Close, audit->func);
    assert_ptr_equal (mpsse, audit->args.close.mpsse);
}

/*
 * Mock function Transfer
 */
char *__wrap_Transfer (struct mpsse_context *mpsse, char *data, int size)
{
    char *ptr;
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_Transfer, audit->func);
    assert_ptr_equal (mpsse, audit->args.transfer.mpsse);
    assert_ptr_equal (size, audit->args.transfer.size);
    assert_true (!memcmp (data, audit->args.transfer.mosi, size));

    ptr = calloc (1, size);
    assert_non_null (ptr);
    memcpy (ptr, audit->args.transfer.miso, size);

    return ptr;
}

static struct_audit audit_general[] = {
    /* Tss2_Tcti_Spi_Ftdi_Init (tcti_ctx, &size, NULL) */
    { .func = __wrap_MPSSE, .args.mpsse = { SPI0, FIFTEEN_MHZ, MSB, MPSSE_DUMMY_PTR } },

    /* TSS2_TCTI_SPI_HELPER_PLATFORM's sleep_ms */
    { .func = __wrap_select, .args.select =
      { 0, NULL, NULL, NULL, { (TIME_MS * 1000) / 1000000, (TIME_MS * 1000) % 1000000 } } },

    /* TSS2_TCTI_SPI_HELPER_PLATFORM's start_timeout */
    { .func = __wrap_gettimeofday, .args.gtod = { { 0, 0 }, NULL } },

    /* TSS2_TCTI_SPI_HELPER_PLATFORM's timeout_expired */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 1, 0 }, NULL } }, /* Return a value > TIME_MS to trigger a timeout event */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 0, (TIME_MS * 1000) }, NULL } }, /* Return a value <= TIME_MS, no timeout occured */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 0, (TIME_MS * 1000) + 1 }, NULL } }, /* Return a value > TIME_MS to trigger a timeout event */

    /* TSS2_TCTI_SPI_HELPER_PLATFORM's transfer */
    { .func = __wrap_Start, .args.start = { MPSSE_DUMMY_PTR } },
    { .func = __wrap_Transfer, .args.transfer =
      { MPSSE_DUMMY_PTR, (void *)TPM2_STARTUP_CMD_MOSI, (void *)TPM2_STARTUP_CMD_MISO, sizeof (TPM2_STARTUP_CMD_MISO) } },
    { .func = __wrap_Stop, .args.stop = { MPSSE_DUMMY_PTR } },

    /* TSS2_TCTI_SPI_HELPER_PLATFORM's finalize */
    { .func = __wrap_Close, .args.close = { MPSSE_DUMMY_PTR } },

    { 0 },
};

TSS2_RC __wrap_Tss2_Tcti_Spi_Helper_Init (TSS2_TCTI_CONTEXT *tcti_context, size_t *size, TSS2_TCTI_SPI_HELPER_PLATFORM *platform)
{
    void *data;
    bool is_expired = false;
    uint8_t response[sizeof (TPM2_STARTUP_CMD_MISO)] = { 0 };

    if (tcti_context == NULL) {
        *size = sizeof (TSS2_TCTI_SPI_FTDI_TEST_CONTEXT);
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
    assert_int_equal (platform->spi_transfer (data, TPM2_STARTUP_CMD_MOSI, response,
        sizeof (response)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM2_STARTUP_CMD_MISO, sizeof (response)));

    platform->finalize (data);

    return TSS2_RC_SUCCESS;
}

static void
tcti_spi_general_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Initialize tester context */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_general;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Ftdi_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    rc = Tss2_Tcti_Spi_Ftdi_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Clean up */
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_general_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
