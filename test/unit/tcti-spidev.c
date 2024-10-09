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

#include "../helper/cmocka_all.h"                     // for assert_int_equal, assert_memo...

#include <linux/spi/spidev.h>           // for spi_ioc_transfer

#include "tss2-tcti/tcti-spi-helper.h"  // for TSS2_TCTI_SPI_HELPER_CONTEXT
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT
#include "tss2_tcti_spi_helper.h"       // for TSS2_TCTI_SPI_HELPER_PLATFORM
#include "tss2_tcti_spidev.h"           // for Tss2_Tcti_Spidev_Init

struct timeval;
struct timezone;

#define LOGMODULE tests
#include "util/log.h"

#define EXIT_SKIP 77

typedef enum {
    TPM_DID_VID_HEAD = 0,
    TPM_DID_VID_DATA,
    TPM_ACCESS_HEAD,
    TPM_ACCESS_DATA,
    TPM_STS_CMD_NOT_READY_HEAD,
    TPM_STS_CMD_NOT_READY_DATA,
    TPM_STS_CMD_READY_HEAD,
    TPM_STS_CMD_READY_DATA,
    TPM_RID_HEAD,
    TPM_RID_DATA,
} tpm_state_t;

// First 4 bytes are the request, the remainder is the response
static const unsigned char TPM_DID_VID_0[] = {0x83, 0xd4, 0x0f, 0x00, 0xd1, 0x15, 0x1b, 0x00};
static const unsigned char TPM_ACCESS_0[] = {0x80, 0xd4, 0x00, 0x00, 0xa1};
static const unsigned char TPM_STS_0_CMD_NOT_READY[] = {0x83, 0xd4, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00};
static const unsigned char TPM_STS_0_CMD_READY[] = {0x83, 0xd4, 0x00, 0x18, 0x40, 0x00, 0x00, 0x00};
static const unsigned char TPM_RID_0[] = {0x80, 0xd4, 0x0f, 0x04, 0x00};

/*
 * Mock function select
 */
int __wrap_select (int nfds, fd_set *readfds,
                   fd_set *writefds,
                   fd_set *exceptfds,
                   struct timeval *timeout)
{

    assert_int_equal (nfds, 0);
    assert_null (readfds);
    assert_null (writefds);
    assert_null (exceptfds);
    assert_non_null (timeout);

    return 0;
}

/*
 * Mock function gettimeofday
 */
int __wrap_gettimeofday (struct timeval *tv,
                         struct timezone *tz)
{
    assert_null (tz);
    assert_non_null (tv);

    tv->tv_sec = 0;
    tv->tv_usec = 0;

    return 0;
}

int __real_open(const char *path, int flags);

#define FD_NO 5
int __wrap_open(const char *path, int flags)
{
    assert_ptr_not_equal(path, NULL);
    if (!!strncmp(path, "/dev/spidev", sizeof("/dev/spidev") - 1))
        return __real_open(path, flags);
    assert_int_equal(flags, O_RDWR);
    return FD_NO;
}

int __wrap_close(int fd)
{
    assert_int_equal(fd, FD_NO);
    return 0;
}

int __wrap_ioctl(int fd, unsigned long request, struct spi_ioc_transfer *tr)
{
    assert_int_equal(tr->delay_usecs, 0);
    assert_int_equal(tr->bits_per_word, 8);

    size_t len = tr->len;

    /* Use size_t to cast 64 bit number to pointer (needed for 32 bit systems) */
    uint8_t *tx_buf = (uint8_t *)(size_t) tr->tx_buf;
    uint8_t *rx_buf = (uint8_t *)(size_t) tr->rx_buf;

    static tpm_state_t tpm_state = TPM_DID_VID_HEAD;

    // Check for CS-acquire/-release which have no payload
    if (len == 0) {
        goto done;
    }

    switch (tpm_state++) {
    case TPM_DID_VID_HEAD:
        assert_int_equal (len, 4);
        assert_memory_equal(&tx_buf[0], TPM_DID_VID_0, 4);
        rx_buf[3] = 0x01; // Set Waitstate OK
        break;
    case TPM_DID_VID_DATA:
        assert_int_equal (len, sizeof (TPM_DID_VID_0) - 4);
        memcpy (&rx_buf[0], &TPM_DID_VID_0[4], sizeof (TPM_DID_VID_0) - 4);
        break;
    case TPM_ACCESS_HEAD:
        assert_int_equal (len, 4);
        assert_memory_equal(&tx_buf[0], TPM_ACCESS_0, 4);
        rx_buf[3] = 0x01; // Set Waitstate OK
        break;
    case TPM_ACCESS_DATA:
        assert_int_equal (len, sizeof (TPM_ACCESS_0) - 4);
        memcpy (&rx_buf[0], &TPM_ACCESS_0[4], sizeof (TPM_ACCESS_0) - 4);
        break;
    case TPM_STS_CMD_NOT_READY_HEAD:
        assert_int_equal (len, 4);
        assert_memory_equal(&tx_buf[0], TPM_STS_0_CMD_NOT_READY, 4);
        rx_buf[3] = 0x01; // Set Waitstate OK
        break;
    case TPM_STS_CMD_NOT_READY_DATA:
        assert_int_equal (len, sizeof (TPM_STS_0_CMD_NOT_READY) - 4);
        memcpy (&rx_buf[0], &TPM_STS_0_CMD_NOT_READY[4], sizeof (TPM_STS_0_CMD_NOT_READY) - 4);
        break;
    case TPM_STS_CMD_READY_HEAD:
        assert_int_equal (len, 4);
        assert_memory_equal(&tx_buf[0], TPM_STS_0_CMD_READY, 4);
        rx_buf[3] = 0x01; // Set Waitstate OK
        break;
    case TPM_STS_CMD_READY_DATA:
        assert_int_equal (len, sizeof (TPM_STS_0_CMD_READY) - 4);
        memcpy (&rx_buf[0], &TPM_STS_0_CMD_READY[4], sizeof (TPM_STS_0_CMD_READY) - 4);
        break;
    case TPM_RID_HEAD:
        assert_int_equal (len, 4);
        assert_memory_equal(&tx_buf[0], TPM_RID_0, 4);
        rx_buf[3] = 0x01; // Set Waitstate OK
        break;
    case TPM_RID_DATA:
        assert_int_equal (len, sizeof (TPM_RID_0) - 4);
        memcpy (&rx_buf[0], &TPM_RID_0[4], sizeof (TPM_RID_0) - 4);
        break;
    default:
        assert_true (false);
    }

done:
    return 0;
}

/*
 * The test will invoke Tss2_Tcti_Spidev_Init() and subsequently
 * it will start reading TPM_DID_VID, claim locality, read TPM_STS,
 * and finally read TPM_RID before exiting the Init function.
 * For testing purpose, the TPM responses are hardcoded.
 */
static void
tcti_spi_init_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT* tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spidev_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    rc = Tss2_Tcti_Spidev_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TSS2_TCTI_SPI_HELPER_PLATFORM platform = ((TSS2_TCTI_SPI_HELPER_CONTEXT *) tcti_ctx)->platform;
    free (platform.user_data);
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
#if __SIZEOF_POINTER__ == 4 && _TIME_BITS == 64
    // Would produce cmocka error
    LOG_WARNING("_TIME_BITS == 64 would produce cmocka errors on this platform.");
    return EXIT_SKIP;
#endif

    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_init_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
