/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2023, Infineon Technologies AG
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_tcti.h"
#include "tss2_tcti_spi_ftdi.h"

#include "tss2-tcti/tcti-common.h"
#include "tss2-tcti/tcti-spi-ftdi.h"
#include "tss2-tcti/tcti-spi-helper.h"
#include "util/key-value-parse.h"

typedef enum {
    TPM_DID_VID = 0,
    TPM_ACCESS,
    TPM_STS_CMD_NOT_READY,
    TPM_STS_CMD_READY,
    TPM_RID,
} tpm_state_t;

static const unsigned char TPM_DID_VID_0[] = {0x83, 0xd4, 0x0f, 0x00, 0xd1, 0x15, 0x1b, 0x00};
static const unsigned char TPM_ACCESS_0[] = {0x80, 0xd4, 0x00, 0x00, 0xa1};
static const unsigned char TPM_STS_0_CMD_NOT_READY[] = {0x83, 0xd4, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00};
static const unsigned char TPM_STS_0_CMD_READY[] = {0x83, 0xd4, 0x00, 0x18, 0x40, 0x00, 0x00, 0x00};
static const unsigned char TPM_RID_0[] = {0x80, 0xd4, 0x0f, 0x04, 0x00};

static struct mpsse_context *_mpsse;

/*
 * Mock function MPSSE
 */
struct mpsse_context *__wrap_MPSSE (enum modes mode, int freq, int endianess)
{
    assert_int_equal (mode, SPI0);
    assert_int_equal (freq, FIFTEEN_MHZ);
    assert_int_equal (endianess, MSB);

    _mpsse = malloc (sizeof (struct mpsse_context));

    return _mpsse;
}

/*
 * Mock function PinLow
 */
int __wrap_PinLow (struct mpsse_context *mpsse, int pin)
{
    assert_ptr_equal (mpsse, _mpsse);
    assert_int_equal (pin, GPIOL0);

    return MPSSE_OK;
}

/*
 * Mock function PinHigh
 */
int __wrap_PinHigh (struct mpsse_context *mpsse, int pin)
{
    assert_ptr_equal (mpsse, _mpsse);
    assert_int_equal (pin, GPIOL0);

    return MPSSE_OK;
}

/*
 * Mock function Start
 */
int __wrap_Start (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    return MPSSE_OK;
}

/*
 * Mock function Transfer
 */
char *__wrap_Transfer (struct mpsse_context *mpsse, char *data, int size)
{

    static tpm_state_t tpm_state = TPM_DID_VID;
    char *ret = malloc (size);

    assert_non_null (ret);
    assert_ptr_equal (mpsse, _mpsse);

    switch (tpm_state++) {
    case TPM_DID_VID:
        assert_int_equal (size, 8);
        assert_true (!memcmp (data, TPM_DID_VID_0, 4));
        memcpy (ret, TPM_DID_VID_0, sizeof (TPM_DID_VID_0));
        break;
    case TPM_ACCESS:
        assert_int_equal (size, 5);
        assert_true (!memcmp (data, TPM_ACCESS_0, 4));
        memcpy (ret, TPM_ACCESS_0, sizeof (TPM_ACCESS_0));
        break;
    case TPM_STS_CMD_NOT_READY:
        assert_int_equal (size, 8);
        assert_true (!memcmp (data, TPM_STS_0_CMD_NOT_READY, 4));
        memcpy (ret, TPM_STS_0_CMD_NOT_READY, sizeof (TPM_STS_0_CMD_NOT_READY));
        break;
    case TPM_STS_CMD_READY:
        assert_int_equal (size, 8);
        assert_true (!memcmp (data, TPM_STS_0_CMD_READY, 4));
        memcpy (ret, TPM_STS_0_CMD_READY, sizeof (TPM_STS_0_CMD_READY));
        break;
    case TPM_RID:
        assert_int_equal (size, 5);
        assert_true (!memcmp (data, TPM_RID_0, 4));
        memcpy (ret, TPM_RID_0, sizeof (TPM_RID_0));
        break;
    default:
        assert_true (false);
    }

    return ret;
}

/*
 * Mock function Stop
 */
int __wrap_Stop (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    return MPSSE_OK;
}

/*
 * Mock function Close
 */
void __wrap_Close (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    free (_mpsse);
    _mpsse = NULL;
}

/*
 * The test will invoke Tss2_Tcti_Spi_Ftdi_Init() and subsequently
 * it will start reading TPM_DID_VID, claim locality, read TPM_STS,
 * and finally read TPM_RID before exiting the Init function.
 * For testing purpose, the TPM responses are hardcoded.
 * SPI wait state is not supported in this test.
 */
static void
tcti_spi_no_wait_state_success_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT* tcti_ctx;

    // Get requested TCTI context size
    rc = Tss2_Tcti_Spi_Ftdi_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    // Allocate TCTI context size
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    // Initialize TCTI context
    rc = Tss2_Tcti_Spi_Ftdi_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    // Finalize
    TSS2_TCTI_FINALIZE(tcti_ctx)(tcti_ctx);

    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_no_wait_state_success_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
