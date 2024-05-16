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

#include <inttypes.h>                   // for uint8_t
#include <stdbool.h>                    // for false, true
#include <stdio.h>                      // for NULL, size_t
#include <stdlib.h>                     // for malloc, free, calloc
#include <string.h>                     // for strncmp, memcpy
#include <sys/select.h>                 // for fd_set, timeval

#include "../helper/cmocka_all.h"                     // for assert_int_equal, assert_true
#include "tss2-tcti/mpsse/mpsse.h"      // for MPSSE_OK, ACK, I2C, MSB, ONE_...
#include "tss2-tcti/tcti-common.h"      // for TCTI_VERSION
#include "tss2-tcti/tcti-i2c-ftdi.h"    // for I2C_DEV_ADDR_DEFAULT
#include "tss2-tcti/tcti-i2c-helper.h"  // for TCTI_I2C_HELPER_TPM_STS_COMMA...
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_TCTI_RC...
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT, TSS2_TCTI_...
#include "tss2_tcti_i2c_ftdi.h"         // for Tss2_Tcti_I2c_Ftdi_Init

struct timeval;
struct timezone;

typedef enum {
    I2C_IDLE = 0,
    /* Read sequence */
    R_I2C_START_0,
    R_I2C_WRITE_0,
    R_I2C_GET_ACK_0,
    R_I2C_STOP_0,
    R_I2C_START_1,
    R_I2C_WRITE_1,
    R_I2C_GET_ACK_1,
    R_I2C_SEND_ACKS,
    R_I2C_READ_0,
    R_I2C_SEND_NACKS,
    R_I2C_READ_1,
    R_I2C_STOP_1,
    R_I2C_LAST,
    /* Write sequence */
    W_I2C_START,
    W_I2C_WRITE_0,
    W_I2C_GET_ACK,
    W_I2C_WRITE_1,
    W_I2C_STOP,
    W_I2C_LAST
} i2c_state_t;

typedef enum {
    /* Tss2_Tcti_I2c_Ftdi_Init () */
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
    /* TSS2_TCTI_RECEIVE () */
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
} tpm_state_t;

static struct m_state_t {
    tpm_state_t tpm;
    i2c_state_t i2c;
} m_state = {R_TPM_DID_VID, I2C_IDLE};

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
static const uint8_t R_TPM_STS_03_07_DATA[] = {TCTI_I2C_HELPER_TPM_STS_VALID, 0x00, 0x00, 0x00};
static const uint8_t W_TPM_STS_00_02_DATA[] = {TCTI_I2C_HELPER_TPM_STS_COMMAND_READY, 0x00, 0x00, 0x00};
static const uint8_t W_TPM_STS_01_DATA[] = {TCTI_I2C_HELPER_TPM_STS_GO, 0x00, 0x00, 0x00};
static const uint8_t W_TPM_CSUM_ENABLE_DATA[] = {0x01};
static const uint8_t RW_TPM_FIFO_DATA[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xde, 0xad, 0xbe, 0xef};

static struct mpsse_context *_mpsse;

static void state_machine (void)
{
    while (true) {
        switch (m_state.tpm) {
        case R_TPM_DID_VID:
        case R_TPM_INTERFACE_CAP:
        case R_TPM_CSUM_ENABLE:
        case R_TPM_CSUM_00:
        case R_TPM_CSUM_01:
        case R_TPM_ACCESS:
        case R_TPM_STS_00:
        case R_TPM_STS_01:
        case R_TPM_STS_02:
        case R_TPM_STS_03:
        case R_TPM_STS_04:
        case R_TPM_STS_05:
        case R_TPM_STS_06:
        case R_TPM_STS_07:
        case R_TPM_RID:
        case R_TPM_FIFO_00:
        case R_TPM_FIFO_01:
        case R_TPM_FIFO_02:
            if (m_state.i2c == I2C_IDLE) {
                /* Start a new read sequence */
                m_state.i2c = R_I2C_START_0;
                goto exit;
            } else if (m_state.i2c == R_I2C_LAST - 1) {
                /* Read sequence has ended */
                m_state.i2c = I2C_IDLE;
                m_state.tpm++;
            } else {
                /* Amidst a read sequence */
                m_state.i2c++;
                goto exit;
            }
            break;
        case W_TPM_FIFO:
        case W_TPM_CSUM_ENABLE:
        case W_TPM_STS_00:
        case W_TPM_STS_01:
        case W_TPM_STS_02:
            if (m_state.i2c == I2C_IDLE) {
                /* Start a new write sequence */
                m_state.i2c = W_I2C_START;
                goto exit;
            } else if (m_state.i2c == W_I2C_LAST - 1) {
                /* Write sequence has ended */
                m_state.i2c = I2C_IDLE;
                m_state.tpm++;
            } else {
                /* Amidst a write sequence */
                m_state.i2c++;
                goto exit;
            }
            break;
        default:
            assert_true (false);
            return;
        }
    }

exit:
    return;
}

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

/*
 * Mock function MPSSE
 */
struct mpsse_context *__wrap_MPSSE (enum modes mode, int freq, int endianess)
{
    assert_int_equal (mode, I2C);
    assert_int_equal (freq, ONE_HUNDRED_KHZ);
    assert_int_equal (endianess, MSB);

    _mpsse = malloc (sizeof (struct mpsse_context));

    return _mpsse;
}

/*
 * Mock function Start
 */
int __wrap_Start (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();
    assert_true ((m_state.i2c == R_I2C_START_0) ||
                 (m_state.i2c == R_I2C_START_1) ||
                 (m_state.i2c == W_I2C_START));
    return MPSSE_OK;
}

/*
 * Mock function Stop
 */
int __wrap_Stop (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();
    assert_true ((m_state.i2c == R_I2C_STOP_0) ||
                 (m_state.i2c == R_I2C_STOP_1) ||
                 (m_state.i2c == W_I2C_STOP));
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
 * Mock function Read
 */
char *__wrap_Read (struct mpsse_context *mpsse, int size)
{
    const uint8_t *payload = NULL;
    int payload_size = 0;
    char *out = NULL;

    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();

    switch (m_state.tpm) {
    case R_TPM_DID_VID:
        payload = R_TPM_DID_VID_DATA;
        payload_size = sizeof (R_TPM_DID_VID_DATA);
        break;
    case R_TPM_INTERFACE_CAP:
        payload = R_TPM_INTERFACE_CAP_DATA;
        payload_size = sizeof (R_TPM_INTERFACE_CAP_DATA);
        break;
    case R_TPM_CSUM_ENABLE:
        payload = R_TPM_CSUM_ENABLE_DATA;
        payload_size = sizeof (R_TPM_CSUM_ENABLE_DATA);
        break;
    case R_TPM_CSUM_00:
    case R_TPM_CSUM_01:
        payload = R_TPM_CSUM_DATA;
        payload_size = sizeof (R_TPM_CSUM_DATA);
        break;
    case R_TPM_ACCESS:
        payload = R_TPM_ACCESS_DATA;
        payload_size = sizeof (R_TPM_ACCESS_DATA);
        break;
    case R_TPM_STS_00:
    case R_TPM_STS_01:
        payload = R_TPM_STS_00_01_DATA;
        payload_size = sizeof (R_TPM_STS_00_01_DATA);
        break;
    case R_TPM_STS_02:
    case R_TPM_STS_05:
        payload = R_TPM_STS_02_05_DATA;
        payload_size = sizeof (R_TPM_STS_02_05_DATA);
        break;
    case R_TPM_STS_03:
    case R_TPM_STS_07:
        payload = R_TPM_STS_03_07_DATA;
        payload_size = sizeof (R_TPM_STS_03_07_DATA);
        break;
    case R_TPM_STS_04:
    case R_TPM_STS_06:
        payload = R_TPM_STS_04_06_DATA;
        payload_size = sizeof (R_TPM_STS_04_06_DATA);
        break;
    case R_TPM_RID:
        payload = R_TPM_RID_DATA;
        payload_size = sizeof (R_TPM_RID_DATA);
        break;
    case R_TPM_FIFO_00:
        payload = RW_TPM_FIFO_DATA;
        payload_size = TCTI_I2C_HELPER_RESP_HEADER_SIZE;
        break;
    case R_TPM_FIFO_01:
        payload = RW_TPM_FIFO_DATA + TCTI_I2C_HELPER_RESP_HEADER_SIZE;
        payload_size = sizeof (RW_TPM_FIFO_DATA) - 1 - TCTI_I2C_HELPER_RESP_HEADER_SIZE;
        break;
    case R_TPM_FIFO_02:
        payload = RW_TPM_FIFO_DATA + sizeof (RW_TPM_FIFO_DATA) - 1;
        payload_size = 1;
        break;
    default:
        assert_true (false);
    }

    switch (m_state.i2c) {
        case R_I2C_READ_0:
            assert_int_equal (size, payload_size - 1);
            out = malloc (size);
            assert_non_null (out);
            memcpy (out, payload, payload_size - 1);
            return out;
            break;
        case R_I2C_READ_1:
            assert_int_equal (size, 1);
            out = malloc (1);
            assert_non_null (out);
            memcpy (out, payload + payload_size - 1, 1);
            return out;
            break;
        default:
            assert_true (false);
    }

    return NULL;
}

/*
 * Mock function Write
 */
int __wrap_Write (struct mpsse_context *mpsse, char *data, int size)
{
    const uint8_t *payload = NULL;
    int payload_size = 0;
    uint8_t addr[2] = {I2C_DEV_ADDR_DEFAULT << 1, 0x0};

    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();

    switch (m_state.tpm) {
    case R_TPM_DID_VID:
        addr[1] = TCTI_I2C_HELPER_TPM_DID_VID_REG;
        break;
    case R_TPM_INTERFACE_CAP:
        addr[1] = TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_REG;
        break;
    case R_TPM_CSUM_ENABLE:
        addr[1] = TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG;
        break;
    case R_TPM_CSUM_00:
    case R_TPM_CSUM_01:
        addr[1] = TCTI_I2C_HELPER_TPM_DATA_CSUM_REG;
        break;
    case R_TPM_ACCESS:
        addr[1] = TCTI_I2C_HELPER_TPM_ACCESS_REG;
        break;
    case R_TPM_STS_00:
    case R_TPM_STS_01:
    case R_TPM_STS_02:
    case R_TPM_STS_03:
    case R_TPM_STS_04:
    case R_TPM_STS_05:
    case R_TPM_STS_06:
    case R_TPM_STS_07:
        addr[1] = TCTI_I2C_HELPER_TPM_STS_REG;
        break;
    case R_TPM_RID:
        addr[1] = TCTI_I2C_HELPER_TPM_RID_REG;
        break;
    case R_TPM_FIFO_00:
    case R_TPM_FIFO_01:
    case R_TPM_FIFO_02:
        addr[1] = TCTI_I2C_HELPER_TPM_DATA_FIFO_REG;
        break;
    case W_TPM_STS_00:
    case W_TPM_STS_02:
        addr[1] = TCTI_I2C_HELPER_TPM_STS_REG;
        payload = W_TPM_STS_00_02_DATA;
        payload_size = sizeof (W_TPM_STS_00_02_DATA);
        break;
    case W_TPM_STS_01:
        addr[1] = TCTI_I2C_HELPER_TPM_STS_REG;
        payload = W_TPM_STS_01_DATA;
        payload_size = sizeof (W_TPM_STS_01_DATA);
        break;
    case W_TPM_CSUM_ENABLE:
        addr[1] = TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG;
        payload = W_TPM_CSUM_ENABLE_DATA;
        payload_size = sizeof (W_TPM_CSUM_ENABLE_DATA);
        break;
    case W_TPM_FIFO:
        addr[1] = TCTI_I2C_HELPER_TPM_DATA_FIFO_REG;
        payload = RW_TPM_FIFO_DATA;
        payload_size = sizeof (RW_TPM_FIFO_DATA);
        break;
    default:
        assert_true (false);
    }

    switch (m_state.tpm) {
    case R_TPM_DID_VID:
    case R_TPM_INTERFACE_CAP:
    case R_TPM_CSUM_ENABLE:
    case R_TPM_CSUM_00:
    case R_TPM_CSUM_01:
    case R_TPM_ACCESS:
    case R_TPM_STS_00:
    case R_TPM_STS_01:
    case R_TPM_STS_02:
    case R_TPM_STS_03:
    case R_TPM_STS_04:
    case R_TPM_STS_05:
    case R_TPM_STS_06:
    case R_TPM_STS_07:
    case R_TPM_RID:
    case R_TPM_FIFO_00:
    case R_TPM_FIFO_01:
    case R_TPM_FIFO_02:
        switch (m_state.i2c) {
            case R_I2C_WRITE_0:
                assert_int_equal (size, 2);
                assert_int_equal (strncmp ((const void *)addr, data, 2), 0);
                break;
            case R_I2C_WRITE_1:
                assert_int_equal (size, 1);
                assert_int_equal ((uint8_t)data[0], addr[0] | 0x01);
                break;
            default:
                assert_true (false);
        }
        break;
    case W_TPM_STS_00:
    case W_TPM_STS_01:
    case W_TPM_STS_02:
    case W_TPM_FIFO:
    case W_TPM_CSUM_ENABLE:
        switch (m_state.i2c) {
            case W_I2C_WRITE_0:
                assert_int_equal (size, 2);
                assert_int_equal (strncmp ((const void *)addr, data, 2), 0);
                break;
            case W_I2C_WRITE_1:
                assert_int_equal (size, payload_size);
                assert_int_equal (strncmp ((const char *)payload, data, payload_size), 0);
                break;
            default:
                assert_true (false);
        }
        break;
    default:
        assert_true (false);
    }

    return 0;
}

/*
 * Mock function GetAck
 */
int __wrap_GetAck (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();
    assert_true ((m_state.i2c == R_I2C_GET_ACK_0) ||
                 (m_state.i2c == R_I2C_GET_ACK_1) ||
                 (m_state.i2c == W_I2C_GET_ACK));
    return ACK;
}

/*
 * Mock function SendAcks
 */
void __wrap_SendAcks (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();
    assert_true (m_state.i2c == R_I2C_SEND_ACKS);
}

/*
 * Mock function SendNacks
 */
void __wrap_SendNacks (struct mpsse_context *mpsse)
{
    assert_ptr_equal (mpsse, _mpsse);
    state_machine ();
    assert_true (m_state.i2c == R_I2C_SEND_NACKS);
}

/*
 * The test will call Tss2_Tcti_I2c_Ftdi_Init(),
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
    TSS2_TCTI_CONTEXT* tcti_ctx;

    m_state.tpm = 0;
    m_state.i2c = 0;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_I2c_Ftdi_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    rc = Tss2_Tcti_I2c_Ftdi_Init (tcti_ctx, &size, NULL);
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

    /* Clean up */
    TSS2_TCTI_FINALIZE (tcti_ctx) (tcti_ctx);
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_i2c_generic_test),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
