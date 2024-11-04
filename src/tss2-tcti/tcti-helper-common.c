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
#include "config.h"                // for MAXLOGLEVEL
#endif

#include <inttypes.h>              // for uint8_t, uint32_t, PRIu32, PRIx32
#include <stdbool.h>               // for bool, false, true
#include <stdio.h>                 // for NULL, size_t
#include <string.h>                // for memcpy, memset

#include "tcti-common.h"           // for TSS2_TCTI_COMMON_CONTEXT, tpm_head...
#include "tcti-helper-common.h"
#include "tss2_common.h"           // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_TCT...
#include "tss2_tcti.h"             // for TSS2_TCTI_CONTEXT, TSS2_TCTI_INFO
#include "util/tss2_endian.h"      // for LE_TO_HOST_32

#define LOGMODULE tcti
#include "util/log.h"              // for LOG_ERROR, LOG_DEBUG, return_if_error

/*
 * CRC-CCITT KERMIT with following parameters:
 *
 * Length                           : 16 bit
 * Poly                             : 0x1021
 * Init                             : 0x0000
 * RefIn                            : False
 * RefOut                           : False
 * XorOut                           : 0x0000
 * Output for ASCII "123456789"     : 0x2189
 */
static const uint16_t crc16_kermit_lookup[256]= {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

static uint16_t crc_ccitt (const uint8_t *buffer, size_t size) {
    size_t i;
    uint16_t result = 0;

    for (i = 0; i < size; i++) {
        uint8_t j = buffer[i] ^ result;
        result = crc16_kermit_lookup[j] ^ (result >> 8);
    }

    return result;
}

static TSS2_RC tcti_helper_common_sanity_check (enum TCTI_HELPER_COMMON_REG reg, uint8_t *buffer, size_t cnt)
{
    uint32_t zero_mask;
    uint32_t value;

    switch (cnt) {
    case sizeof (uint8_t):
        value = buffer[0];
        break;
    case sizeof (uint16_t):
        value = LE_TO_HOST_16 (*((uint16_t *)buffer));
        break;
    case sizeof (uint32_t):
        value = LE_TO_HOST_32 (*((uint32_t *)buffer));
        break;
    default:
        return TSS2_RC_SUCCESS;
    }

    switch (reg) {
    case TCTI_HELPER_COMMON_REG_TPM_ACCESS:
        zero_mask = TCTI_HELPER_COMMON_TPM_ACCESS_ZERO_MASK;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_STS:
        zero_mask = TCTI_HELPER_COMMON_TPM_STS_ZERO_MASK;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_I2C_INTF_CAP:
        zero_mask = TCTI_HELPER_COMMON_TPM_I2C_INTF_CAP_ZERO_MASK;
        break;
    default:
        return TSS2_RC_SUCCESS;
    }

    if (value & zero_mask) {
        LOG_ERROR ("The TPM return value failed the sanity check");
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}

static inline size_t tcti_helper_common_size_t_min (size_t a, size_t b)
{
    if (a < b) {
        return a;
    }
    return b;
}

static inline uint32_t tcti_helper_common_read_be32 (const void *src)
{
    const uint8_t *s = src;
    return (((uint32_t)s[0]) << 24) | (((uint32_t)s[1]) << 16) | (((uint32_t)s[2]) << 8) | (((uint32_t)s[3]) << 0);
}

static TSS2_RC tcti_helper_common_read_sts_reg (TCTI_HELPER_COMMON_CONTEXT *ctx, uint32_t *reg)
{
    uint32_t status = 0;
    TSS2_RC rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_STS, &status, sizeof (status));
    if (rc) {
        return rc;
    }

    rc = tcti_helper_common_sanity_check (TCTI_HELPER_COMMON_REG_TPM_STS, (uint8_t *)&status, sizeof (status));
    if (rc) {
        return rc;
    }

    *reg = LE_TO_HOST_32 (status);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_helper_common_write_sts_reg (TCTI_HELPER_COMMON_CONTEXT *ctx, uint32_t status)
{
    status = HOST_TO_LE_32 (status);
    return ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_STS, &status, sizeof (status));
}

static TSS2_RC tcti_helper_common_wait_for_burst_count (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t *count, enum TCTI_HELPER_COMMON_FIFO_TRANSFER_DIRECTION direction)
{
    TSS2_RC rc;
    bool is_timeout_expired = false;
    uint32_t expected_status_bits;
    uint32_t status;

    rc = ctx->start_timeout (ctx->data, TIMEOUT_A);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to invoke start_timeout()");
        return rc;
    }

    /* Wait for the expected status with or without timeout */
    do {
        rc = tcti_helper_common_read_sts_reg (ctx, &status);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to read the TPM_STS register");
            return rc;
        }

        if (direction == TCTI_HELPER_COMMON_FIFO_RECEIVE) {
            expected_status_bits = TCTI_HELPER_COMMON_TPM_STS_VALID | TCTI_HELPER_COMMON_TPM_STS_DATA_AVAIL;
            if ((status & expected_status_bits) != expected_status_bits) {
                LOG_ERROR ("Invalid stsValid and dataAvail bits in the TPM_STS register were detected during transmission");
                return TSS2_TCTI_RC_IO_ERROR;
            }
        } else if (direction == TCTI_HELPER_COMMON_FIFO_TRANSMIT_2) {
            expected_status_bits = TCTI_HELPER_COMMON_TPM_STS_VALID | TCTI_HELPER_COMMON_TPM_STS_DATA_EXPECT;
            if ((status & expected_status_bits) != expected_status_bits) {
                LOG_ERROR ("Invalid stsValid and Expect bits in the TPM_STS register were detected during transmission");
                return TSS2_TCTI_RC_IO_ERROR;
            }
        }

        /* Return on non-zero value */
        *count = (status & TCTI_HELPER_COMMON_TPM_STS_BURST_COUNT_MASK) >> TCTI_HELPER_COMMON_TPM_STS_BURST_COUNT_SHIFT;
        if (*count) {
            return TSS2_RC_SUCCESS;
        }

        /* Delay the next poll to prevent spamming the TPM */
        rc = ctx->sleep_ms (ctx->data, POLLING_INTERVAL_MS);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to invoke sleep_ms()");
            return rc;
        }

        rc = ctx->timeout_expired (ctx->data, &is_timeout_expired);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to invoke timeout_expired()");
            return rc;
        }
    } while (!is_timeout_expired);

    /* Timed out */
    return TSS2_TCTI_RC_TRY_AGAIN;
}

static TSS2_RC tcti_helper_common_read_access_reg (TCTI_HELPER_COMMON_CONTEXT *ctx, uint8_t *reg)
{
    uint8_t access = 0;
    TSS2_RC rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_ACCESS, &access, sizeof (access));
    if (rc) {
        return rc;
    }

    rc = tcti_helper_common_sanity_check (TCTI_HELPER_COMMON_REG_TPM_ACCESS, (uint8_t *)&access, sizeof (access));
    if (rc) {
        return rc;
    }

    *reg = access;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_helper_common_write_access_reg (TCTI_HELPER_COMMON_CONTEXT *ctx, uint8_t access_bit)
{
    TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
    /* Writes to access register can set only 1 bit at a time */
    if (access_bit & (access_bit - 1)) {
        LOG_ERROR ("Writes to access register can set only 1 bit at a time.");
    } else {
        rc = ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_ACCESS, &access_bit, sizeof (access_bit));
    }

    return rc;
}

static TSS2_RC tcti_helper_common_claim_locality (TCTI_HELPER_COMMON_CONTEXT *ctx)
{
    uint8_t access;
    TSS2_RC rc;

    rc = tcti_helper_common_read_access_reg (ctx, &access);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to read the TPM_ACCESS register");
        return rc;
    }

    /* Check if tpmRegValidSts is set */
    if (!(access & TCTI_HELPER_COMMON_TPM_ACCESS_VALID)) {
        LOG_ERROR ("tpmRegValidSts bit of TPM_ACCESS register is not set to 1, TPM_ACCESS: 0x%02" PRIx8, access);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Check if locality 0 is active */
    if (access & TCTI_HELPER_COMMON_TPM_ACCESS_ACTIVE_LOCALITY) {
        LOG_DEBUG ("Locality 0 is already active, TPM_ACCESS: 0x%02" PRIx8, access);
        return TSS2_RC_SUCCESS;
    }

    /* Request for locality 0 */
    rc = tcti_helper_common_write_access_reg (ctx, TCTI_HELPER_COMMON_TPM_ACCESS_REQUEST_USE);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed writing requestUse to TPM_ACCESS register");
        return rc;
    }

    rc = tcti_helper_common_read_access_reg (ctx, &access);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to read the TPM_ACCESS register");
        return rc;
    }

    /* Check if locality 0 is active */
    if (access & (TCTI_HELPER_COMMON_TPM_ACCESS_VALID | TCTI_HELPER_COMMON_TPM_ACCESS_ACTIVE_LOCALITY)) {
        LOG_DEBUG ("Successfully claimed locality 0");
        return TSS2_RC_SUCCESS;
    }

    LOG_ERROR ("Failed to claim locality 0, TPM_ACCESS: 0x%02" PRIx8, access);
    return TSS2_TCTI_RC_IO_ERROR;
}

static TSS2_RC tcti_helper_common_wait_for_status (TCTI_HELPER_COMMON_CONTEXT *ctx, uint32_t status_mask, uint32_t status_expected, int32_t timeout)
{
    TSS2_RC rc;
    bool is_timeout_expired = false;
    uint32_t status;
    bool blocking = (timeout == TSS2_TCTI_TIMEOUT_BLOCK);

    if (!blocking) {
        rc = ctx->start_timeout (ctx->data, timeout);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to invoke start_timeout()");
            return rc;
        }

    }

    /* Wait for the expected status with or without timeout */
    do {
        rc = tcti_helper_common_read_sts_reg (ctx, &status);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to read the TPM_STS register");
            return rc;
        }

        /* Return success on expected status */
        if ((status & status_mask) == status_expected) {
            return TSS2_RC_SUCCESS;
        }
        /* Delay the next poll to prevent spamming the TPM */
        rc = ctx->sleep_ms (ctx->data, POLLING_INTERVAL_MS);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to invoke sleep_ms()");
            return rc;
        }

        rc = ctx->timeout_expired (ctx->data, &is_timeout_expired);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to invoke timeout_expired()");
            return rc;
        }
    } while (blocking || !is_timeout_expired);

    /* Timed out */
    return TSS2_TCTI_RC_TRY_AGAIN;
}

static TSS2_RC tcti_helper_common_fifo_transfer (TCTI_HELPER_COMMON_CONTEXT *ctx, uint8_t *transfer_buffer, size_t transfer_size, enum TCTI_HELPER_COMMON_FIFO_TRANSFER_DIRECTION direction)
{
    TSS2_RC rc;
    size_t transaction_size;
    size_t burst_count;
    size_t handled_so_far = 0;

    do {
        if ((rc = tcti_helper_common_wait_for_burst_count (ctx, &burst_count, direction))) {
            LOG_ERROR ("Failed to wait for the burst count to turn non-zero");
            return rc;
        }

        transaction_size = transfer_size - handled_so_far;
        transaction_size = tcti_helper_common_size_t_min (transaction_size, burst_count);
        transaction_size = tcti_helper_common_size_t_min (transaction_size, 64);

        if (direction == TCTI_HELPER_COMMON_FIFO_RECEIVE){
            rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (void *)(transfer_buffer + handled_so_far), transaction_size);
        } else {
            rc = ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO, (const void *)(transfer_buffer + handled_so_far), transaction_size);
        }

        if (rc) {
            return rc;
        }

        handled_so_far += transaction_size;

    } while (handled_so_far != transfer_size);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_helper_common_read_guard_time (TCTI_HELPER_COMMON_CONTEXT *ctx)
{
    TSS2_RC rc;
    uint32_t i2c_caps;

    ctx->i2c_guard_time_read = true;
    ctx->i2c_guard_time_write = true;
    ctx->i2c_guard_time = TCTI_HELPER_COMMON_I2C_GUARD_TIME_US_DEFAULT;

    rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_I2C_INTF_CAP, &i2c_caps, sizeof (i2c_caps));
    if (rc) {
        LOG_ERROR ("Failed to read the TPM_I2C_INTERFACE_CAPABILITY register");
        return rc;
    }

    rc = tcti_helper_common_sanity_check (TCTI_HELPER_COMMON_REG_TPM_I2C_INTF_CAP, (uint8_t *)&i2c_caps, sizeof (i2c_caps));
    if (rc) {
        return rc;
    }

    i2c_caps = LE_TO_HOST_32 (i2c_caps);

    ctx->i2c_guard_time_read  = (i2c_caps & TCTI_HELPER_COMMON_I2C_GUARD_TIME_RR_MASK) ||
                                (i2c_caps & TCTI_HELPER_COMMON_I2C_GUARD_TIME_RW_MASK);
    ctx->i2c_guard_time_write = (i2c_caps & TCTI_HELPER_COMMON_I2C_GUARD_TIME_WR_MASK) ||
                                (i2c_caps & TCTI_HELPER_COMMON_I2C_GUARD_TIME_WW_MASK);
    ctx->i2c_guard_time       = (i2c_caps & TCTI_HELPER_COMMON_I2C_GUARD_TIME_MASK) >>
                                TCTI_HELPER_COMMON_I2C_GUARD_TIME_SHIFT;

    if (ctx->i2c_guard_time_read) {
        LOG_DEBUG ("I2c guard time enabled after read");
    }

    if (ctx->i2c_guard_time_write) {
        LOG_DEBUG ("I2c guard time enabled after write");
    }

    if (ctx->i2c_guard_time_read || ctx->i2c_guard_time_write) {
        LOG_DEBUG ("I2c GUARD_TIME value: %"PRIu8" us", ctx->i2c_guard_time);
    } else {
        LOG_DEBUG ("No GUARD_TIME needed");
    }

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_helper_common_enable_crc (TCTI_HELPER_COMMON_CONTEXT *ctx)
{
    TSS2_RC rc;
    uint8_t crc_enable;

    rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM_ENABLE, &crc_enable, sizeof (crc_enable));
    if (rc) {
        LOG_ERROR ("Failed to read the TPM_DATA_CSUM_ENABLE register");
        return rc;
    }

    if (crc_enable == 1) {
        return TSS2_RC_SUCCESS;
    }

    crc_enable = 1;
    rc = ctx->write_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM_ENABLE, &crc_enable, sizeof (crc_enable));
    if (rc) {
        LOG_ERROR ("Failed to write to TPM_DATA_CSUM_ENABLE register");
        return rc;
    }

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_helper_common_verify_crc (TCTI_HELPER_COMMON_CONTEXT *ctx, const uint8_t* buffer, size_t size)
{
    TSS2_RC rc;
    uint16_t crc_tpm = 0;
    uint16_t crc_host = 0;

    rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM, &crc_tpm, sizeof (crc_tpm));
    if (rc) {
        LOG_ERROR ("Failed to read the TPM_DATA_CSUM register");
        return rc;
    }

    crc_tpm = LE_TO_HOST_16 (crc_tpm);
    crc_tpm = ((crc_tpm >> 8) & 0xFFu) | ((crc_tpm << 8) & 0xFF00u);
    crc_host = crc_ccitt (buffer, size);

    if (crc_tpm == crc_host) {
        return TSS2_RC_SUCCESS;
    }

    return TSS2_TCTI_RC_IO_ERROR;
}

TSS2_RC Tcti_Helper_Common_Init (TCTI_HELPER_COMMON_CONTEXT *ctx, bool is_i2c)
{
    TSS2_RC rc;
    uint8_t rid = 0;
    uint32_t did_vid = 0;
    uint32_t expected_status_bits = TCTI_HELPER_COMMON_TPM_STS_COMMAND_READY;

    LOG_DEBUG ("Probing TPM...");

    for (int retries = 100; retries > 0; retries--) {
        /* In case of failed read div_vid is set to zero */
        ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_DID_VID, &did_vid, sizeof (did_vid));
        if (did_vid != 0) break;
        /* TPM might be resetting, let's retry in a bit */
        rc = ctx->sleep_ms (ctx->data, POLLING_INTERVAL_MS);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to invoke sleep_ms()");
            return rc;
        }
    }
    if (did_vid == 0) {
        LOG_ERROR ("Probing TPM failed");
        return TSS2_TCTI_RC_IO_ERROR;
    }
    LOG_DEBUG ("Probing TPM successful");

    if (is_i2c) {
        /* Read i2c guard time */
        LOG_DEBUG ("Reading the i2c GUARD_TIME value");
        rc = tcti_helper_common_read_guard_time (ctx);
        if (rc != TSS2_RC_SUCCESS) {
            return TSS2_TCTI_RC_IO_ERROR;
        }

        /* Enable Data Checksum */
        LOG_DEBUG ("Enable Data Checksum");
        rc = tcti_helper_common_enable_crc (ctx);
        if (rc != TSS2_RC_SUCCESS) {
            return TSS2_TCTI_RC_IO_ERROR;
        }
    }

    ctx->is_i2c = is_i2c;

    /* Claim locality */
    LOG_DEBUG ("Claiming TPM locality...");
    rc = tcti_helper_common_claim_locality (ctx);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Wait up to TIMEOUT_B for TPM to become ready */
    LOG_DEBUG ("Waiting for TPM to become ready...");
    rc = tcti_helper_common_wait_for_status (ctx, expected_status_bits, expected_status_bits, TIMEOUT_B);
    if (rc == TSS2_TCTI_RC_TRY_AGAIN) {
        /*
         * TPM did not auto transition into ready state,
         * write 1 to commandReady to start the transition.
         */
        if ((rc = tcti_helper_common_write_sts_reg (ctx, TCTI_HELPER_COMMON_TPM_STS_COMMAND_READY))) {
            LOG_ERROR ("Failed to write the commandReady bit to TPM_STS register");
            return rc;
        }
        rc = tcti_helper_common_wait_for_status (ctx, expected_status_bits, expected_status_bits, TIMEOUT_B);
    }

    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to wait for the TPM to become ready");
        return rc;
    }

    LOG_DEBUG ("TPM is ready");

    /* Get rid */
    rc = ctx->read_reg (ctx->data, TCTI_HELPER_COMMON_REG_TPM_RID, &rid, sizeof(rid));
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to read the TPM_RID register");
        return rc;
    }

#if MAXLOGLEVEL >= LOGL_INFO
    /* Print device details */
    uint16_t vendor_id, device_id;
    vendor_id = did_vid & 0xffff;
    device_id = did_vid >> 16;
    LOG_DEBUG ("Connected to TPM with vid:did:rid of 0x%04" PRIx16 ":%04" PRIx16 ":%02" PRIx8, vendor_id, device_id, rid);
#endif

    return TSS2_RC_SUCCESS;
}

TSS2_RC Tcti_Helper_Common_Transmit (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t size, const uint8_t *cmd_buf)
{
    TSS2_RC rc;
    tpm_header_t header;
    uint32_t expected_status_bits;

    if (ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    rc = header_unmarshal (cmd_buf, &header);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (header.size != size) {
        LOG_ERROR ("Buffer size parameter: %zu, and TPM2 command header size "
                   "field: %" PRIu32 " disagree.", size, header.size);
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    LOGBLOB_DEBUG (cmd_buf, size, "Sending command with TPM_CC 0x%08"PRIx32" and size %" PRIu32,
               header.code, header.size);

    /* Tell TPM to expect command */
    rc = tcti_helper_common_write_sts_reg (ctx, TCTI_HELPER_COMMON_TPM_STS_COMMAND_READY);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to write the commandReady bit to TPM_STS register");
        return rc;
    }

    /* Wait until ready bit is set by TPM device */
    expected_status_bits = TCTI_HELPER_COMMON_TPM_STS_COMMAND_READY;
    rc = tcti_helper_common_wait_for_status (ctx, expected_status_bits, expected_status_bits, TIMEOUT_B);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to wait for the TPM to become ready (commandReady == 1)");
        return rc;
    }

    /* Send the first byte of the command */
    rc = tcti_helper_common_fifo_transfer (ctx, (void *)cmd_buf, 1, TCTI_HELPER_COMMON_FIFO_TRANSMIT_1);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to send the command");
        return rc;
    }

    /* Send all but the last byte in the FIFO */
    rc = tcti_helper_common_fifo_transfer (ctx, (void *)(cmd_buf + 1), size - 2, TCTI_HELPER_COMMON_FIFO_TRANSMIT_2);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to send the command");
        return rc;
    }

    /* Send the last byte */
    rc = tcti_helper_common_fifo_transfer (ctx, (void *)(cmd_buf + size - 1), 1, TCTI_HELPER_COMMON_FIFO_TRANSMIT_2);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to send the command");
        return rc;
    }

    /* Await TPM readiness */
    expected_status_bits = TCTI_HELPER_COMMON_TPM_STS_VALID | TCTI_HELPER_COMMON_TPM_STS_DATA_EXPECT;
    rc = tcti_helper_common_wait_for_status (ctx, expected_status_bits, TCTI_HELPER_COMMON_TPM_STS_VALID, TIMEOUT_A);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to wait for the TPM to become ready (expect == 0)");
        return rc;
    }

    if (ctx->is_i2c) {
        /* Verify CRC */
        rc = tcti_helper_common_verify_crc (ctx, cmd_buf, size);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("CRC mismatch detected for the command");
            return rc;
        }
    }

    /* Tell TPM to start processing the command */
    tcti_helper_common_write_sts_reg (ctx, TCTI_HELPER_COMMON_TPM_STS_GO);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to write the tpmGo bit to TPM_STS register");
        return rc;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC Tcti_Helper_Common_Receive (TCTI_HELPER_COMMON_CONTEXT *ctx, size_t *response_size, unsigned char *response_buffer, int32_t timeout)
{
    (void) timeout;
    TSS2_RC rc;
    size_t bytes_to_go;
    uint32_t expected_status_bits = TCTI_HELPER_COMMON_TPM_STS_VALID | TCTI_HELPER_COMMON_TPM_STS_DATA_AVAIL;

    if (ctx == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    /* Check if we already have received the header */
    if (ctx->response_size == 0) {
        /* Wait for response to be ready */
        rc = tcti_helper_common_wait_for_status (ctx, expected_status_bits, expected_status_bits, TIMEOUT_A);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to wait for the TPM to become ready (dataAvail == 1)");
            /* Return rc from wait_for_status(). May be TRY_AGAIN after timeout */
            return rc;
        }

        /* Read only response header into context header buffer */
        rc = tcti_helper_common_fifo_transfer (ctx, ctx->header, TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE, TCTI_HELPER_COMMON_FIFO_RECEIVE);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed to read the response header");
            return TSS2_TCTI_RC_IO_ERROR;
        }

        /* Find out the total payload size, skipping the two byte tag and update tcti_common */
        ctx->response_size = tcti_helper_common_read_be32 (ctx->header + 2);
        LOG_TRACE ("Response size: %" PRIu32 " bytes", ctx->response_size);
    }

    /* Check if response size is requested */
    if (response_buffer == NULL) {
        *response_size = ctx->response_size;
        LOG_TRACE ("Caller requested response size. Returning size of %" PRIu32 " bytes", (uint32_t)*response_size);
        return TSS2_RC_SUCCESS;
    }

    /* Check if response fits in buffer and update response size */
    if (ctx->response_size > *response_size) {
        LOG_ERROR ("The buffer size is smaller than the response size");
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    *response_size = ctx->response_size;

    /* Receive the TPM response */
    LOG_TRACE ("Reading a response of size %" PRIu32, ctx->response_size);

    /* Copy already received header into response buffer */
    memcpy (response_buffer, ctx->header, TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE);

    /* Read all but the last byte in the FIFO */
    bytes_to_go = ctx->response_size - 1 - TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE;
    rc = tcti_helper_common_fifo_transfer (ctx, response_buffer + TCTI_HELPER_COMMON_RESP_HEADER_MIN_SIZE, bytes_to_go, TCTI_HELPER_COMMON_FIFO_RECEIVE);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to read the response");
        return rc;
    }

    /* Read the last byte */
    rc = tcti_helper_common_fifo_transfer (ctx, response_buffer + ctx->response_size - 1, 1, TCTI_HELPER_COMMON_FIFO_RECEIVE);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Verify that there is no more data available */
    rc = tcti_helper_common_wait_for_status (ctx, expected_status_bits, TCTI_HELPER_COMMON_TPM_STS_VALID, TIMEOUT_A);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to wait for the TPM to become ready (dataAvail == 0)");
        /* Return rc from wait_for_status(). May be TRY_AGAIN after timeout */
        return rc;
    }

    LOGBLOB_DEBUG(response_buffer, ctx->response_size, "Response buffer received:");

    if (ctx->is_i2c) {
        /* Verify CRC */
        rc = tcti_helper_common_verify_crc (ctx, response_buffer, *response_size);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("CRC mismatch detected for the response");
            return rc;
        }
    }

    /* Set the TPM back to idle state */
    rc = tcti_helper_common_write_sts_reg (ctx, TCTI_HELPER_COMMON_TPM_STS_COMMAND_READY);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to write the commandReady bit to TPM_STS register");
        return rc;
    }

    ctx->response_size = 0;

    return TSS2_RC_SUCCESS;
}
