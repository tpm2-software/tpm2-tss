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
#include <config.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "tss2_tcti.h"
#include "tss2_tcti_i2c_helper.h"
#include "tss2_mu.h"
#include "tcti-common.h"
#include "tcti-i2c-helper.h"
#include "util/io.h"
#include "util/tss2_endian.h"
#define LOGMODULE tcti
#include "util/log.h"

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

static uint16_t crc_ccitt (const uint8_t *buffer, int size) {
    int i;
    uint16_t result = 0;

    for (i = 0; i < size; i++) {
        uint8_t j = buffer[i] ^ result;
        result = crc16_kermit_lookup[j] ^ (result >> 8);
    }

    return result;
}

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the device TCTI context. The only safe-guard we have to ensure
 * this operation is possible is the magic number for the device TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
TSS2_TCTI_I2C_HELPER_CONTEXT* tcti_i2c_helper_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC (tcti_ctx) == TCTI_I2C_HELPER_MAGIC) {
        return (TSS2_TCTI_I2C_HELPER_CONTEXT*)tcti_ctx;
    }
    return NULL;
}

/*
 * This function down-casts the device TCTI context to the common context
 * defined in the tcti-common module.
 */
TSS2_TCTI_COMMON_CONTEXT* tcti_i2c_helper_down_cast (TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper)
{
    if (tcti_i2c_helper == NULL) {
        return NULL;
    }
    return &tcti_i2c_helper->common;
}

static inline TSS2_RC i2c_tpm_helper_delay_us (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, int microseconds)
{
    /* Sleep a specified amount of microseconds */
    if (ctx->platform.sleep_us == NULL) {
        return ctx->platform.sleep_ms (ctx->platform.user_data, (microseconds < 1000) ? 1 : (microseconds / 1000));
    } else {
        return ctx->platform.sleep_us (ctx->platform.user_data, microseconds);
    }
}

static inline TSS2_RC i2c_tpm_helper_delay_ms (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, int milliseconds)
{
    /* Sleep a specified amount of milliseconds */
    if (ctx->platform.sleep_ms == NULL) {
        return ctx->platform.sleep_us (ctx->platform.user_data, milliseconds * 1000);
    } else {
        return ctx->platform.sleep_ms (ctx->platform.user_data, milliseconds);
    }
}

static inline TSS2_RC i2c_tpm_helper_start_timeout (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, int milliseconds)
{
    /* Start a timeout timer with the specified amount of milliseconds */
    return ctx->platform.start_timeout (ctx->platform.user_data, milliseconds);
}

static inline TSS2_RC i2c_tpm_helper_timeout_expired(TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, bool *result)
{
    /* Check if the last started tiemout expired */
    return ctx->platform.timeout_expired (ctx->platform.user_data, result);
}

static inline TSS2_RC i2c_tpm_helper_i2c_write (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint8_t reg_addr, const void *data, size_t cnt)
{
    TSS2_RC rc;
    int i = TCTI_I2C_HELPER_RETRY;

    do {
        /* Perform I2C write with cnt bytes */
        rc = ctx->platform.i2c_write (ctx->platform.user_data, reg_addr, data, cnt);
        if (rc == TSS2_RC_SUCCESS) {
            if (ctx->guard_time_write) {
                i2c_tpm_helper_delay_us (ctx, ctx->guard_time);
            }
            break;
        }

        i2c_tpm_helper_delay_us (ctx, TCTI_I2C_HELPER_DEFAULT_GUARD_TIME_US);
    } while (--i);

    return rc;
}

static inline TSS2_RC i2c_tpm_helper_i2c_read (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint8_t reg_addr, void *data, size_t cnt)
{
    TSS2_RC rc;
    int i = TCTI_I2C_HELPER_RETRY;

    do {
        /* Perform I2C read with cnt bytes */
        rc = ctx->platform.i2c_read (ctx->platform.user_data, reg_addr, data, cnt);
        if (rc == TSS2_RC_SUCCESS) {
            if (ctx->guard_time_read) {
                i2c_tpm_helper_delay_us (ctx, ctx->guard_time);
            }
            break;
        }

        i2c_tpm_helper_delay_us (ctx, TCTI_I2C_HELPER_DEFAULT_GUARD_TIME_US);
    } while (--i);

    return rc;
}

static inline void i2c_tpm_helper_platform_finalize (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    /* Free user_data and resources inside */
    if (ctx->platform.finalize)
        ctx->platform.finalize (ctx->platform.user_data);
}

static TSS2_RC check_platform_conf(TSS2_TCTI_I2C_HELPER_PLATFORM *platform_conf)
{

    bool required_set = (platform_conf->sleep_ms || platform_conf->sleep_us) \
            && platform_conf->i2c_write \
            && platform_conf->i2c_read && platform_conf->start_timeout \
            && platform_conf->timeout_expired;
    if (!required_set) {
        LOG_ERROR("Expected sleep_us/sleep_ms, i2c_write, i2c_read, start_timeout and timeout_expired to be set.");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

static void i2c_tpm_helper_log_register_access (enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE access, uint8_t reg_addr, const void *buffer, size_t cnt, char* err)
{
#if MAXLOGLEVEL == LOGL_NONE
    (void) access;
    (void) reg_addr;
    (void) buffer;
    (void) cnt;
    (void) err;
#else
    /* Print register access debug information */
    char* access_str = (access == TCTI_I2C_HELPER_REGISTER_READ) ? "READ" : "WRITE";

    if (err != NULL) {
        LOG_ERROR ("%s register %#02x (%zu bytes) %s", access_str, reg_addr, cnt, err);
    } else {
#if MAXLOGLEVEL < LOGL_TRACE
        (void) buffer;
#else
        LOGBLOB_TRACE (buffer, cnt, "%s register %#02x (%zu bytes)", access_str, reg_addr, cnt);
#endif
    }
#endif
}

static TSS2_RC i2c_tpm_sanity_check_read (uint8_t reg, uint8_t *buffer, size_t cnt)
{
    uint32_t zero_mask;
    uint32_t value;

    switch (cnt) {
    case sizeof (uint8_t):
        value = buffer[0];
        break;
    case sizeof (uint16_t):
        value = le16toh (*((uint16_t *)buffer));
        break;
    case sizeof (uint32_t):
        value = le32toh (*((uint32_t *)buffer));
        break;
    default:
        return TSS2_RC_SUCCESS;
    }

    switch (reg) {
    case TCTI_I2C_HELPER_TPM_ACCESS_REG:
        zero_mask = TCTI_I2C_HELPER_TPM_ACCESS_ZERO;
        break;
    case TCTI_I2C_HELPER_TPM_STS_REG:
        zero_mask = TCTI_I2C_HELPER_TPM_STS_ZERO;
        break;
    case TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_REG:
        zero_mask = TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_ZERO;
        break;
    default:
        return TSS2_RC_SUCCESS;
    }

    if (value & zero_mask) {
        LOG_ERROR ("TPM I2C read of register 0x%02x failed sanity check", reg);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}

static TSS2_RC i2c_tpm_helper_read_reg (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint8_t reg_addr, void *buffer, size_t cnt)
{
    TSS2_RC rc;
    enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE access = TCTI_I2C_HELPER_REGISTER_READ;

    /* Read register */
    rc = i2c_tpm_helper_i2c_read (ctx, reg_addr, buffer, cnt);
    if (rc != TSS2_RC_SUCCESS) {
        i2c_tpm_helper_log_register_access (access, reg_addr, NULL, cnt, "failed in transfer");
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Sanity check, check that the 0 bits of the TPM_STS register are indeed 0s*/
    rc = i2c_tpm_sanity_check_read (reg_addr, buffer, cnt);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /* Print debug information and return success */
    i2c_tpm_helper_log_register_access (access, reg_addr, buffer, cnt, NULL);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC i2c_tpm_helper_write_reg (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint8_t reg_addr, const void *buffer, size_t cnt)
{
    TSS2_RC rc;
    enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE access = TCTI_I2C_HELPER_REGISTER_WRITE;

    /* Write register */
    rc = i2c_tpm_helper_i2c_write (ctx, reg_addr, buffer, cnt);
    if (rc != TSS2_RC_SUCCESS) {
        i2c_tpm_helper_log_register_access (access, reg_addr, buffer, cnt, "failed in transfer");
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Print debug information and return success */
    i2c_tpm_helper_log_register_access (access, reg_addr, buffer, cnt, NULL);
    return TSS2_RC_SUCCESS;
}

static uint8_t i2c_tpm_helper_read_access_reg (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    uint8_t access = 0;
    i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_ACCESS_REG, &access, sizeof(access));
    return access;
}

static void i2c_tpm_helper_write_access_reg (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint8_t access_bit)
{
    /* Writes to access register can set only 1 bit at a time */
    if (access_bit & (access_bit - 1)) {
        LOG_ERROR ("Writes to access register can set only 1 bit at a time.");
    } else {
        i2c_tpm_helper_write_reg (ctx, TCTI_I2C_HELPER_TPM_ACCESS_REG, &access_bit, sizeof(access_bit));
    }
}

static uint32_t i2c_tpm_helper_read_sts_reg (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    uint32_t status = 0;
    i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_STS_REG, &status, sizeof(status));
    return le32toh (status);
}

static void i2c_tpm_helper_write_sts_reg (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint32_t status)
{
    status = htole32 (status);
    i2c_tpm_helper_write_reg (ctx, TCTI_I2C_HELPER_TPM_STS_REG, &status, sizeof (status));
}

static uint32_t i2c_tpm_helper_get_burst_count (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    uint32_t status = i2c_tpm_helper_read_sts_reg (ctx);
    return (status & TCTI_I2C_HELPER_TPM_STS_BURST_COUNT_MASK) >> TCTI_I2C_HELPER_TPM_STS_BURST_COUNT_SHIFT;
}

static inline size_t i2c_tpm_helper_size_t_min (size_t a, size_t b) {
    if (a < b) {
        return a;
    }
    return b;
}

static inline uint32_t i2c_tpm_helper_read_be32 (const void *src)
{
    const uint8_t *s = src;
    return (((uint32_t)s[0]) << 24) | (((uint32_t)s[1]) << 16) | (((uint32_t)s[2]) << 8) | (((uint32_t)s[3]) << 0);
}

static TSS2_RC i2c_tpm_helper_claim_locality (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    uint8_t access;
    access = i2c_tpm_helper_read_access_reg (ctx);

    /* Check if locality 0 is active */
    if (access & TCTI_I2C_HELPER_TPM_ACCESS_ACTIVE_LOCALITY) {
        LOG_DEBUG ("Locality 0 is already active, status: %#x", access);
        return TSS2_RC_SUCCESS;
    }

    /* Request locality 0 */
    i2c_tpm_helper_write_access_reg (ctx, TCTI_I2C_HELPER_TPM_ACCESS_REQUEST_USE);
    access = i2c_tpm_helper_read_access_reg (ctx);
    if (access & (TCTI_I2C_HELPER_TPM_ACCESS_VALID | TCTI_I2C_HELPER_TPM_ACCESS_ACTIVE_LOCALITY)) {
        LOG_DEBUG ("Claimed locality 0");
        return TSS2_RC_SUCCESS;
    }

    LOG_ERROR ("Failed to claim locality 0, status: %#x", access);
    return TSS2_TCTI_RC_IO_ERROR;
}

static TSS2_RC i2c_tpm_helper_init_guard_time (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    TSS2_RC rc;
    uint32_t i2c_caps;

    ctx->guard_time_read = true;
    ctx->guard_time_write = true;
    ctx->guard_time = TCTI_I2C_HELPER_DEFAULT_GUARD_TIME_US;

    rc = i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_INTERFACE_CAPABILITY_REG, &i2c_caps, sizeof (i2c_caps));
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to read TPM_I2C_INTERFACE_CAPABILITY register");
        return rc;
    }

    i2c_caps = le32toh (i2c_caps);

    ctx->guard_time_read  = (i2c_caps & TCTI_I2C_HELPER_TPM_GUARD_TIME_RR_MASK) ||
                            (i2c_caps & TCTI_I2C_HELPER_TPM_GUARD_TIME_RW_MASK);
    ctx->guard_time_write = (i2c_caps & TCTI_I2C_HELPER_TPM_GUARD_TIME_WR_MASK) ||
                            (i2c_caps & TCTI_I2C_HELPER_TPM_GUARD_TIME_WW_MASK);
    ctx->guard_time       = (i2c_caps & TCTI_I2C_HELPER_TPM_GUARD_TIME_MASK) >>
                            TCTI_I2C_HELPER_TPM_GUARD_TIME_SHIFT;

    return TSS2_RC_SUCCESS;
}

static TSS2_RC i2c_tpm_helper_enable_crc (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx)
{
    TSS2_RC rc;
    uint8_t crc_enable;

    rc = i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG, &crc_enable, sizeof (crc_enable));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    if (crc_enable == 1) {
        return TSS2_RC_SUCCESS;
    }

    crc_enable = 1;
    return i2c_tpm_helper_write_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_CSUM_ENABLE_REG, &crc_enable, sizeof (crc_enable));
}

static TSS2_RC i2c_tpm_helper_wait_for_status (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint32_t status_mask, uint32_t status_expected, int32_t timeout)
{
    TSS2_RC rc;
    uint32_t status;
    bool blocking = (timeout == TSS2_TCTI_TIMEOUT_BLOCK);
    if (!blocking) {
        rc = i2c_tpm_helper_start_timeout (ctx, timeout);
        return_if_error(rc, "i2c_tpm_helper_start_timeout");
    }

    /* Wait for the expected status with or without timeout */
    bool is_timeout_expired = false;
    do {
        status = i2c_tpm_helper_read_sts_reg (ctx);
        /* Return success on expected status */
        if ((status & status_mask) == status_expected) {
            return TSS2_RC_SUCCESS;
        }
        /* Delay next poll by 8ms to avoid spamming the TPM */
        rc = i2c_tpm_helper_delay_ms (ctx, 8);
        return_if_error (rc, "i2c_tpm_helper_delay_ms");

        rc = i2c_tpm_helper_timeout_expired (ctx, &is_timeout_expired);
        return_if_error (rc, "i2c_tpm_helper_timeout_expired");
    } while (blocking || !is_timeout_expired);

    /* Timed out */
    return TSS2_TCTI_RC_TRY_AGAIN;
}

static TSS2_RC i2c_tpm_helper_verify_crc (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, const uint8_t* buffer, size_t size)
{
    (void) buffer;
    (void) size;
    TSS2_RC rc;
    uint16_t crc_tpm = 0;
    uint16_t crc_host = 0;

    rc = i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_CSUM_REG, &crc_tpm, sizeof (crc_tpm));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    crc_tpm = le16toh (crc_tpm);
    /* Reflect crc result, regardless of host endianness */
    crc_tpm = ((crc_tpm >> 8) & 0xFFu) | ((crc_tpm << 8) & 0xFF00u);
    crc_host = crc_ccitt (buffer, size);

    if (crc_tpm == crc_host) {
        return TSS2_RC_SUCCESS;
    }

    return TSS2_TCTI_RC_IO_ERROR;
}

static void i2c_tpm_helper_fifo_transfer (TSS2_TCTI_I2C_HELPER_CONTEXT* ctx, uint8_t* transfer_buffer, size_t transfer_size, enum TCTI_I2C_HELPER_FIFO_TRANSFER_DIRECTION direction)
{
    size_t transaction_size;
    size_t burst_count;
    size_t handled_so_far = 0;

    do {
        do {
            /* Can be zero when TPM is busy */
            burst_count = i2c_tpm_helper_get_burst_count (ctx);
        } while (!burst_count);

        transaction_size = transfer_size - handled_so_far;
        transaction_size = i2c_tpm_helper_size_t_min (transaction_size, burst_count);

        if (direction == TCTI_I2C_HELPER_FIFO_RECEIVE){
            i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG, (void*)(transfer_buffer + handled_so_far), transaction_size);
        } else {
            i2c_tpm_helper_write_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG, (const void*)(transfer_buffer + handled_so_far), transaction_size);
        }

        handled_so_far += transaction_size;

    } while (handled_so_far != transfer_size);
}

TSS2_RC tcti_i2c_helper_transmit (TSS2_TCTI_CONTEXT *tcti_ctx, size_t size, const uint8_t *cmd_buf)
{
    TSS2_RC rc;
    TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_ctx);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_i2c_helper_down_cast (tcti_i2c_helper);
    tpm_header_t header;

    if (tcti_i2c_helper == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    TSS2_TCTI_I2C_HELPER_CONTEXT* ctx = tcti_i2c_helper;

    rc = tcti_common_transmit_checks (tcti_common, cmd_buf, TCTI_I2C_HELPER_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    rc = header_unmarshal (cmd_buf, &header);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (header.size != size) {
        LOG_ERROR("Buffer size parameter: %zu, and TPM2 command header size "
                  "field: %" PRIu32 " disagree.", size, header.size);
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    LOGBLOB_DEBUG (cmd_buf, size, "Sending command with TPM_CC %#x and size %" PRIu32,
               header.code, header.size);

    /* Tell TPM to expect command */
    i2c_tpm_helper_write_sts_reg(ctx, TCTI_I2C_HELPER_TPM_STS_COMMAND_READY);

    /* Wait until ready bit is set by TPM device */
    uint32_t expected_status_bits = TCTI_I2C_HELPER_TPM_STS_COMMAND_READY;
    rc = i2c_tpm_helper_wait_for_status (ctx, expected_status_bits, expected_status_bits, 200);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed waiting for TPM to become ready");
        return rc;
    }

    /* Send command */
    i2c_tpm_helper_fifo_transfer (ctx, (void*)cmd_buf, size, TCTI_I2C_HELPER_FIFO_TRANSMIT);

    /* Verify CRC */
    rc = i2c_tpm_helper_verify_crc (ctx, cmd_buf, size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("CRC mismatch for command");
        return rc;
    }

    /* Tell TPM to start processing the command */
    i2c_tpm_helper_write_sts_reg (ctx, TCTI_I2C_HELPER_TPM_STS_GO);

    tcti_common->state = TCTI_STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

TSS2_RC tcti_i2c_helper_receive (TSS2_TCTI_CONTEXT* tcti_context, size_t *response_size, unsigned char *response_buffer, int32_t timeout)
{
    TSS2_RC rc;
    TSS2_TCTI_I2C_HELPER_CONTEXT* tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT* tcti_common = tcti_i2c_helper_down_cast (tcti_i2c_helper);

    if (tcti_i2c_helper == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    rc = tcti_common_receive_checks (tcti_common, response_size, TCTI_I2C_HELPER_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /* Use ctx as a shorthand for tcti_i2c_helper */
    TSS2_TCTI_I2C_HELPER_CONTEXT* ctx = tcti_i2c_helper;

    /* Expected status bits for valid status and data availabe */
    uint32_t expected_status_bits = TCTI_I2C_HELPER_TPM_STS_VALID | TCTI_I2C_HELPER_TPM_STS_DATA_AVAIL;

    /* Check if we already have received the header */
    if (tcti_common->header.size == 0) {
        /* Wait for response to be ready */
        rc = i2c_tpm_helper_wait_for_status (ctx, expected_status_bits, expected_status_bits, timeout);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed waiting for status");
            /* Return rc from wait_for_status(). May be TRY_AGAIN after timeout. */
            return rc;
        }

        /* Read only response header into context header buffer */
        rc = i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG, ctx->header, TCTI_I2C_HELPER_RESP_HEADER_SIZE);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Failed reading response header");
            return TSS2_TCTI_RC_IO_ERROR;
        }

        /* Find out the total payload size, skipping the two byte tag and update tcti_common */
        tcti_common->header.size = i2c_tpm_helper_read_be32 (ctx->header + 2);
        LOG_TRACE ("Read response size from response header: %" PRIu32 " bytes", tcti_common->header.size);
    }

    /* Check if response size is requested */
    if (response_buffer == NULL) {
        *response_size = tcti_common->header.size;
        LOG_TRACE ("Caller requested response size. Returning size of %zu bytes", *response_size);
        return TSS2_RC_SUCCESS;
    }

    /* Check if response fits in buffer and update response size */
    if (tcti_common->header.size > *response_size) {
        LOG_ERROR ("TPM response too long (%" PRIu32 " bytes)", tcti_common->header.size);
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    *response_size = tcti_common->header.size;

    /* Receive the TPM response */
    LOG_TRACE ("Reading response of size %" PRIu32, tcti_common->header.size);

    /* Copy already received header into response buffer */
    memcpy (response_buffer, ctx->header, TCTI_I2C_HELPER_RESP_HEADER_SIZE);

    /* Read all but the last byte in the FIFO */
    size_t bytes_to_go = tcti_common->header.size - 1 - TCTI_I2C_HELPER_RESP_HEADER_SIZE;
    i2c_tpm_helper_fifo_transfer (ctx, response_buffer + TCTI_I2C_HELPER_RESP_HEADER_SIZE, bytes_to_go, TCTI_I2C_HELPER_FIFO_RECEIVE);

    /* Verify that there is still data to read */
    uint32_t status = i2c_tpm_helper_read_sts_reg (ctx);
    if ((status & expected_status_bits) != expected_status_bits) {
        LOG_ERROR ("Unexpected intermediate status %#x",status);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Read the last byte */
    rc = i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_DATA_FIFO_REG, response_buffer + tcti_common->header.size - 1, 1);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Verify that there is no more data available */
    status = i2c_tpm_helper_read_sts_reg (ctx);
    if ((status & expected_status_bits) != TCTI_I2C_HELPER_TPM_STS_VALID) {
        LOG_ERROR ("Unexpected final status %#x", status);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Verify CRC */
    rc = i2c_tpm_helper_verify_crc (ctx, response_buffer, *response_size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("CRC mismatch for response");
        return rc;
    }

    LOGBLOB_DEBUG (response_buffer, tcti_common->header.size, "Response buffer received:");

    /* Set the TPM back to idle state */
    i2c_tpm_helper_write_sts_reg(ctx, TCTI_I2C_HELPER_TPM_STS_COMMAND_READY);

    tcti_common->header.size = 0;
    tcti_common->state = TCTI_STATE_TRANSMIT;

    return TSS2_RC_SUCCESS;
}

void tcti_i2c_helper_finalize (TSS2_TCTI_CONTEXT* tcti_context)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_i2c_helper_down_cast (tcti_i2c_helper);

    if (tcti_i2c_helper == NULL) {
        return;
    }
    tcti_common->state = TCTI_STATE_FINAL;

    /* Free platform struct user data and resources inside */
    i2c_tpm_helper_platform_finalize (tcti_i2c_helper);
}

TSS2_RC tcti_i2c_helper_cancel (TSS2_TCTI_CONTEXT* tcti_context)
{
    (void)(tcti_context);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_i2c_helper_get_poll_handles (TSS2_TCTI_CONTEXT* tcti_context, TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles)
{
    (void)(tcti_context);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_i2c_helper_set_locality (TSS2_TCTI_CONTEXT* tcti_context, uint8_t locality)
{
    (void)(tcti_context);
    (void)(locality);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC Tss2_Tcti_I2c_Helper_Init (TSS2_TCTI_CONTEXT* tcti_context, size_t* size, TSS2_TCTI_I2C_HELPER_PLATFORM *platform_conf)
{
    TSS2_RC rc;
    TSS2_TCTI_I2C_HELPER_CONTEXT* tcti_i2c_helper;
    TSS2_TCTI_COMMON_CONTEXT* tcti_common;

    if (!size) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Check if context size is requested */
    if (tcti_context == NULL) {
        *size = sizeof (TSS2_TCTI_I2C_HELPER_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    if (!platform_conf) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (*size < sizeof (TSS2_TCTI_I2C_HELPER_CONTEXT)) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    if (!platform_conf) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Init TCTI context */
    TSS2_TCTI_MAGIC (tcti_context) = TCTI_I2C_HELPER_MAGIC;
    TSS2_TCTI_VERSION (tcti_context) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_context) = tcti_i2c_helper_transmit;
    TSS2_TCTI_RECEIVE (tcti_context) = tcti_i2c_helper_receive;
    TSS2_TCTI_FINALIZE (tcti_context) = tcti_i2c_helper_finalize;
    TSS2_TCTI_CANCEL (tcti_context) = tcti_i2c_helper_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_context) = tcti_i2c_helper_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_context) = tcti_i2c_helper_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_context) = tcti_make_sticky_not_implemented;

    /* Init I2C TCTI context */
    tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_context);
    tcti_common = tcti_i2c_helper_down_cast (tcti_i2c_helper);
    tcti_common->state = TCTI_STATE_TRANSMIT;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));
    tcti_common->locality = 0;

    rc = check_platform_conf (platform_conf);
    return_if_error (rc, "platform_conf invalid");

    /* Copy platform struct into context */
    tcti_i2c_helper->platform = *platform_conf;

    /* Probe TPM */
    TSS2_TCTI_I2C_HELPER_CONTEXT* ctx = tcti_i2c_helper;
    LOG_DEBUG ("Probing TPM...");
    uint32_t did_vid = 0;
    for (int retries = 100; retries > 0; retries--) {
        /* In case of failed read div_vid is set to zero */
        i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_DID_VID_REG, &did_vid, sizeof(did_vid));
        if (did_vid != 0) {
            did_vid = le32toh (did_vid);
            break;
        }
        /* TPM might be resetting, let's retry in a bit */
        rc = i2c_tpm_helper_delay_ms (ctx, 10);
        return_if_error (rc, "i2c_tpm_helper_delay_ms");
    }
    if (did_vid == 0) {
        LOG_ERROR ("Probing TPM failed");
        return TSS2_TCTI_RC_IO_ERROR;
    }
    LOG_DEBUG ("Probing TPM successful");

    /* Init guard time */
    LOG_DEBUG ("Initializing guard time");
    rc = i2c_tpm_helper_init_guard_time (ctx);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Claim locality */
    LOG_DEBUG ("Claiming TPM locality");
    rc = i2c_tpm_helper_claim_locality (ctx);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Enable Data Checksum */
    LOG_DEBUG ("Enable Data Checksum");
    rc = i2c_tpm_helper_enable_crc (ctx);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Wait up to 200ms for TPM to become ready */
    LOG_DEBUG ("Waiting for TPM to become ready...");
    uint32_t expected_status_bits = TCTI_I2C_HELPER_TPM_STS_COMMAND_READY;
    rc = i2c_tpm_helper_wait_for_status (ctx, expected_status_bits, expected_status_bits, 200);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed waiting for TPM to become ready");
        return rc;
    }
    LOG_DEBUG ("TPM is ready");

    /* Get rid */
    uint8_t rid = 0;
    i2c_tpm_helper_read_reg (ctx, TCTI_I2C_HELPER_TPM_RID_REG, &rid, sizeof(rid));

#if MAXLOGLEVEL >= LOGL_INFO
    /* Print device details */
    uint16_t vendor_id, device_id, revision;
    vendor_id = did_vid & 0xffff;
    device_id = did_vid >> 16;
    revision = rid;
    LOG_INFO ("Connected to TPM with vid:did:rid of %4.4x:%4.4x:%2.2x", vendor_id, device_id, revision);
#endif

    return TSS2_RC_SUCCESS;
}

static const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-i2c-helper",
    .description = "Platform independent TCTI for communication with TPMs over I2C.",
    .config_help = "TSS2_TCTI_I2C_HELPER_PLATFORM struct containing platform methods. See tss2_tcti_i2c_helper.h for more information.",

    /*
     * The Tss2_Tcti_I2c_Helper_Init method has a different signature than required by .init due too
     * our custom platform_conf parameter, so we can't expose it here and it has to be used directly.
     */
    .init = NULL,
};

const TSS2_TCTI_INFO* Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
