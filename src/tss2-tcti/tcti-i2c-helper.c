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
#include "config.h"                // for MAXLOGLEVEL
#endif
#include <inttypes.h>              // for uint8_t, uint32_t, uint16_t, PRIu32
#include <stdbool.h>               // for bool, true, false
#include <stdio.h>                 // for size_t, NULL
#include <string.h>                // for memcpy, memset

#include "tcti-common.h"           // for TSS2_TCTI_COMMON_CONTEXT, tpm_head...
#include "tcti-i2c-helper.h"
#include "tcti-helper-common.h"
#include "tss2_common.h"           // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_TCT...
#include "tss2_tcti.h"             // for TSS2_TCTI_CONTEXT, TSS2_TCTI_INFO
#include "tss2_tcti_i2c_helper.h"  // for TSS2_TCTI_I2C_HELPER_PLATFORM, Tss...
#include "util/tss2_endian.h"      // for LE_TO_HOST_32, LE_TO_HOST_16, HOST...

#define LOGMODULE tcti
#include "util/log.h"              // for LOG_ERROR, LOG_DEBUG, return_if_error

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the device TCTI context. The only safe-guard we have to ensure
 * this operation is possible is the magic number for the device TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
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
TSS2_TCTI_COMMON_CONTEXT* tcti_i2c_helper_down_cast_tcti_common (TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper)
{
    if (tcti_i2c_helper == NULL) {
        return NULL;
    }
    return &tcti_i2c_helper->common;
}

/*
 * This function down-casts the device TCTI context to the helper common context
 * defined in the tcti-helper-common module.
 */
static TCTI_HELPER_COMMON_CONTEXT* tcti_i2c_helper_down_cast_helper_common (TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper)
{
    if (tcti_i2c_helper == NULL) {
        return NULL;
    }
    return &tcti_i2c_helper->helper_common;
}

static void tcti_i2c_helper_log_register_access (enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE access, uint8_t reg_addr, const void *buffer, size_t cnt, char *err)
{
#if MAXLOGLEVEL == LOGL_NONE
    (void) access;
    (void) reg_addr;
    (void) buffer;
    (void) cnt;
    (void) err;
#else
    /* Print register access debug information */
    char* access_str = (access == TCTI_I2C_HELPER_REGISTER_READ) ? "READ from" : "WRITE to";

    if (err != NULL) {
        LOG_ERROR ("%s register 0x%02"PRIx8" (%zu bytes) %s", access_str, reg_addr, cnt, err);
    } else {
#if MAXLOGLEVEL < LOGL_TRACE
        (void) buffer;
#else
        LOGBLOB_TRACE (buffer, cnt, "%s register 0x%02"PRIx8, access_str, reg_addr);
#endif
    }
#endif
}

static TSS2_RC tcti_i2c_helper_check_platform_conf (TSS2_TCTI_I2C_HELPER_PLATFORM *platform_conf)
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

static TSS2_RC tcti_i2c_helper_convert_to_addr (enum TCTI_HELPER_COMMON_REG reg, uint8_t *reg_addr)
{
    switch (reg) {
    case TCTI_HELPER_COMMON_REG_TPM_ACCESS:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_ACCESS;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_STS:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_STS;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_DATA_FIFO;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_DID_VID:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_DID_VID;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_RID:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_RID;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_DATA_CSUM;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_DATA_CSUM_ENABLE:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_DATA_CSUM_ENABLE;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_I2C_INTF_CAP:
        *reg_addr = TCTI_I2C_HELPER_REG_TPM_I2C_INTF_CAP;
        break;
    default:
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

static inline TSS2_RC tcti_i2c_helper_delay_us (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, int microseconds)
{
    /* Sleep a specified amount of microseconds */
    if (ctx->platform.sleep_us == NULL) {
        return ctx->platform.sleep_ms (ctx->platform.user_data, (microseconds < 1000) ? 1 : (microseconds / 1000));
    } else {
        return ctx->platform.sleep_us (ctx->platform.user_data, microseconds);
    }
}

static inline TSS2_RC tcti_i2c_helper_delay_ms (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, int milliseconds)
{
    /* Sleep a specified amount of milliseconds */
    if (ctx->platform.sleep_ms == NULL) {
        return ctx->platform.sleep_us (ctx->platform.user_data, milliseconds * 1000);
    } else {
        return ctx->platform.sleep_ms (ctx->platform.user_data, milliseconds);
    }
}

static inline TSS2_RC tcti_i2c_helper_start_timeout (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, int milliseconds)
{
    /* Start a timeout timer with the specified amount of milliseconds */
    return ctx->platform.start_timeout (ctx->platform.user_data, milliseconds);
}

static inline TSS2_RC tcti_i2c_helper_timeout_expired (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, bool *result)
{
    /* Check if the last started tiemout expired */
    return ctx->platform.timeout_expired (ctx->platform.user_data, result);
}

static inline TSS2_RC tcti_i2c_helper_i2c_read (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, uint8_t reg_addr, void *data, size_t cnt)
{
    TSS2_RC rc;
    int i = TCTI_I2C_HELPER_RETRY;

    do {
        /* Perform I2C read with cnt bytes */
        rc = ctx->platform.i2c_read (ctx->platform.user_data, reg_addr, data, cnt);
        if (rc == TSS2_RC_SUCCESS) {
            if (ctx->helper_common.i2c_guard_time_read) {
                tcti_i2c_helper_delay_us (ctx, ctx->helper_common.i2c_guard_time);
            }
            break;
        }

        tcti_i2c_helper_delay_us (ctx, TCTI_HELPER_COMMON_I2C_GUARD_TIME_US_DEFAULT);
    } while (--i);

    return rc;
}

static TSS2_RC tcti_i2c_helper_read_reg (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, uint8_t reg_addr, void *buffer, size_t cnt)
{
    TSS2_RC rc;
    enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE access = TCTI_I2C_HELPER_REGISTER_READ;

    /* Read register */
    rc = tcti_i2c_helper_i2c_read (ctx, reg_addr, buffer, cnt);
    if (rc != TSS2_RC_SUCCESS) {
        tcti_i2c_helper_log_register_access (access, reg_addr, NULL, cnt, "failed in transfer");
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Print debug information and return success */
    tcti_i2c_helper_log_register_access (access, reg_addr, buffer, cnt, NULL);
    return TSS2_RC_SUCCESS;
}

static inline TSS2_RC tcti_i2c_helper_i2c_write (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, uint8_t reg_addr, const void *data, size_t cnt)
{
    TSS2_RC rc;
    int i = TCTI_I2C_HELPER_RETRY;

    do {
        /* Perform I2C write with cnt bytes */
        rc = ctx->platform.i2c_write (ctx->platform.user_data, reg_addr, data, cnt);
        if (rc == TSS2_RC_SUCCESS) {
            if (ctx->helper_common.i2c_guard_time_write) {
                tcti_i2c_helper_delay_us (ctx, ctx->helper_common.i2c_guard_time);
            }
            break;
        }

        tcti_i2c_helper_delay_us (ctx, TCTI_HELPER_COMMON_I2C_GUARD_TIME_US_DEFAULT);
    } while (--i);

    return rc;
}

static TSS2_RC tcti_i2c_helper_write_reg (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx, uint8_t reg_addr, const void *buffer, size_t cnt)
{
    TSS2_RC rc;
    enum TCTI_I2C_HELPER_REGISTER_ACCESS_TYPE access = TCTI_I2C_HELPER_REGISTER_WRITE;

    /* Write register */
    rc = tcti_i2c_helper_i2c_write (ctx, reg_addr, buffer, cnt);
    if (rc != TSS2_RC_SUCCESS) {
        tcti_i2c_helper_log_register_access (access, reg_addr, buffer, cnt, "failed in transfer");
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Print debug information and return success */
    tcti_i2c_helper_log_register_access (access, reg_addr, buffer, cnt, NULL);
    return TSS2_RC_SUCCESS;
}

static inline void tcti_i2c_helper_platform_finalize (TSS2_TCTI_I2C_HELPER_CONTEXT *ctx)
{
    /* Free user_data and resources inside */
    if (ctx->platform.finalize)
        ctx->platform.finalize (ctx->platform.user_data);
}

TSS2_RC tcti_i2c_helper_transmit (TSS2_TCTI_CONTEXT *tcti_context, size_t size, const uint8_t *cmd_buf)
{
    TSS2_RC rc;
    TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_i2c_helper_down_cast_tcti_common (tcti_i2c_helper);
    TCTI_HELPER_COMMON_CONTEXT *helper_common = tcti_i2c_helper_down_cast_helper_common (tcti_i2c_helper);

    if (tcti_i2c_helper == NULL) {
        return TSS2_BASE_RC_BAD_CONTEXT;
    }

    rc = tcti_common_transmit_checks (tcti_common, cmd_buf, TCTI_I2C_HELPER_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tcti_Helper_Common_Transmit (helper_common, size, cmd_buf);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;

    return rc;
}

TSS2_RC tcti_i2c_helper_receive (TSS2_TCTI_CONTEXT *tcti_context, size_t *response_size, unsigned char *response_buffer, int32_t timeout)
{
    TSS2_RC rc;
    TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_i2c_helper_down_cast_tcti_common (tcti_i2c_helper);
    TCTI_HELPER_COMMON_CONTEXT *helper_common = tcti_i2c_helper_down_cast_helper_common (tcti_i2c_helper);

    if (tcti_i2c_helper == NULL) {
        return TSS2_BASE_RC_BAD_CONTEXT;
    }

    rc = tcti_common_receive_checks (tcti_common, response_size, TCTI_I2C_HELPER_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tcti_Helper_Common_Receive (helper_common, response_size, response_buffer, timeout);
    if (response_buffer != NULL && rc == TSS2_RC_SUCCESS) {
        tcti_common->state = TCTI_STATE_TRANSMIT;
    }

    return rc;
}

void tcti_i2c_helper_finalize (TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper = tcti_i2c_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_i2c_helper_down_cast_tcti_common (tcti_i2c_helper);

    if (tcti_i2c_helper == NULL) {
        return;
    }
    tcti_common->state = TCTI_STATE_FINAL;

    /* Free platform struct user data and resources inside */
    tcti_i2c_helper_platform_finalize (tcti_i2c_helper);
}

TSS2_RC tcti_i2c_helper_cancel (TSS2_TCTI_CONTEXT *tcti_context)
{
    (void)(tcti_context);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_i2c_helper_get_poll_handles (TSS2_TCTI_CONTEXT *tcti_context, TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles)
{
    (void)(tcti_context);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_i2c_helper_set_locality (TSS2_TCTI_CONTEXT *tcti_context, uint8_t locality)
{
    (void)(tcti_context);
    (void)(locality);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_i2c_helper_common_sleep_ms (void *data, int milliseconds)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *) data;
    return tcti_i2c_helper_delay_ms (ctx, milliseconds);
}

TSS2_RC tcti_i2c_helper_common_start_timeout (void *data, int milliseconds)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *) data;
    return tcti_i2c_helper_start_timeout (ctx, milliseconds);
}

TSS2_RC tcti_i2c_helper_common_timeout_expired (void *data, bool *result)
{
    TSS2_TCTI_I2C_HELPER_CONTEXT *ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *) data;
    return tcti_i2c_helper_timeout_expired (ctx, result);
}

TSS2_RC tcti_i2c_helper_common_read_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, void *buffer, size_t cnt)
{
    TSS2_RC rc;
    uint8_t reg_addr;
    TSS2_TCTI_I2C_HELPER_CONTEXT *ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *) data;

    if ((rc = tcti_i2c_helper_convert_to_addr (reg, &reg_addr))) {
        return rc;
    }

    return tcti_i2c_helper_read_reg (ctx, reg_addr, buffer, cnt);
}

TSS2_RC tcti_i2c_helper_common_write_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, const void *buffer, size_t cnt)
{
    TSS2_RC rc;
    uint8_t reg_addr;
    TSS2_TCTI_I2C_HELPER_CONTEXT *ctx = (TSS2_TCTI_I2C_HELPER_CONTEXT *) data;

    if ((rc = tcti_i2c_helper_convert_to_addr (reg, &reg_addr))) {
        return rc;
    }

    return tcti_i2c_helper_write_reg (ctx, reg_addr, buffer, cnt);
}

TSS2_RC Tss2_Tcti_I2c_Helper_Init (TSS2_TCTI_CONTEXT *tcti_context, size_t* size, TSS2_TCTI_I2C_HELPER_PLATFORM *platform_conf)
{
    TSS2_RC rc;
    TSS2_TCTI_I2C_HELPER_CONTEXT *tcti_i2c_helper;
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
    tcti_common = tcti_i2c_helper_down_cast_tcti_common (tcti_i2c_helper);
    tcti_common->state = TCTI_STATE_TRANSMIT;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));
    tcti_common->locality = 0;

    rc = tcti_i2c_helper_check_platform_conf (platform_conf);
    return_if_error (rc, "platform_conf invalid");

    /* Copy platform struct into context */
    tcti_i2c_helper->platform = *platform_conf;

    /* Register the callback functions before using the Tcti_Helper_Common_ functions */
    TCTI_HELPER_COMMON_CONTEXT helper_common = {
        .data = (void *)tcti_i2c_helper,
        .sleep_ms = tcti_i2c_helper_common_sleep_ms,
        .start_timeout = tcti_i2c_helper_common_start_timeout,
        .timeout_expired = tcti_i2c_helper_common_timeout_expired,
        .read_reg = tcti_i2c_helper_common_read_reg,
        .write_reg = tcti_i2c_helper_common_write_reg,
    };
    tcti_i2c_helper->helper_common = helper_common;

    /* TPM probing */
    rc = Tcti_Helper_Common_Init (&tcti_i2c_helper->helper_common, true);
    return_if_error (rc, "tcti initialization sequence has failed");

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
