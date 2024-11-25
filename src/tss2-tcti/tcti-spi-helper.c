/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Fraunhofer SIT. All rights reserved.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"                // for MAXLOGLEVEL
#endif

#include <inttypes.h>              // for uint8_t, uint32_t, PRIu32, PRIx32
#include <stdbool.h>               // for bool, false, true
#include <stdio.h>                 // for NULL, size_t
#include <string.h>                // for memcpy, memset

#include "tcti-common.h"           // for TSS2_TCTI_COMMON_CONTEXT, tpm_head...
#include "tcti-spi-helper.h"
#include "tcti-helper-common.h"
#include "tss2_common.h"           // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_TCT...
#include "tss2_tcti.h"             // for TSS2_TCTI_CONTEXT, TSS2_TCTI_INFO
#include "tss2_tcti_spi_helper.h"  // for TSS2_TCTI_SPI_HELPER_PLATFORM, Tss...
#include "util/tss2_endian.h"      // for LE_TO_HOST_32

#define LOGMODULE tcti
#include "util/log.h"              // for LOG_ERROR, LOG_DEBUG, return_if_error

static TSS2_RC tcti_spi_helper_build_header (enum TCTI_HELPER_COMMON_REG reg, uint32_t *spi_header)
{
    switch (reg) {
    case TCTI_HELPER_COMMON_REG_TPM_ACCESS:
        *spi_header = TCTI_SPI_HELPER_HEAD_TPM_ACCESS;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_STS:
        *spi_header = TCTI_SPI_HELPER_HEAD_TPM_STS;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_DATA_FIFO:
        *spi_header = TCTI_SPI_HELPER_HEAD_TPM_DATA_FIFO;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_DID_VID:
        *spi_header = TCTI_SPI_HELPER_HEAD_TPM_DID_VID;
        break;
    case TCTI_HELPER_COMMON_REG_TPM_RID:
        *spi_header = TCTI_SPI_HELPER_HEAD_TPM_RID;
        break;
    default:
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

static inline TSS2_RC tcti_spi_helper_delay_ms (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx, int milliseconds)
{
    /* Sleep a specified amount of milliseconds */
    return ctx->platform.sleep_ms (ctx->platform.user_data, milliseconds);
}

static inline TSS2_RC tcti_spi_helper_start_timeout (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx, int milliseconds)
{
    /* Start a timeout timer with the specified amount of milliseconds */
    return ctx->platform.start_timeout (ctx->platform.user_data, milliseconds);
}

static inline TSS2_RC tcti_spi_helper_timeout_expired (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx, bool *result)
{
    /* Check if the last started tiemout expired */
    return ctx->platform.timeout_expired (ctx->platform.user_data, result);
}

static inline TSS2_RC tcti_spi_helper_spi_acquire (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx)
{
    if (ctx->platform.spi_acquire == NULL) {
        return TSS2_RC_SUCCESS;
    }

    /* Reserve SPI bus until transaction is over and keep pulling CS */
    return ctx->platform.spi_acquire (ctx->platform.user_data);
}

static inline TSS2_RC tcti_spi_helper_spi_release (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx)
{
    if (ctx->platform.spi_release == NULL) {
        return TSS2_RC_SUCCESS;
    }

    /* Release SPI bus and release CS */
    return ctx->platform.spi_release (ctx->platform.user_data);
}

static inline TSS2_RC tcti_spi_helper_spi_transfer (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx, const void *data_out, void *data_in, size_t cnt)
{
    /* Perform SPI transaction with cnt bytes */
    return ctx->platform.spi_transfer (ctx->platform.user_data, data_out, data_in, cnt);
}

static inline void tcti_spi_helper_platform_finalize (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx)
{
    /* Free user_data and resources inside */
    if (ctx->platform.finalize)
        ctx->platform.finalize (ctx->platform.user_data);
}

static TSS2_RC tcti_spi_helper_start_transaction (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx, enum TCTI_SPI_HELPER_REGISTER_ACCESS_TYPE access, size_t bytes, uint32_t spi_header)
{
    TSS2_RC rc;

    /* Build spi header */
    uint8_t header[4];

    /* Transaction type and transfer size */
    header[0] = ((access == TCTI_SPI_HELPER_REGISTER_READ) ? 0x80 : 0x00) | (bytes - 1);

    /* TPM register spi_headeress */
    header[1] = spi_header >> 16 & 0xff;
    header[2] = spi_header >> 8  & 0xff;
    header[3] = spi_header >> 0  & 0xff;

    /* Reserve SPI bus until transaction is over and keep pulling CS */
    rc = tcti_spi_helper_spi_acquire (ctx);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Send header */
    uint8_t header_response[4];
    rc = tcti_spi_helper_spi_transfer (ctx, header, header_response, 4);
    if (rc != TSS2_RC_SUCCESS) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Wait until the TPM exits the wait state and sends a 1 bit */
    uint8_t byte;

    /* The 1 bit is often already set in the last byte of the transaction header */
    byte = header_response[3];
    if (byte & 1) {
        return TSS2_RC_SUCCESS;
    }

    /*
     * With most current TPMs there shouldn't be any more waitstate at all, but according to
     * the spec, we have to retry until there is no more waitstate inserted. So we try again
     * a few times by reading only one byte at a time and waiting in between.
     */
    uint8_t zero = 0;
    for (int retries = 256; retries > 0; retries--) {
        rc = tcti_spi_helper_spi_transfer (ctx, &zero, &byte, 1);
        if (rc != TSS2_RC_SUCCESS) {
            return TSS2_TCTI_RC_IO_ERROR;
        }
        if (byte & 1) {
            return TSS2_RC_SUCCESS;
        }
        rc = tcti_spi_helper_delay_ms (ctx, 1);
        return_if_error (rc, "tcti_spi_helper_delay_ms");
    }

    /* The TPM did not exit the wait state in time */
    return TSS2_TCTI_RC_IO_ERROR;
}

static TSS2_RC tcti_spi_helper_end_transaction (TSS2_TCTI_SPI_HELPER_CONTEXT *ctx)
{
    /* Release CS (ends the transaction) and release the bus for other devices */
    return tcti_spi_helper_spi_release (ctx);
}

static void tcti_spi_helper_log_register_access (enum TCTI_SPI_HELPER_REGISTER_ACCESS_TYPE access, uint32_t spi_header, const void *buffer, size_t cnt, char* err) {

#if MAXLOGLEVEL == LOGL_NONE
    (void) access;
    (void) spi_header;
    (void) buffer;
    (void) cnt;
    (void) err;
#else
    /* Print register access debug information */
    char* access_str = (access == TCTI_SPI_HELPER_REGISTER_READ) ? "READ from" : "WRITE to";
    uint16_t reg_addr = (uint16_t)(spi_header & 0xFFFF);

    if (err != NULL) {
        LOG_ERROR ("%s register 0x%04"PRIx16" (%zu bytes) %s", access_str, reg_addr, cnt, err);
    } else {
#if MAXLOGLEVEL < LOGL_TRACE
        (void) buffer;
#else
        LOGBLOB_TRACE (buffer, cnt, "%s register 0x%04"PRIx16, access_str, reg_addr);
#endif
    }
#endif
}

static size_t tcti_spi_helper_no_waitstate_preprocess (enum TCTI_SPI_HELPER_REGISTER_ACCESS_TYPE access, uint32_t addr, uint8_t *buffer1, uint8_t *buffer2, size_t cnt)
{
    /* Transaction type and transfer size */
    buffer2[0] = ((access == TCTI_SPI_HELPER_REGISTER_READ) ? 0x80 : 0x00) | (cnt - 1);

    /* TPM register address */
    buffer2[1] = addr >> 16 & 0xff;
    buffer2[2] = addr >> 8  & 0xff;
    buffer2[3] = addr >> 0  & 0xff;

    if (access == TCTI_SPI_HELPER_REGISTER_WRITE) {
        memcpy(&buffer2[4], buffer1, cnt);
    } else {
        memset(&buffer2[4], 0, cnt);
    }

    return cnt + 4;
}

static void tcti_spi_helper_no_waitstate_postprocess (enum TCTI_SPI_HELPER_REGISTER_ACCESS_TYPE access, uint8_t *buffer1, uint8_t *buffer2, size_t cnt)
{
    if (access == TCTI_SPI_HELPER_REGISTER_WRITE) {
        return;
    }

    memcpy(buffer1, &buffer2[4], cnt - 4);
}

static TSS2_RC tcti_spi_helper_check_platform_conf (TSS2_TCTI_SPI_HELPER_PLATFORM *platform_conf)
{

    bool required_set = platform_conf->sleep_ms && platform_conf->spi_transfer \
            && platform_conf->start_timeout && platform_conf->timeout_expired;
    if (!required_set) {
        LOG_ERROR("Expected sleep_ms, spi_transfer, start_timeout and timeout_expired to be set.");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (!!platform_conf->spi_acquire != !!platform_conf->spi_release) {
        LOG_ERROR("Expected spi_acquire and spi_release to both be NULL or set.");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the device TCTI context. The only safe-guard we have to ensure
 * this operation is possible is the magic number for the device TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
static TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC (tcti_ctx) == TCTI_SPI_HELPER_MAGIC) {
        return (TSS2_TCTI_SPI_HELPER_CONTEXT*)tcti_ctx;
    }
    return NULL;
}

/*
 * This function down-casts the device TCTI context to the common context
 * defined in the tcti-common module.
 */
static TSS2_TCTI_COMMON_CONTEXT* tcti_spi_helper_down_cast_tcti_common (TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper)
{
    if (tcti_spi_helper == NULL) {
        return NULL;
    }
    return &tcti_spi_helper->common;
}

/*
 * This function down-casts the device TCTI context to the helper common context
 * defined in the tcti-helper-common module.
 */
static TCTI_HELPER_COMMON_CONTEXT* tcti_spi_helper_down_cast_helper_common (TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper)
{
    if (tcti_spi_helper == NULL) {
        return NULL;
    }
    return &tcti_spi_helper->helper_common;
}


TSS2_RC tcti_spi_helper_transmit (TSS2_TCTI_CONTEXT *tcti_context, size_t size, const uint8_t *cmd_buf)
{
    TSS2_RC rc;
    TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper = tcti_spi_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_spi_helper_down_cast_tcti_common (tcti_spi_helper);
    TCTI_HELPER_COMMON_CONTEXT *helper_common = tcti_spi_helper_down_cast_helper_common (tcti_spi_helper);

    if (tcti_spi_helper == NULL) {
        return TSS2_BASE_RC_BAD_CONTEXT;
    }

    rc = tcti_common_transmit_checks (tcti_common, cmd_buf, TCTI_SPI_HELPER_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tcti_Helper_Common_Transmit (helper_common, size, cmd_buf);
    if (rc == TSS2_RC_SUCCESS) {
        tcti_common->state = TCTI_STATE_RECEIVE;
    }

    return rc;
}

TSS2_RC tcti_spi_helper_receive (TSS2_TCTI_CONTEXT *tcti_context, size_t *response_size, unsigned char *response_buffer, int32_t timeout)
{
    TSS2_RC rc;
    TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper = tcti_spi_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_spi_helper_down_cast_tcti_common (tcti_spi_helper);
    TCTI_HELPER_COMMON_CONTEXT *helper_common = tcti_spi_helper_down_cast_helper_common (tcti_spi_helper);

    if (tcti_spi_helper == NULL) {
        return TSS2_BASE_RC_BAD_CONTEXT;
    }

    rc = tcti_common_receive_checks (tcti_common, response_size, TCTI_SPI_HELPER_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tcti_Helper_Common_Receive (helper_common, response_size, response_buffer, timeout);
    if (response_buffer != NULL && rc == TSS2_RC_SUCCESS) {
        tcti_common->state = TCTI_STATE_TRANSMIT;
    }

    return rc;
}

void tcti_spi_helper_finalize (TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper = tcti_spi_helper_context_cast (tcti_context);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_spi_helper_down_cast_tcti_common (tcti_spi_helper);

    if (tcti_spi_helper == NULL) {
        return;
    }
    tcti_common->state = TCTI_STATE_FINAL;

    /* Free platform struct user data and resources inside */
    tcti_spi_helper_platform_finalize (tcti_spi_helper);
}

TSS2_RC tcti_spi_helper_cancel (TSS2_TCTI_CONTEXT *tcti_context)
{
    (void)(tcti_context);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_spi_helper_get_poll_handles (TSS2_TCTI_CONTEXT *tcti_context, TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles)
{
    (void)(tcti_context);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_spi_helper_set_locality (TSS2_TCTI_CONTEXT *tcti_context, uint8_t locality)
{
    (void)(tcti_context);
    (void)(locality);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC tcti_spi_helper_common_sleep_ms (void *data, int milliseconds)
{
    TSS2_TCTI_SPI_HELPER_CONTEXT *ctx = (TSS2_TCTI_SPI_HELPER_CONTEXT *) data;
    return tcti_spi_helper_delay_ms (ctx, milliseconds);
}

TSS2_RC tcti_spi_helper_common_start_timeout (void *data, int milliseconds)
{
    TSS2_TCTI_SPI_HELPER_CONTEXT *ctx = (TSS2_TCTI_SPI_HELPER_CONTEXT *) data;
    return tcti_spi_helper_start_timeout (ctx, milliseconds);
}

TSS2_RC tcti_spi_helper_common_timeout_expired (void *data, bool *result)
{
    TSS2_TCTI_SPI_HELPER_CONTEXT *ctx = (TSS2_TCTI_SPI_HELPER_CONTEXT *) data;
    return tcti_spi_helper_timeout_expired (ctx, result);
}

TSS2_RC tcti_spi_helper_common_read_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, void *buffer, size_t cnt)
{
    TSS2_RC rc;
    TSS2_TCTI_SPI_HELPER_CONTEXT *ctx = (TSS2_TCTI_SPI_HELPER_CONTEXT *) data;
    enum TCTI_SPI_HELPER_REGISTER_ACCESS_TYPE access = TCTI_SPI_HELPER_REGISTER_READ;
    bool has_waitstate = true;
    uint32_t spi_header = 0;
    uint8_t buffer2[68];
    size_t cnt2 = 0;

    /* Check maximum register transfer size is 64 byte */
    if (cnt > 64) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Detect wait state configuration */
    if (ctx->platform.spi_acquire == NULL || ctx->platform.spi_release == NULL) {
        has_waitstate = false;
    }

    /* Set register address */
    if ((rc = tcti_spi_helper_build_header (reg, &spi_header))) {
        return rc;
    }

    if (has_waitstate) {
        /* Start read transaction */
        rc = tcti_spi_helper_start_transaction (ctx, access, cnt, spi_header);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_log_register_access (access, spi_header, NULL, cnt, "failed in transaction start");
            tcti_spi_helper_end_transaction (ctx);
            return TSS2_TCTI_RC_IO_ERROR;
        }
        /* Read register */
        rc = tcti_spi_helper_spi_transfer (ctx, NULL, buffer, cnt);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_log_register_access (access, spi_header, NULL, cnt, "failed in transfer");
            tcti_spi_helper_end_transaction (ctx);
            return TSS2_TCTI_RC_IO_ERROR;
        }
        /* End transaction */
        rc = tcti_spi_helper_end_transaction (ctx);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_log_register_access (access, spi_header, NULL, cnt, "failed ending the transaction");
            return TSS2_TCTI_RC_IO_ERROR;
        }
    } else {
        /* Append header */
        cnt2 = tcti_spi_helper_no_waitstate_preprocess (access, spi_header, (uint8_t *)buffer, buffer2, cnt);
        /* Read register */
        rc = tcti_spi_helper_spi_transfer (ctx, buffer2, buffer2, cnt2);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_log_register_access (access, spi_header, NULL, cnt, "failed in transfer");
            tcti_spi_helper_end_transaction (ctx);
            return TSS2_TCTI_RC_IO_ERROR;
        }
        /* Trim the response */
        tcti_spi_helper_no_waitstate_postprocess (access, (uint8_t *)buffer, buffer2, cnt2);
    }

    /* Print debug information and return success */
    tcti_spi_helper_log_register_access (access, spi_header, buffer, cnt, NULL);
    return TSS2_RC_SUCCESS;
}

TSS2_RC tcti_spi_helper_common_write_reg (void *data, enum TCTI_HELPER_COMMON_REG reg, const void *buffer, size_t cnt)
{
    TSS2_RC rc;
    TSS2_TCTI_SPI_HELPER_CONTEXT *ctx = (TSS2_TCTI_SPI_HELPER_CONTEXT *) data;
    enum TCTI_SPI_HELPER_REGISTER_ACCESS_TYPE access = TCTI_SPI_HELPER_REGISTER_WRITE;
    bool has_waitstate = true;
    uint32_t spi_header = 0;
    uint8_t buffer2[68];
    size_t cnt2 = 0;

    /* Check maximum register transfer size is 64 byte */
    if (cnt > 64) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Detect wait state configuration */
    if (ctx->platform.spi_acquire == NULL || ctx->platform.spi_release == NULL) {
        has_waitstate = false;
    }

    /* Set register address */
    if ((rc = tcti_spi_helper_build_header (reg, &spi_header))) {
        return rc;
    }

    /* Start write transaction */
    if (has_waitstate) {
        rc = tcti_spi_helper_start_transaction (ctx, access, cnt, spi_header);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_end_transaction (ctx);
            tcti_spi_helper_log_register_access (access, spi_header, buffer, cnt, "failed in transaction start");
            return TSS2_TCTI_RC_IO_ERROR;
        }
        /* Write register */
        rc = tcti_spi_helper_spi_transfer (ctx, buffer, NULL, cnt);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_end_transaction (ctx);
            tcti_spi_helper_log_register_access (access, spi_header, buffer, cnt, "failed in transfer");
            return TSS2_TCTI_RC_IO_ERROR;
        }
        /* End transaction */
        rc = tcti_spi_helper_end_transaction (ctx);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_log_register_access (access, spi_header, NULL, cnt, "failed ending the transaction");
            return TSS2_TCTI_RC_IO_ERROR;
        }
    } else {
        /* Append header */
        cnt2 = tcti_spi_helper_no_waitstate_preprocess (access, spi_header, (uint8_t *)buffer, buffer2, cnt);
        /* Write register */
        rc = tcti_spi_helper_spi_transfer (ctx, buffer2, NULL, cnt2);
        if (rc != TSS2_RC_SUCCESS) {
            tcti_spi_helper_end_transaction (ctx);
            tcti_spi_helper_log_register_access (access, spi_header, buffer, cnt, "failed in transfer");
            return TSS2_TCTI_RC_IO_ERROR;
        }
    }

    /* Print debug information and return success */
    tcti_spi_helper_log_register_access (access, spi_header, buffer, cnt, NULL);
    return TSS2_RC_SUCCESS;
}

TSS2_RC Tss2_Tcti_Spi_Helper_Init (TSS2_TCTI_CONTEXT *tcti_context, size_t *size, TSS2_TCTI_SPI_HELPER_PLATFORM *platform_conf)
{
    TSS2_RC rc;
    TSS2_TCTI_SPI_HELPER_CONTEXT *tcti_spi_helper;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common;

    if (!size) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Check if context size is requested */
    if (tcti_context == NULL) {
        *size = sizeof (TSS2_TCTI_SPI_HELPER_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    if (!platform_conf) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (*size < sizeof (TSS2_TCTI_SPI_HELPER_CONTEXT)) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    /* Init TCTI context */
    TSS2_TCTI_MAGIC (tcti_context) = TCTI_SPI_HELPER_MAGIC;
    TSS2_TCTI_VERSION (tcti_context) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_context) = tcti_spi_helper_transmit;
    TSS2_TCTI_RECEIVE (tcti_context) = tcti_spi_helper_receive;
    TSS2_TCTI_FINALIZE (tcti_context) = tcti_spi_helper_finalize;
    TSS2_TCTI_CANCEL (tcti_context) = tcti_spi_helper_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_context) = tcti_spi_helper_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_context) = tcti_spi_helper_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_context) = tcti_make_sticky_not_implemented;

    /* Init SPI TCTI context */
    tcti_spi_helper = tcti_spi_helper_context_cast (tcti_context);
    tcti_common = tcti_spi_helper_down_cast_tcti_common (tcti_spi_helper);
    tcti_common->state = TCTI_STATE_TRANSMIT;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));
    tcti_common->locality = 0;

    rc = tcti_spi_helper_check_platform_conf (platform_conf);
    return_if_error (rc, "invalid platform_conf");

    /* Copy platform struct into context */
    tcti_spi_helper->platform = *platform_conf;

    /* Register the callback functions before using the Tcti_Helper_Common_ functions */
    TCTI_HELPER_COMMON_CONTEXT helper_common = {
        .data = (void *)tcti_spi_helper,
        .sleep_ms = tcti_spi_helper_common_sleep_ms,
        .start_timeout = tcti_spi_helper_common_start_timeout,
        .timeout_expired = tcti_spi_helper_common_timeout_expired,
        .read_reg = tcti_spi_helper_common_read_reg,
        .write_reg = tcti_spi_helper_common_write_reg,
    };
    tcti_spi_helper->helper_common = helper_common;

    /* TPM probing */
    rc = Tcti_Helper_Common_Init (&tcti_spi_helper->helper_common, false);
    return_if_error (rc, "tcti initialization sequence has failed");

    return TSS2_RC_SUCCESS;
}

static const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-spi-helper",
    .description = "Platform independent TCTI for communication with TPMs over SPI.",
    .config_help = "TSS2_TCTI_SPI_HELPER_PLATFORM struct containing platform methods. See tss2_tcti_spi_helper.h for more information.",

    /*
     * The Tss2_Tcti_Spi_Helper_Init method has a different signature than required by .init due too
     * our custom platform_conf parameter, so we can't expose it here and it has to be used directly.
     */
    .init = NULL,
};

const TSS2_TCTI_INFO *Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
