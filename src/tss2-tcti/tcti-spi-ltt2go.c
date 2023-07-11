/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Peter Huewe
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include "tss2_tcti.h"
#include "tcti-spi-ltt2go.h"
#include "tss2_tcti_spi_ltt2go.h"
#include "tcti-spi-helper.h"
#include "tss2_mu.h"
#include "util/io.h"
#define LOGMODULE tcti
#include "util/log.h"

#define VID_PI3G 0x365Du
#define PID_LTT2GO 0x1337u
#define TIMEOUT 1000
#define CTRL_SET 0xC0u
#define CTRL_GET 0x40u
#define CY_CMD_SPI 0xCAu
#define CY_CMD_GPIO_SET 0xDBu
#define CY_SPI_WRITEREAD 0x03u
#define EP_OUT 0x01u
#define EP_IN 0x82u

#define SPI_MAX_TRANSFER (4 + 64)

TSS2_RC
platform_spi_transfer (void *user_data, const void *data_out, void *data_in, size_t cnt)
{
    int act_len = 0;
    int retry = 0;
    int ret = 0;
    size_t transfered = 0;
    size_t length = cnt;
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;
    uint8_t *spi_dma_buffer = platform_data->spi_dma_buffer;
    libusb_device_handle *dev_handle = platform_data->dev_handle;

    memset (spi_dma_buffer, 0, SPI_MAX_TRANSFER);

    /* Maximum transfer size is 64 bytes */
    if (cnt > SPI_MAX_TRANSFER) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* At least one of the buffers has to be set */
    if (data_out == NULL && data_in == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Clear receive buffer */
    if (data_in != NULL && data_in !=  data_out) {
        memset (data_in, 0, cnt);
    }

    if (data_out != NULL){
        memcpy (spi_dma_buffer, data_out, length);
    }

    ret = libusb_control_transfer (dev_handle, CTRL_SET, CY_CMD_SPI, CY_SPI_WRITEREAD, length, NULL, 0, TIMEOUT);
    if (ret) {
        LOG_ERROR ("libusb_control_transfer failed with error: %s.", libusb_strerror(ret));
        ret = TSS2_TCTI_RC_IO_ERROR;
        goto out;
    }

    while (transfered != cnt){
        ret = libusb_bulk_transfer (dev_handle, EP_OUT, spi_dma_buffer+transfered, length, &act_len, TIMEOUT);
        if (ret) {
            LOG_ERROR ("libusb_bulk_transfer write failed with error: %s.", libusb_strerror(ret));
            ret = TSS2_TCTI_RC_IO_ERROR;
            goto out;
        }
        transfered += act_len;
        length -= act_len;
    }

    transfered = 0;
    length = cnt;
    while(transfered != cnt){
        ret = libusb_bulk_transfer (dev_handle, EP_IN, spi_dma_buffer+transfered, length, &act_len, TIMEOUT);
        if (ret) {
            if (retry++ > 5) {
                LOG_ERROR ("libusb_bulk_transfer read failed with error: %s.", libusb_strerror(ret));
                ret = TSS2_TCTI_RC_IO_ERROR;
                goto out;
            }
            continue;
        }
        transfered += act_len;
        length -= act_len;
    }

    if (data_in != NULL) {
        memcpy(data_in, spi_dma_buffer, cnt);
    }

out:
    memset (spi_dma_buffer, 0, SPI_MAX_TRANSFER);
    return ret;
}

TSS2_RC
platform_sleep_ms (void *user_data, int32_t milliseconds)
{
    (void) user_data;
    struct timeval tv = {milliseconds/1000, (milliseconds%1000)*1000};
    select (0, NULL, NULL, NULL, &tv);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_start_timeout (void *user_data, int32_t milliseconds)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    memset (&platform_data->timeout, 0, sizeof (struct timeval));

    if (gettimeofday (&platform_data->timeout, NULL)) {
        LOG_ERROR ("getimeofday failed with errno: %d.", errno);
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }

    platform_data->timeout.tv_sec += (milliseconds/1000);
    platform_data->timeout.tv_usec += (milliseconds%1000)*1000;
    if (platform_data->timeout.tv_usec > 999999) {
        platform_data->timeout.tv_sec++;
        platform_data->timeout.tv_usec -= 1000000;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_timeout_expired (void *user_data, bool *is_timeout_expired)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    struct timeval now;
    if (gettimeofday (&now, NULL)) {
        LOG_ERROR ("getimeofday failed with errno: %d.", errno);
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }

    if (now.tv_sec > platform_data->timeout.tv_sec) {
        *is_timeout_expired = true;
    } else if ((now.tv_sec == platform_data->timeout.tv_sec)
               && (now.tv_usec > platform_data->timeout.tv_usec)) {
        *is_timeout_expired = true;
    } else {
        *is_timeout_expired = false;
    }

    return TSS2_RC_SUCCESS;
}

void
platform_finalize(void *user_data)
{
    int ret = 0;
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    if (platform_data->spi_dma_buffer)
        libusb_dev_mem_free (platform_data->dev_handle, platform_data->spi_dma_buffer, SPI_MAX_TRANSFER);

    if (platform_data->dev_handle) {
        /* Release the interface we claimed */
        ret = libusb_release_interface (platform_data->dev_handle, 0);
        if (ret) {
            LOG_WARNING ("libusb_release_interface failed: %s.", libusb_strerror (ret));
        }

        /* Close the device we opened */
        libusb_close (platform_data->dev_handle);
    }

    if (platform_data->ctx) {
        /* Needs to be called after closing all open devices
           and before your application terminates */
        libusb_exit (platform_data->ctx);
    }

    free(platform_data);
}

TSS2_RC
create_tcti_spi_ltt2go_platform (TSS2_TCTI_SPI_HELPER_PLATFORM *platform)
{
    int ret = 0;
    int nb_ifaces = 0;
    libusb_device *dev = NULL;
    struct libusb_config_descriptor *conf_desc = NULL;

    /* Create required platform user data */
    PLATFORM_USERDATA *platform_data = calloc (1, sizeof (PLATFORM_USERDATA));

    if (platform_data == NULL) {
        return TSS2_BASE_RC_MEMORY;
    }

    ret = libusb_init (&platform_data->ctx);
    if (ret) {
        LOG_ERROR ("libusb init failed: %s.", libusb_strerror (ret));
        goto out;
    }

    platform_data->dev_handle = libusb_open_device_with_vid_pid (platform_data->ctx, VID_PI3G, PID_LTT2GO);
    if (!platform_data->dev_handle) {
        LOG_ERROR ("LetsTrust-TPM2Go not found.");
        goto out;
    }

    dev = libusb_get_device (platform_data->dev_handle);
    if (dev == NULL) {
        LOG_ERROR ("libusb_get_device failed.");
        goto out;
    }

    ret = libusb_get_config_descriptor (dev, 0, &conf_desc);
    if (ret) {
        LOG_ERROR ("libusb_get_config_descriptor failed: %s.", libusb_strerror (ret));
        goto out;
    }

    nb_ifaces = conf_desc->bNumInterfaces;
    libusb_free_config_descriptor(conf_desc);
    if (!nb_ifaces) {
        LOG_ERROR ("libusb no interface found.");
        goto out;
    }

    ret = libusb_set_auto_detach_kernel_driver (platform_data->dev_handle, 1);
    if (ret) {
        LOG_ERROR ("libusb_set_auto_detach_kernel_driver failed: %s.", libusb_strerror (ret));
        goto out;
    }

    ret = libusb_claim_interface (platform_data->dev_handle, 0);
    if (ret) {
        LOG_ERROR ("libusb_claim_interface failed: %s.", libusb_strerror (ret));
        goto out;
    }

    platform_data->spi_dma_buffer = libusb_dev_mem_alloc (platform_data->dev_handle, SPI_MAX_TRANSFER);
    if (!platform_data->spi_dma_buffer){
        LOG_ERROR ("libusb_dev_mem_alloc failed.");
        goto out;
    }

    /* Create TCTI SPI platform struct with custom platform methods */
    platform->user_data = platform_data;
    platform->sleep_ms = platform_sleep_ms;
    platform->start_timeout = platform_start_timeout;
    platform->timeout_expired = platform_timeout_expired;
    platform->spi_acquire = NULL;
    platform->spi_release = NULL;
    platform->spi_transfer = platform_spi_transfer;
    platform->finalize = platform_finalize;

    return TSS2_RC_SUCCESS;

out:
    if (platform_data->spi_dma_buffer)
        libusb_dev_mem_free (platform_data->dev_handle, platform_data->spi_dma_buffer, SPI_MAX_TRANSFER);

    if (platform_data->dev_handle) {
        /* Release the interface we claimed */
        ret = libusb_release_interface(platform_data->dev_handle, 0);
        if (ret) {
            LOG_WARNING ("libusb_release_interface failed: %s.", libusb_strerror (ret));
        }

        /* Close the device we opened */
        libusb_close (platform_data->dev_handle);
    }

    if (platform_data->ctx) {
        /* Needs to be called after closing all open devices
           and before your application terminates */
        libusb_exit (platform_data->ctx);
    }

    return TSS2_BASE_RC_IO_ERROR;
}

TSS2_RC
Tss2_Tcti_Spi_Ltt2go_Init (TSS2_TCTI_CONTEXT* tcti_context, size_t* size, const char* config)
{
    (void) config;
    TSS2_RC ret = 0;
    TSS2_TCTI_SPI_HELPER_PLATFORM tcti_platform = {0};

    /* Check if context size is requested */
    if (tcti_context == NULL) {
        return Tss2_Tcti_Spi_Helper_Init (NULL, size, NULL);
    }

    if ((ret = create_tcti_spi_ltt2go_platform (&tcti_platform))) {
        return ret;
    }

    /* Initialize TCTI context */
    return Tss2_Tcti_Spi_Helper_Init (tcti_context, size, &tcti_platform);
}

const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-spi-ltt2go",
    .description = "TCTI for communicating with LetsTrust-TPM2Go.",
    .config_help = "Takes no configuration.",
    .init = Tss2_Tcti_Spi_Ltt2go_Init
};

const TSS2_TCTI_INFO *
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
