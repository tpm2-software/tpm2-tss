/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Peter Huewe
 */
#include <errno.h>                 // for errno
#include <fcntl.h>                 // for open, O_RDWR
#include <inttypes.h>              // for int32_t
#include <stdbool.h>               // for true, bool, false
#include <stdio.h>                 // for NULL, size_t
#include <stdlib.h>                // for free, calloc
#include <string.h>                // for strerror, memset
#include <sys/ioctl.h>             // for ioctl
#include <sys/select.h>            // for select
#include <sys/time.h>              // for timeval, gettimeofday
#include <unistd.h>                // for close
#include <linux/spi/spidev.h>      // for spi_ioc_transfer, SPI_IOC_MESSAGE

#include "tcti-common.h"           // for TCTI_VERSION
#include "tss2_common.h"           // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_TCT...
#include "tss2_tcti.h"             // for TSS2_TCTI_INFO, TSS2_TCTI_CONTEXT
#include "tss2_tcti_spi_helper.h"  // for TSS2_TCTI_SPI_HELPER_PLATFORM, Tss...
#include "tss2_tcti_spidev.h"      // for Tss2_Tcti_Spidev_Init

#define LOGMODULE tcti
#include "util/log.h"              // for LOG_ERROR, LOGBLOB_DEBUG

typedef struct {
    struct timeval timeout;
    int fd;
} PLATFORM_USERDATA;

TSS2_RC
platform_spi_acquire (void *user_data)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;
    struct spi_ioc_transfer tr = {
        .delay_usecs = 0,
        .speed_hz = 5000000,
        .bits_per_word = 8,
        .cs_change = 1,
        .len = 0,
    };

	int ret = ioctl(platform_data->fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 0) {
        LOG_ERROR("SPI acquire failed: %s", strerror(errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_spi_release (void *user_data)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;
    struct spi_ioc_transfer tr = {
        .delay_usecs = 0,
        .speed_hz = 5000000,
        .bits_per_word = 8,
        .cs_change = 0,
        .len = 0,
    };

	int ret = ioctl(platform_data->fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 0) {
        LOG_ERROR("SPI release failed: %s", strerror(errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_spi_transfer (void *user_data, const void *data_out, void *data_in, size_t cnt)
{
    LOGBLOB_DEBUG(data_out, cnt, "Transferring data over ioctl:");
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    struct spi_ioc_transfer tr = {
        .delay_usecs = 0,
        .speed_hz = 5000000,
        .bits_per_word = 8,
        .cs_change = 1,
    };

    tr.len = cnt;
    tr.tx_buf = (unsigned long) data_out;
    tr.rx_buf = (unsigned long) data_in;
	int ret = ioctl(platform_data->fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 0) {
        LOG_ERROR("SPI acquire failed: %s", strerror(errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    LOGBLOB_DEBUG(data_in, cnt, "Received data over ioctl:");
    return TSS2_RC_SUCCESS;
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
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;
    close(platform_data->fd);
    free(platform_data);
}

TSS2_RC
Tss2_Tcti_Spidev_Init (TSS2_TCTI_CONTEXT* tcti_context, size_t* size, const char* config)
{
    TSS2_TCTI_SPI_HELPER_PLATFORM platform = {0};

    if (!config || config[0] == '\0')
        config = "/dev/spidev0.1";

    /* Check if context size is requested */
    if (tcti_context == NULL) {
        return Tss2_Tcti_Spi_Helper_Init (NULL, size, NULL);
    }

    /* Create required platform user data */
    PLATFORM_USERDATA *platform_data = calloc (1, sizeof (PLATFORM_USERDATA));
    if (platform_data == NULL) {
        return TSS2_BASE_RC_MEMORY;
    }

    platform_data->fd = open(config, O_RDWR);
    if (!platform_data->fd) {
        LOG_ERROR("%s cannot be opened: %s", config, strerror(errno));
        free(platform_data);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Create TCTI SPI platform struct with custom platform methods */
    platform.user_data = platform_data;
    platform.sleep_ms = platform_sleep_ms;
    platform.start_timeout = platform_start_timeout;
    platform.timeout_expired = platform_timeout_expired;
    platform.spi_acquire = platform_spi_acquire;
    platform.spi_release = platform_spi_release;
    platform.spi_transfer = platform_spi_transfer;
    platform.finalize = platform_finalize;

    /* Initialize TCTI context */
    return Tss2_Tcti_Spi_Helper_Init (tcti_context, size, &platform);
}

const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-spidev",
    .description = "TCTI for communicating with a TPM via spidev.",
    .config_help = "Path to spidev (Default: /dev/spidev0.1).",
    .init = Tss2_Tcti_Spidev_Init
};

const TSS2_TCTI_INFO *
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
