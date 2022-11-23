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
#include "tcti-spi-ftdi.h"
#include "tss2_tcti_spi_ftdi.h"
#include "tcti-spi-helper.h"
#include "tss2_mu.h"
#include "util/io.h"
#define LOGMODULE tcti
#include "util/log.h"

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

TSS2_RC
platform_spi_transfer (void *user_data, const void *data_out, void *data_in, size_t cnt)
{
    int length = cnt;
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;
    struct mpsse_context *mpsse = platform_data->mpsse;
    char *data = NULL;

    if (Start (mpsse) != MPSSE_OK) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    if ((data = Transfer (mpsse, (char *)data_out, length)) == NULL) {
        Stop (mpsse);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    if (data_in != NULL) {
        memcpy (data_in, (unsigned char *)data, length);
    }

    free (data);

    if (Stop (mpsse) != MPSSE_OK) {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}

void
platform_finalize (void *user_data)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;
    struct mpsse_context *mpsse = platform_data->mpsse;

    if (mpsse != NULL) {
        Close (mpsse);
    }

    free (platform_data);
}

TSS2_RC
create_tcti_spi_ftdi_platform (TSS2_TCTI_SPI_HELPER_PLATFORM *platform)
{
    PLATFORM_USERDATA *platform_data = malloc (sizeof (PLATFORM_USERDATA));
    struct mpsse_context **mpsse = &platform_data->mpsse;

    if (platform_data == NULL) {
        return TSS2_BASE_RC_MEMORY;
    }

    memset (platform_data, 0, sizeof (PLATFORM_USERDATA));

    if ((*mpsse = MPSSE (SPI0, FIFTEEN_MHZ, MSB)) == NULL )
    {
        goto error;
    }

    platform->user_data = platform_data;
    platform->sleep_ms = platform_sleep_ms;
    platform->start_timeout = platform_start_timeout;
    platform->timeout_expired = platform_timeout_expired;
    platform->spi_acquire = NULL;
    platform->spi_release = NULL;
    platform->spi_transfer = platform_spi_transfer;
    platform->finalize = platform_finalize;

    return TSS2_RC_SUCCESS;

error:
    platform_finalize ((void *) platform_data);
    return TSS2_BASE_RC_IO_ERROR;
}

TSS2_RC
Tss2_Tcti_Spi_Ftdi_Init (TSS2_TCTI_CONTEXT* tcti_context, size_t* size, const char* config)
{
    (void) config;
    TSS2_RC ret = 0;
    TSS2_TCTI_SPI_HELPER_PLATFORM tcti_platform = {0};

    if (tcti_context == NULL) {
        return Tss2_Tcti_Spi_Helper_Init (NULL, size, NULL);
    }

    if ((ret = create_tcti_spi_ftdi_platform (&tcti_platform))) {
        return ret;
    }

    return Tss2_Tcti_Spi_Helper_Init (tcti_context, size, &tcti_platform);
}

const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-spi-ftdi",
    .description = "TCTI for communicating with TPM through the USB-FTDI-SPI converter.",
    .config_help = "Takes no configuration.",
    .init = Tss2_Tcti_Spi_Ftdi_Init
};

const TSS2_TCTI_INFO *
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
