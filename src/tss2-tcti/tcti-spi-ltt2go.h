/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Peter Huewe
 */
#ifndef TCTI_SPI_LTT2GO_H
#define TCTI_SPI_LTT2GO_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdint.h>
#include <libusb-1.0/libusb.h>

#include "tcti-common.h"
#include "tss2_tcti_spi_helper.h"

typedef struct {
    struct timeval timeout;
    libusb_device_handle *dev_handle;
    libusb_context *ctx;
    uint8_t *spi_dma_buffer;
} PLATFORM_USERDATA;

#endif /* TCTI_SPI_LTT2GO_H */
