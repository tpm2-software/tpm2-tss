/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Peter Huewe
 */
#ifndef TCTI_SPI_LTT2GO_H
#define TCTI_SPI_LTT2GO_H
#include <libusb-1.0/libusb.h>  // for libusb_context, libusb_device_handle
#include <stdint.h>             // for uint8_t
#include <sys/time.h>           // for timeval

typedef struct {
    struct timeval timeout;
    libusb_device_handle *dev_handle;
    libusb_context *ctx;
    uint8_t *spi_dma_buffer;
} PLATFORM_USERDATA;

#endif /* TCTI_SPI_LTT2GO_H */
