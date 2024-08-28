/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Peter Huewe
 */
#ifndef TCTI_SPI_LTT2GO_H
#define TCTI_SPI_LTT2GO_H
#include <libusb-1.0/libusb.h>  // for libusb_context, libusb_device_handle
#include <stdint.h>             // for uint8_t
#include <sys/time.h>           // for timeval

#define VID_PI3G 0x365Du
#define PID_LTT2GO 0x1337u
#define LTT2GO_TIMEOUT_MS 1000
#define CTRL_SET 0xC0u
#define CTRL_GET 0x40u
#define CY_CMD_SPI 0xCAu
#define CY_CMD_GPIO_SET 0xDBu
#define CY_SPI_WRITEREAD 0x03u
#define EP_OUT 0x01u
#define EP_IN 0x82u

#define SPI_MAX_TRANSFER (4 + 64)

typedef struct {
    struct timeval timeout;
    libusb_device_handle *dev_handle;
    libusb_context *ctx;
    uint8_t *spi_dma_buffer;
} PLATFORM_USERDATA;

#endif /* TCTI_SPI_LTT2GO_H */
