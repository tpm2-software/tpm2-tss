/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2022, Infineon Technologies AG
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_tcti.h"
#include "tss2_tcti_spi_lt2go.h"

#include "tss2-tcti/tcti-common.h"
#include "tss2-tcti/tcti-spi-lt2go.h"
#include "tss2-tcti/tcti-spi-helper.h"
#include "util/key-value-parse.h"

#define VID_CYPRESS 0x04b4u
#define PID_CYUSBSPI 0x0004u
#define CTRL_SET 0xC0u
#define CY_CMD_SPI 0xCAu
#define CY_SPI_WRITEREAD 0x03u
#define TIMEOUT 1000
#define EP_OUT 0x01u
#define EP_IN 0x82u

typedef enum {
    TPM_DID_VID_HEAD_RX = 0,
    TPM_DID_VID_HEAD_TX,
    TPM_ACCESS_HEAD_RX,
    TPM_ACCESS_HEAD_TX,
    TPM_STS_HEAD_RX,
    TPM_STS_HEAD_TX,
    TPM_RID_HEAD_RX,
    TPM_RID_HEAD_TX,
} tpm_state_t;

static const unsigned char TPM_DID_VID_0[] = {0x83, 0xd4, 0x0f, 0x00, 0xd1, 0x15, 0x1b, 0x00};
static const unsigned char TPM_ACCESS_0[] = {0x80, 0xd4, 0x00, 0x00, 0xa1};
static const unsigned char TPM_STS_0[] = {0x83, 0xd4, 0x00, 0x18, 0x40, 0x00, 0x00, 0x00};
static const unsigned char TPM_RID_0[] = {0x80, 0xd4, 0x0f, 0x04, 0x00};

static libusb_device_handle *device_handle;
static libusb_context *context;
struct libusb_config_descriptor *config_descriptor;
static libusb_device *usb_device;
static unsigned char *device_mem_alloc;
static size_t device_mem_alloc_length;
static uint16_t transfer_length;

/*
 * Mock function libusb_get_device.
 */
libusb_device * __wrap_libusb_get_device (libusb_device_handle *dev_handle)
{
    assert_ptr_equal (dev_handle, device_handle);
    usb_device = malloc (1);
    return usb_device;
}

/*
 * Mock function libusb_get_config_descriptor.
 */
int __wrap_libusb_get_config_descriptor (libusb_device *dev,
    uint8_t config_index, struct libusb_config_descriptor **config)
{
    assert_ptr_equal (dev, usb_device);
    assert_int_equal (config_index, 0);
    config_descriptor = malloc (sizeof (struct libusb_config_descriptor));
    config_descriptor->bNumInterfaces = 2;
    *config = config_descriptor;

    return 0;
}

/*
 * Mock function libusb_free_config_descriptor.
 */
void __wrap_libusb_free_config_descriptor (
     struct libusb_config_descriptor *config)
{
    assert_ptr_equal (config, config_descriptor);
    free (config);
}

/*
 * Mock function libusb_set_auto_detach_kernel_driver.
 */
int __wrap_libusb_set_auto_detach_kernel_driver (
    libusb_device_handle *dev_handle, int enable)
{
    assert_ptr_equal (dev_handle, device_handle);
    assert_int_equal (enable, 1);

    return 0;
}

/*
 * Mock function libusb_claim_interface.
 */
int __wrap_libusb_claim_interface (libusb_device_handle *dev_handle,
    int interface_number)
{
    assert_ptr_equal (dev_handle, device_handle);
    assert_int_equal (interface_number, 0);

    return 0;
}

/*
 * Mock function libusb_release_interface.
 */
int __wrap_libusb_release_interface (libusb_device_handle *dev_handle,
    int interface_number)
{
    assert_ptr_equal (dev_handle, device_handle);
    assert_int_equal (interface_number, 0);

    return 0;
}

/*
 * Mock function libusb_control_transfer.
 */
int __wrap_libusb_control_transfer (libusb_device_handle *dev_handle,
    uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
    unsigned char *data, uint16_t wLength, unsigned int timeout)
{
    assert_ptr_equal (dev_handle, device_handle);
    assert_int_equal (request_type, CTRL_SET);
    assert_int_equal (bRequest, CY_CMD_SPI);
    assert_int_equal (wValue, CY_SPI_WRITEREAD);
    assert_null (data);
    assert_int_equal (wLength, 0);
    assert_int_equal (timeout, TIMEOUT);

    transfer_length = wIndex;

    return 0;
}

/*
 * Mock function libusb_bulk_transfer.
 *
 * Here we are imitating the best case scenario where the
 * actual_length is always equal to length. In actual world,
 * the transmission can be fragmented hence the actual_length < length,
 * and multiple retries can happen to process the remaining length.
 */
int __wrap_libusb_bulk_transfer (libusb_device_handle *dev_handle,
    unsigned char endpoint, unsigned char *data, int length,
    int *actual_length, unsigned int timeout)
{
    static tpm_state_t tpm_state = TPM_DID_VID_HEAD_RX;

    assert_ptr_equal (dev_handle, device_handle);
    assert_int_equal (timeout, TIMEOUT);
    assert_int_equal (length, transfer_length);

    switch (tpm_state) {
    case TPM_DID_VID_HEAD_RX:
        assert_true (endpoint == EP_OUT);
        assert_int_equal (length, 8);
        assert_true (!memcmp (data, TPM_DID_VID_0, 4));
        break;
    case TPM_DID_VID_HEAD_TX:
        assert_true (endpoint == EP_IN);
        assert_int_equal (length, 8);
        memcpy (data, TPM_DID_VID_0, sizeof (TPM_DID_VID_0));
        break;
    case TPM_ACCESS_HEAD_RX:
        assert_true (endpoint == EP_OUT);
        assert_int_equal (length, 5);
        assert_true (!memcmp (data, TPM_ACCESS_0, 4));
        break;
    case TPM_ACCESS_HEAD_TX:
        assert_true (endpoint == EP_IN);
        assert_int_equal (length, 5);
        memcpy (data, TPM_ACCESS_0, sizeof (TPM_ACCESS_0));
        break;
    case TPM_STS_HEAD_RX:
        assert_true (endpoint == EP_OUT);
        assert_int_equal (length, 8);
        assert_true (!memcmp (data, TPM_STS_0, 4));
        break;
    case TPM_STS_HEAD_TX:
        assert_true (endpoint == EP_IN);
        assert_int_equal (length, 8);
        memcpy (data, TPM_STS_0, sizeof (TPM_STS_0));
        break;
    case TPM_RID_HEAD_RX:
        assert_true (endpoint == EP_OUT);
        assert_int_equal (length, 5);
        assert_true (!memcmp (data, TPM_RID_0, 4));
        break;
    case TPM_RID_HEAD_TX:
        assert_true (endpoint == EP_IN);
        assert_int_equal (length, 5);
        memcpy (data, TPM_RID_0, sizeof (TPM_RID_0));
        break;
    default:
        assert_true (false);
    }

    tpm_state += 1;
    *actual_length = length;

    return 0;
}

/*
 * Mock function libusb_close.
 */
void __wrap_libusb_close (libusb_device_handle *dev_handle)
{
    assert_ptr_equal (dev_handle, device_handle);
    free (usb_device);
    free (dev_handle);
}

/*
 * Mock function libusb_exit.
 */
void __wrap_libusb_exit (libusb_context *ctx)
{
    assert_ptr_equal (ctx, context);
    free (ctx);
}

/*
 * Mock function libusb_init.
 */
int __wrap_libusb_init (libusb_context **ctx)
{
    context = malloc (1);
    *ctx = context;

    return 0;
}

/*
 * Mock function libusb_strerror.
 */
const char * __wrap_libusb_strerror (int errcode)
{
    return NULL;
}

/*
 * Mock function libusb_open_device_with_vid_pid.
 */
libusb_device_handle * __wrap_libusb_open_device_with_vid_pid (
    libusb_context *ctx, uint16_t vendor_id, uint16_t product_id)
{
    assert_ptr_equal (ctx, context);
    assert_int_equal (vendor_id, VID_CYPRESS);
    assert_int_equal (product_id, PID_CYUSBSPI);

    device_handle = malloc (1);

    return device_handle;
}

/*
 * Mock function libusb_dev_mem_alloc.
 */
unsigned char * __wrap_libusb_dev_mem_alloc (libusb_device_handle *dev_handle,
    size_t length)
{
    assert_ptr_equal (dev_handle, device_handle);

    device_mem_alloc_length = length;
    device_mem_alloc = malloc (length);

    return device_mem_alloc;
}

/*
 * Mock function libusb_dev_mem_free.
 */
int __wrap_libusb_dev_mem_free (libusb_device_handle *dev_handle,
    unsigned char *buffer, size_t length)
{
    assert_ptr_equal (dev_handle, device_handle);
    assert_ptr_equal (buffer, device_mem_alloc);
    assert_int_equal (length, device_mem_alloc_length);

    free (dev_handle);
    free (buffer);

    return 0;
}

/*
 * The test will invoke Tss2_Tcti_Spi_Lt2go_Init() and subsequently
 * it will start reading TPM_DID_VID, claim locality, read TPM_STS,
 * and finally read TPM_RID before exiting the Init function.
 * For testing purpose, the TPM responses are hardcoded.
 * SPI wait state is not supported in this test.
 */
static void
tcti_spi_no_wait_state_success_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT* tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Lt2go_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    rc = Tss2_Tcti_Spi_Lt2go_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TSS2_TCTI_SPI_HELPER_PLATFORM platform = ((TSS2_TCTI_SPI_HELPER_CONTEXT *) tcti_ctx)->platform;
    free (platform.user_data);
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_no_wait_state_success_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
