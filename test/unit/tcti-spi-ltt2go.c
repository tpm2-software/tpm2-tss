/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2022, Infineon Technologies AG
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>                   // for uint16_t, uint8_t
#include <libusb-1.0/libusb.h>          // for libusb_device_handle, libusb_...
#include <stdbool.h>                    // for false
#include <stdio.h>                      // for NULL, size_t
#include <stdlib.h>                     // for free, malloc, calloc
#include <string.h>                     // for memcmp, memcpy
#include <sys/select.h>                 // for fd_set, timeval

#include "../helper/cmocka_all.h"                     // for assert_int_equal, assert_ptr_...
#include "tss2-tcti/tcti-spi-helper.h"  // for TSS2_TCTI_SPI_HELPER_CONTEXT
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT
#include "tss2_tcti_spi_helper.h"       // for TSS2_TCTI_SPI_HELPER_PLATFORM
#include "tss2_tcti_spi_ltt2go.h"       // for Tss2_Tcti_Spi_Ltt2go_Init

struct timeval;
struct timezone;

#define DEV_DESC_SERIAL_NUMBER_INDEX 1
#define DEV_DESC_SERIAL_NUMBER "Y23CW29NR00000RND987654321012"

#define VID_PI3G 0x365Du
#define PID_LTT2GO 0x1337u

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

static tpm_state_t tpm_state = TPM_DID_VID_HEAD_RX;
static libusb_device_handle *device_handle;
static libusb_context *context;
static libusb_device *device;
static libusb_device **device_list;
static struct libusb_config_descriptor *config_descriptor;
static unsigned char *device_mem_alloc;
static size_t device_mem_alloc_length;
static uint16_t transfer_length;

/*
 * Mock function select
 */
int __wrap_select (int nfds, fd_set *readfds,
                   fd_set *writefds,
                   fd_set *exceptfds,
                   struct timeval *timeout)
{

    assert_int_equal (nfds, 0);
    assert_null (readfds);
    assert_null (writefds);
    assert_null (exceptfds);
    assert_non_null (timeout);

    return 0;
}

/*
 * Mock function gettimeofday
 */
int __wrap_gettimeofday (struct timeval *tv,
                         struct timezone *tz)
{
    assert_null (tz);
    assert_non_null (tv);

    tv->tv_sec = 0;
    tv->tv_usec = 0;

    return 0;
}

/*
 * Mock function libusb_get_device_list.
 */
ssize_t  __wrap_libusb_get_device_list (libusb_context *ctx, libusb_device ***list)
{
    ssize_t num_of_devs = 1;

    assert_ptr_equal (ctx, context);

    *list = device_list = malloc (sizeof (*list));
    **list = device = malloc (sizeof (**list));

    return num_of_devs;
}

/*
 * Mock function libusb_get_device_descriptor.
 */
int  __wrap_libusb_get_device_descriptor (libusb_device *dev,
    struct libusb_device_descriptor *desc)
{
    assert_ptr_equal (dev, device);
    assert_non_null (desc);

    desc->idVendor = VID_PI3G;
    desc->idProduct = PID_LTT2GO;
    desc->iSerialNumber = DEV_DESC_SERIAL_NUMBER_INDEX;

    return 0;
}

/*
 * Mock function libusb_get_string_descriptor_ascii.
 */
int  __wrap_libusb_get_string_descriptor_ascii (libusb_device_handle *dev_handle,
    uint8_t desc_index, unsigned char *data, int length)
{
    unsigned char *sn = (unsigned char *)DEV_DESC_SERIAL_NUMBER;
    int sn_size = strlen ((const char *)sn) + 1;

    assert_ptr_equal (dev_handle, device_handle);
    assert_int_equal (desc_index, DEV_DESC_SERIAL_NUMBER_INDEX);
    assert_non_null (data);
    assert_int_equal (length, 256);
    assert_true (length >= sn_size);

    memcpy (data, (const void *)sn, sn_size);

    return sn_size;
}

/*
 * Mock function libusb_get_config_descriptor.
 */
int __wrap_libusb_get_config_descriptor (libusb_device *dev,
    uint8_t config_index, struct libusb_config_descriptor **config)
{
    assert_ptr_equal (dev, device);
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
    free (config_descriptor);
    config_descriptor = NULL;
}

/*
 * Mock function libusb_free_device_list.
 */
void __wrap_libusb_free_device_list (
    libusb_device **list, int unref_devices)
{
    assert_ptr_equal (list, device_list);
    assert_ptr_equal (*list, device);
    assert_int_equal (unref_devices, 1);
    free (device);
    free (device_list);
    device = NULL;
    device_list = NULL;
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
 * Mock function libusb_open.
 */
int __wrap_libusb_open (libusb_device *dev, libusb_device_handle **dev_handle)
{
    assert_ptr_equal (dev, device);
    assert_non_null (dev_handle);
    *dev_handle = device_handle = malloc (1);

    return 0;
}

/*
 * Mock function libusb_close.
 */
void __wrap_libusb_close (libusb_device_handle *dev_handle)
{
    assert_ptr_equal (dev_handle, device_handle);
    free (device_handle);
    device_handle = NULL;
}

/*
 * Mock function libusb_exit.
 */
void __wrap_libusb_exit (libusb_context *ctx)
{
    assert_ptr_equal (ctx, context);
    free (context);
    context = NULL;
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
    free (device_mem_alloc);
    device_mem_alloc = NULL;
    device_mem_alloc_length = 0;

    return 0;
}

/*
 * The test will invoke Tss2_Tcti_Spi_Ltt2go_Init() and subsequently
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
    rc = Tss2_Tcti_Spi_Ltt2go_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    Tss2_Tcti_Finalize (tcti_ctx);
    free (tcti_ctx);
}

/*
 * This test is similar to tcti_spi_no_wait_state_success_test(),
 * with the difference being that the serial number is provided as
 * one of the input arguments. The focus of this test is to verify
 * the serial number matching algorithm.
 */
static void
tcti_spi_no_wait_state_regex_success_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT* tcti_ctx;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Ltt2go_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Positive tests: */

    /* Initialize TCTI context with S/N: DEV_DESC_SERIAL_NUMBER */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, DEV_DESC_SERIAL_NUMBER);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    Tss2_Tcti_Finalize (tcti_ctx);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N starting with "Y23CW" */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "^Y23CW");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    Tss2_Tcti_Finalize (tcti_ctx);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N containing "RND9876" */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "RND9876");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    Tss2_Tcti_Finalize (tcti_ctx);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N ending with "321012" */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "321012$");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    Tss2_Tcti_Finalize (tcti_ctx);
    memset (tcti_ctx, 0, size);

    /* Negative tests: */

    /* Initialize TCTI context with S/N starting with "Z23CW" */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "^Z23CW");
    assert_int_equal (rc, TSS2_BASE_RC_IO_ERROR);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N containing "RND8876" */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "RND8876");
    assert_int_equal (rc, TSS2_BASE_RC_IO_ERROR);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N ending with "321011" */
    tpm_state = TPM_DID_VID_HEAD_RX;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "321011$");
    assert_int_equal (rc, TSS2_BASE_RC_IO_ERROR);

    /* Release tcti_ctx */
    free (tcti_ctx);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_spi_no_wait_state_success_test),
        cmocka_unit_test (tcti_spi_no_wait_state_regex_success_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
