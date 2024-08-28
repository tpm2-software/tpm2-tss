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
#include "tss2-tcti/tcti-common.h"
#include "tss2-tcti/tcti-spi-ltt2go.h"
#include "tss2-tcti/tcti-spi-helper.h"
#include "tss2_common.h"                // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_tcti.h"                  // for TSS2_TCTI_CONTEXT
#include "tss2_tcti_spi_helper.h"       // for TSS2_TCTI_SPI_HELPER_PLATFORM
#include "tss2_tcti_spi_ltt2go.h"       // for Tss2_Tcti_Spi_Ltt2go_Init

/*
 * The goal is to verify the LTT2GO (LetsTrust-TPM2Go) implementation by checking
 * the order in which libusb functions are invoked when using functions in
 * the TSS2_TCTI_SPI_HELPER_PLATFORM (e.g., sleep_ms, start_timeout,
 * timeout_expired, spi_transfer).

 * The audit arrays (e.g., audit_general) contain this information. Each
 * entry specifies the expected libusb function to be invoked, the command
 * to be received, or the response to be written back in a specific order.
 * The tester_context.audit_step (audit array index) variable tracks the
 * sequence of these operations.
 */

#define DEV_DESC_SERIAL_NUMBER_INDEX 1
#define DEV_DESC_SERIAL_NUMBER "Y23CW29NR00000RND987654321012"

#define DUMMY_PTR       ((void *)0xA5A5A5A5)
#define TIME_MS         450

/* Define the incomplete struct */
struct libusb_device {
    int dummy;
};

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TSS2_TCTI_SPI_HELPER_PLATFORM platform;
} TSS2_TCTI_SPI_LTT2GO_TEST_CONTEXT;

typedef struct {
    int nfds;
    void *readfds;
    void *writefds;
    void *exceptfds;
    struct timeval timeout;
} fn_select;

typedef struct {
    struct timeval tv;
    void *tz;
} fn_gettimeofday;

typedef struct {
    libusb_context *ctx;
    libusb_device **list;
    ssize_t size;
} fn_libusb_get_device_list;

typedef struct {
    libusb_device *dev;
    struct libusb_device_descriptor desc;
} fn_libusb_get_device_descriptor;

typedef struct {
    libusb_device_handle *dev_handle;
    uint8_t desc_index;
    unsigned char *data;
    int length;
} fn_libusb_get_string_descriptor_ascii;

typedef struct {
    libusb_device *dev;
    uint8_t config_index;
    struct libusb_config_descriptor *config;
} fn_libusb_get_config_descriptor;

typedef struct {
    struct libusb_config_descriptor *config;
} fn_libusb_free_config_descriptor;

typedef struct {
    libusb_device **list;
    int unref_devices;
} fn_libusb_free_device_list;

typedef struct {
    libusb_device_handle *dev_handle;
    int enable;
} fn_libusb_set_auto_detach_kernel_driver;

typedef struct {
    libusb_device_handle *dev_handle;
    int interface_number;
} fn_libusb_claim_interface, fn_libusb_release_interface;

typedef struct {
    libusb_device_handle *dev_handle;
    uint8_t request_type;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    unsigned char *data;
    uint16_t wLength;
    unsigned int timeout;
} fn_libusb_control_transfer;

typedef struct {
    libusb_device_handle *dev_handle;
    unsigned char endpoint;
    unsigned char *data;
    int length;
    unsigned int timeout;
} fn_libusb_bulk_transfer;

typedef struct {
    libusb_device *dev;
    libusb_device_handle *dev_handle;
} fn_libusb_open;

typedef struct {
    libusb_device_handle *dev_handle;
} fn_libusb_close;

typedef struct {
    libusb_context *ctx;
} fn_libusb_exit, fn_libusb_init;

typedef struct {
    int errcode;
} fn_libusb_strerror;

typedef struct {
    libusb_device_handle *dev_handle;
    unsigned char *buffer;
    size_t length;
} fn_libusb_dev_mem_alloc;

typedef struct {
    libusb_device_handle *dev_handle;
    unsigned char *buffer;
    size_t length;
} fn_libusb_dev_mem_free;

typedef struct {
    void *func;
    union {
        fn_select select;
        fn_gettimeofday gtod;
        fn_libusb_get_device_list gdl;
        fn_libusb_get_device_descriptor gdd;
        fn_libusb_get_string_descriptor_ascii gsda;
        fn_libusb_get_config_descriptor gcd;
        fn_libusb_free_config_descriptor fcd;
        fn_libusb_free_device_list fdl;
        fn_libusb_set_auto_detach_kernel_driver sadkd;
        fn_libusb_claim_interface ci;
        fn_libusb_release_interface ri;
        fn_libusb_control_transfer ct;
        fn_libusb_bulk_transfer bt;
        fn_libusb_open open;
        fn_libusb_close close;
        fn_libusb_exit exit;
        fn_libusb_init init;
        fn_libusb_strerror strerr;
        fn_libusb_dev_mem_alloc dma;
        fn_libusb_dev_mem_free dmf;
    } args;
} struct_audit;

typedef struct {
    int audit_step;
    struct_audit *audit;
    bool is_regex_test;
} tester_context;

static tester_context tester_ctx;
static unsigned char TPM2_STARTUP_CMD_MOSI[] =
    { 0x0B, 0xD4, 0x00, 0x24, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
static unsigned char TPM2_STARTUP_CMD_MISO[] =
    { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static libusb_device *dummy_device_list[] = { DUMMY_PTR };
static struct libusb_config_descriptor dummy_config_desc = { .bNumInterfaces = 1 };
static uint8_t spi_dma_buffer[SPI_MAX_TRANSFER];

/*
 * Mock function select
 */
int __wrap_select (int nfds, fd_set *readfds,
                   fd_set *writefds,
                   fd_set *exceptfds,
                   struct timeval *timeout)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_select, audit->func);
    assert_int_equal (nfds, audit->args.select.nfds);
    assert_int_equal (readfds, audit->args.select.readfds);
    assert_int_equal (writefds, audit->args.select.writefds);
    assert_int_equal (exceptfds, audit->args.select.exceptfds);
    assert_int_equal (timeout->tv_sec, audit->args.select.timeout.tv_sec);
    assert_int_equal (timeout->tv_usec, audit->args.select.timeout.tv_usec);

    return 0;
}

/*
 * Mock function gettimeofday
 */
int __wrap_gettimeofday (struct timeval *tv,
                         struct timezone *tz)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_gettimeofday, audit->func);
    assert_non_null (tv);
    assert_ptr_equal (tz, audit->args.gtod.tz);

    tv->tv_sec = audit->args.gtod.tv.tv_sec;
    tv->tv_usec = audit->args.gtod.tv.tv_usec;

    return 0;
}

/*
 * Mock function libusb_get_device_list.
 */
ssize_t  __wrap_libusb_get_device_list (libusb_context *ctx, libusb_device ***list)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_get_device_list, audit->func);
    assert_ptr_equal (ctx, audit->args.gdl.ctx);
    assert_non_null (list);
    *list = audit->args.gdl.list;

    return audit->args.gdl.size;
}

/*
 * Mock function libusb_get_device_descriptor.
 */
int  __wrap_libusb_get_device_descriptor (libusb_device *dev,
    struct libusb_device_descriptor *desc)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_get_device_descriptor, audit->func);
    assert_ptr_equal (dev, audit->args.gdd.dev);
    assert_non_null (desc);
    *desc = audit->args.gdd.desc;

    return 0;
}

/*
 * Mock function libusb_get_string_descriptor_ascii.
 */
int  __wrap_libusb_get_string_descriptor_ascii (libusb_device_handle *dev_handle,
    uint8_t desc_index, unsigned char *data, int length)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];
    int l;

    assert_ptr_equal (__wrap_libusb_get_string_descriptor_ascii, audit->func);
    assert_ptr_equal (dev_handle, audit->args.gsda.dev_handle);
    assert_int_equal (desc_index, audit->args.gsda.desc_index);
    assert_non_null (data);
    assert_int_equal (length, audit->args.gsda.length);

    l = (int) strlen ((const char *)audit->args.gsda.data);
    assert_true (length >= l);
    memcpy (data, audit->args.gsda.data, l);
    data[l] = 0; /* NULL byte */

    return l;
}

/*
 * Mock function libusb_get_config_descriptor.
 */
int __wrap_libusb_get_config_descriptor (libusb_device *dev,
    uint8_t config_index, struct libusb_config_descriptor **config)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_get_config_descriptor, audit->func);
    assert_ptr_equal (dev, audit->args.gcd.dev);
    assert_int_equal (config_index, audit->args.gcd.config_index);
    assert_non_null (config);
    *config = audit->args.gcd.config;

    return 0;
}

/*
 * Mock function libusb_free_config_descriptor.
 */
void __wrap_libusb_free_config_descriptor (
     struct libusb_config_descriptor *config)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];
    assert_ptr_equal (__wrap_libusb_free_config_descriptor, audit->func);
    assert_ptr_equal (config, audit->args.fcd.config);
}

/*
 * Mock function libusb_free_device_list.
 */
void __wrap_libusb_free_device_list (
    libusb_device **list, int unref_devices)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];
    assert_ptr_equal (__wrap_libusb_free_device_list, audit->func);
    assert_ptr_equal (list, audit->args.fdl.list);
    assert_int_equal (unref_devices, audit->args.fdl.unref_devices);
}

/*
 * Mock function libusb_set_auto_detach_kernel_driver.
 */
int __wrap_libusb_set_auto_detach_kernel_driver (
    libusb_device_handle *dev_handle, int enable)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_set_auto_detach_kernel_driver, audit->func);
    assert_ptr_equal (dev_handle, audit->args.sadkd.dev_handle);
    assert_int_equal (enable, audit->args.sadkd.enable);

    return 0;
}

/*
 * Mock function libusb_claim_interface.
 */
int __wrap_libusb_claim_interface (libusb_device_handle *dev_handle,
    int interface_number)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_claim_interface, audit->func);
    assert_ptr_equal (dev_handle, audit->args.ci.dev_handle);
    assert_int_equal (interface_number, audit->args.ci.interface_number);

    return 0;
}

/*
 * Mock function libusb_release_interface.
 */
int __wrap_libusb_release_interface (libusb_device_handle *dev_handle,
    int interface_number)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_release_interface, audit->func);
    assert_ptr_equal (dev_handle, audit->args.ri.dev_handle);
    assert_int_equal (interface_number, audit->args.ci.interface_number);

    return 0;
}

/*
 * Mock function libusb_control_transfer.
 */
int __wrap_libusb_control_transfer (libusb_device_handle *dev_handle,
    uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
    unsigned char *data, uint16_t wLength, unsigned int timeout)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_control_transfer, audit->func);
    assert_ptr_equal (dev_handle, audit->args.ct.dev_handle);
    assert_int_equal (request_type, audit->args.ct.request_type);
    assert_int_equal (bRequest, audit->args.ct.bRequest);
    assert_int_equal (wValue, audit->args.ct.wValue);
    assert_int_equal (wIndex, audit->args.ct.wIndex);
    assert_int_equal (wLength, audit->args.ct.wLength);
    assert_int_equal (timeout, audit->args.ct.timeout);
    assert_ptr_equal (data, audit->args.ct.data);

    return 0;
}

/*
 * Mock function libusb_bulk_transfer.
 */
int __wrap_libusb_bulk_transfer (libusb_device_handle *dev_handle,
    unsigned char endpoint, unsigned char *data, int length,
    int *actual_length, unsigned int timeout)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_bulk_transfer, audit->func);
    assert_ptr_equal (dev_handle, audit->args.bt.dev_handle);
    assert_int_equal (endpoint, audit->args.bt.endpoint);
    assert_non_null (data);
    assert_int_equal (length, audit->args.bt.length);
    assert_non_null (actual_length);
    assert_int_equal (timeout, audit->args.bt.timeout);

    if (endpoint == EP_OUT) {
        assert_true (!memcmp (data, audit->args.bt.data, length));
    } else if (endpoint == EP_IN) {
        memcpy (data, audit->args.bt.data, length);
    } else {
        assert_true (false);
    }
    *actual_length = audit->args.bt.length;

    return 0;
}

/*
 * Mock function libusb_open.
 */
int __wrap_libusb_open (libusb_device *dev, libusb_device_handle **dev_handle)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_open, audit->func);
    assert_ptr_equal (dev, audit->args.open.dev);
    assert_non_null (dev_handle);
    *dev_handle = audit->args.open.dev_handle;

    return 0;
}

/*
 * Mock function libusb_close.
 */
void __wrap_libusb_close (libusb_device_handle *dev_handle)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];
    assert_ptr_equal (__wrap_libusb_close, audit->func);
    assert_ptr_equal (dev_handle, audit->args.close.dev_handle);
}

/*
 * Mock function libusb_exit.
 */
void __wrap_libusb_exit (libusb_context *ctx)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];
    assert_ptr_equal (__wrap_libusb_exit, audit->func);
    assert_ptr_equal (ctx, audit->args.exit.ctx);
}

/*
 * Mock function libusb_init.
 */
int __wrap_libusb_init (libusb_context **ctx)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_init, audit->func);
    assert_non_null (ctx);
    *ctx = audit->args.init.ctx;

    return 0;
}

/*
 * Mock function libusb_strerror.
 */
const char * __wrap_libusb_strerror (int errcode)
{
    (void) errcode;
    assert_true (false);
    return NULL;
}

/*
 * Mock function libusb_dev_mem_alloc.
 */
unsigned char * __wrap_libusb_dev_mem_alloc (libusb_device_handle *dev_handle,
    size_t length)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_dev_mem_alloc, audit->func);
    assert_ptr_equal (dev_handle, audit->args.dma.dev_handle);
    assert_int_equal (length, audit->args.dma.length);

    return audit->args.dma.buffer;
}

/*
 * Mock function libusb_dev_mem_free.
 */
int __wrap_libusb_dev_mem_free (libusb_device_handle *dev_handle,
    unsigned char *buffer, size_t length)
{
    struct_audit *audit = &tester_ctx.audit[tester_ctx.audit_step++];

    assert_ptr_equal (__wrap_libusb_dev_mem_free, audit->func);
    assert_ptr_equal (dev_handle, audit->args.dmf.dev_handle);
    assert_ptr_equal (buffer, audit->args.dmf.buffer);
    assert_int_equal (length, audit->args.dmf.length);

    return 0;
}

static struct_audit audit_general[] = {
    /* Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, NULL) */
    { .func = __wrap_libusb_init, .args.init = { DUMMY_PTR } },
    { .func = __wrap_libusb_get_device_list, .args.gdl =
      { DUMMY_PTR, dummy_device_list, sizeof (dummy_device_list) / sizeof(dummy_device_list[0]) } },
    { .func = __wrap_libusb_get_device_descriptor, .args.gdd = { DUMMY_PTR,
      { .idVendor = VID_PI3G, .idProduct = PID_LTT2GO, .iSerialNumber = DEV_DESC_SERIAL_NUMBER_INDEX } } },
    { .func = __wrap_libusb_get_config_descriptor, .args.gcd = { DUMMY_PTR, 0, &dummy_config_desc } },
    { .func = __wrap_libusb_free_config_descriptor, .args.fcd = { &dummy_config_desc } },
    { .func = __wrap_libusb_open, .args.open = { DUMMY_PTR, DUMMY_PTR } },
    { .func = __wrap_libusb_get_string_descriptor_ascii, .args.gsda =
      { DUMMY_PTR, DEV_DESC_SERIAL_NUMBER_INDEX, (unsigned char *)DEV_DESC_SERIAL_NUMBER, 256 } },
    { .func = __wrap_libusb_set_auto_detach_kernel_driver, .args.sadkd = { DUMMY_PTR, 1 } },
    { .func = __wrap_libusb_claim_interface, .args.sadkd = { DUMMY_PTR, 0 } },
    { .func = __wrap_libusb_dev_mem_alloc, .args.dma = { DUMMY_PTR, spi_dma_buffer, sizeof (spi_dma_buffer) } },
    { .func = __wrap_libusb_free_device_list, .args.fdl = { dummy_device_list, 1 } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's sleep_ms */
    { .func = __wrap_select, .args.select =
      { 0, NULL, NULL, NULL,{ (TIME_MS * 1000) / 1000000, (TIME_MS * 1000) % 1000000 } } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's start_timeout */
    { .func = __wrap_gettimeofday, .args.gtod = { { 0, 0 }, NULL } },

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's timeout_expired */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 1, 0 }, NULL } }, /* Return a value > TIME_MS to trigger a timeout event */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 0, (TIME_MS * 1000) }, NULL } }, /* Return a value <= TIME_MS, no timeout occured */
    { .func = __wrap_gettimeofday, .args.gtod =
      { { 0, (TIME_MS * 1000) + 1 }, NULL } }, /* Return a value > TIME_MS to trigger a timeout event */

    /* TSS2_TCTI_I2C_HELPER_PLATFORM's spi_transfer */
    { .func = __wrap_libusb_control_transfer, .args.ct =
      { DUMMY_PTR, CTRL_SET, CY_CMD_SPI, CY_SPI_WRITEREAD, sizeof (TPM2_STARTUP_CMD_MOSI), NULL, 0, LTT2GO_TIMEOUT_MS } },
    { .func = __wrap_libusb_bulk_transfer, .args.bt =
      { DUMMY_PTR, EP_OUT, TPM2_STARTUP_CMD_MOSI, sizeof (TPM2_STARTUP_CMD_MOSI), LTT2GO_TIMEOUT_MS } },
    { .func = __wrap_libusb_bulk_transfer, .args.bt =
      { DUMMY_PTR, EP_IN, TPM2_STARTUP_CMD_MISO, sizeof (TPM2_STARTUP_CMD_MISO), LTT2GO_TIMEOUT_MS } },

    /* platform->finalize */
    { .func = __wrap_libusb_dev_mem_free, .args.dmf = { DUMMY_PTR, spi_dma_buffer, sizeof (spi_dma_buffer) } },
    { .func = __wrap_libusb_release_interface, .args.ri = { DUMMY_PTR, 0 } },
    { .func = __wrap_libusb_close, .args.close = { DUMMY_PTR } },
    { .func = __wrap_libusb_exit, .args.exit = { DUMMY_PTR } },

    { 0 },
};

static struct_audit audit_regex[] = {
    /* Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, XXXXX) */
    { .func = __wrap_libusb_init, .args.init = { DUMMY_PTR } },
    { .func = __wrap_libusb_get_device_list, .args.gdl =
      { DUMMY_PTR, dummy_device_list , sizeof (dummy_device_list) / sizeof(dummy_device_list[0]) } },
    { .func = __wrap_libusb_get_device_descriptor, .args.gdd =
      { DUMMY_PTR,  { .idVendor = VID_PI3G, .idProduct = PID_LTT2GO, .iSerialNumber = DEV_DESC_SERIAL_NUMBER_INDEX } } },
    { .func = __wrap_libusb_get_config_descriptor, .args.gcd = { DUMMY_PTR, 0, &dummy_config_desc } },
    { .func = __wrap_libusb_free_config_descriptor, .args.fcd = { &dummy_config_desc } },
    { .func = __wrap_libusb_open, .args.open = { DUMMY_PTR, DUMMY_PTR } },
    { .func = __wrap_libusb_get_string_descriptor_ascii, .args.gsda =
      { DUMMY_PTR, DEV_DESC_SERIAL_NUMBER_INDEX, (unsigned char *)DEV_DESC_SERIAL_NUMBER, 256 } },
    { .func = __wrap_libusb_set_auto_detach_kernel_driver, .args.sadkd = { DUMMY_PTR, 1 } },
    { .func = __wrap_libusb_claim_interface, .args.sadkd = { DUMMY_PTR, 0 } },
    { .func = __wrap_libusb_dev_mem_alloc, .args.dma = { DUMMY_PTR, spi_dma_buffer, sizeof (spi_dma_buffer) } },
    { .func = __wrap_libusb_free_device_list, .args.fdl = { dummy_device_list, 1 } },

    /* platform->finalize */
    { .func = __wrap_libusb_dev_mem_free, .args.dmf = { DUMMY_PTR, spi_dma_buffer, sizeof (spi_dma_buffer) } },
    { .func = __wrap_libusb_release_interface, .args.ri = { DUMMY_PTR, 0 } },
    { .func = __wrap_libusb_close, .args.close = { DUMMY_PTR } },
    { .func = __wrap_libusb_exit, .args.exit = { DUMMY_PTR } },

    { 0 },
};

static struct_audit audit_regex_nok[] = {
    /* Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, XXXXX) */
    { .func = __wrap_libusb_init, .args.init = { DUMMY_PTR } },
    { .func = __wrap_libusb_get_device_list, .args.gdl =
      { DUMMY_PTR, dummy_device_list , sizeof (dummy_device_list) / sizeof(dummy_device_list[0]) } },
    { .func = __wrap_libusb_get_device_descriptor, .args.gdd =
      { DUMMY_PTR, { .idVendor = VID_PI3G, .idProduct = PID_LTT2GO, .iSerialNumber = DEV_DESC_SERIAL_NUMBER_INDEX } } },
    { .func = __wrap_libusb_get_config_descriptor, .args.gcd = { DUMMY_PTR, 0, &dummy_config_desc } },
    { .func = __wrap_libusb_free_config_descriptor, .args.fcd = { &dummy_config_desc } },
    { .func = __wrap_libusb_open, .args.open = { DUMMY_PTR, DUMMY_PTR } },
    { .func = __wrap_libusb_get_string_descriptor_ascii, .args.gsda =
      { DUMMY_PTR, DEV_DESC_SERIAL_NUMBER_INDEX, (unsigned char *)DEV_DESC_SERIAL_NUMBER, 256 } },
    { .func = __wrap_libusb_close, .args.close = { DUMMY_PTR } },
    { .func = __wrap_libusb_free_device_list, .args.fdl = { dummy_device_list, 1 } },
    { .func = __wrap_libusb_exit, .args.exit = { DUMMY_PTR } },

    { 0 },
};

TSS2_RC __wrap_Tss2_Tcti_Spi_Helper_Init (TSS2_TCTI_CONTEXT *tcti_context, size_t *size, TSS2_TCTI_SPI_HELPER_PLATFORM *platform)
{
    void *data;
    bool is_expired = false;
    uint8_t response[sizeof (TPM2_STARTUP_CMD_MISO)] = { 0 };

    if (tcti_context == NULL) {
        *size = sizeof (TSS2_TCTI_SPI_LTT2GO_TEST_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    data = platform->user_data;
    assert_non_null (data);

    if (tester_ctx.is_regex_test) {
        platform->finalize (data);
        return TSS2_RC_SUCCESS;
    }

    /* Test TSS2_TCTI_SPI_HELPER_PLATFORM's callbacks */

    assert_int_equal (platform->sleep_ms (data, TIME_MS), TSS2_RC_SUCCESS);
    assert_int_equal (platform->start_timeout (data, TIME_MS), TSS2_RC_SUCCESS);
    assert_int_equal (platform->timeout_expired (data, &is_expired), TSS2_RC_SUCCESS);
    assert_true (is_expired);
    assert_int_equal (platform->timeout_expired (data, &is_expired), TSS2_RC_SUCCESS);
    assert_false (is_expired);
    assert_int_equal (platform->timeout_expired (data, &is_expired), TSS2_RC_SUCCESS);
    assert_true (is_expired);
    assert_int_equal (platform->spi_transfer (data, TPM2_STARTUP_CMD_MOSI,
        response, sizeof (response)), TSS2_RC_SUCCESS);
    assert_true (!memcmp (response, TPM2_STARTUP_CMD_MISO, sizeof (response)));

    platform->finalize (data);

    return TSS2_RC_SUCCESS;
}

static void
tcti_spi_general_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT* tcti_ctx;

    /* Initialize tester context */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_general;
    tester_ctx.is_regex_test = false;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Ltt2go_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Initialize TCTI context */
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    free (tcti_ctx);
}

/*
 * The focus of this test is to verify the implementation of serial number matching
 */
static void
tcti_spi_regex_test (void **state)
{
    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    /* Initialize tester context */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex;
    tester_ctx.is_regex_test = true;

    /* Get requested TCTI context size */
    rc = Tss2_Tcti_Spi_Ltt2go_Init (NULL, &size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    /* Allocate TCTI context size */
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc (1, size);
    assert_non_null (tcti_ctx);

    /* Positive tests: */

    /* Initialize TCTI context with S/N: DEV_DESC_SERIAL_NUMBER */
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, DEV_DESC_SERIAL_NUMBER);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N starting with "Y23CW" */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "^Y23CW");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N containing "RND9876" */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "RND9876");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N ending with "321012" */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "321012$");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    memset (tcti_ctx, 0, size);

    /* Negative tests: */

    /* Initialize TCTI context with S/N starting with "Z23CW" */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex_nok;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "^Z23CW");
    assert_int_equal (rc, TSS2_BASE_RC_IO_ERROR);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N containing "RND8876" */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex_nok;
    rc = Tss2_Tcti_Spi_Ltt2go_Init (tcti_ctx, &size, "RND8876");
    assert_int_equal (rc, TSS2_BASE_RC_IO_ERROR);
    memset (tcti_ctx, 0, size);

    /* Initialize TCTI context with S/N ending with "321011" */
    tester_ctx.audit_step = 0;
    tester_ctx.audit = audit_regex_nok;
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
        cmocka_unit_test (tcti_spi_general_test),
        cmocka_unit_test (tcti_spi_regex_test),
    };

    return cmocka_run_group_tests (tests, NULL, NULL);
}
