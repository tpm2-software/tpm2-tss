/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include <dlfcn.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_tcti.h"

#include "esys_tcti_default.h"
#define LOGMODULE test
#include "util/log.h"

#ifndef ESYS_TCTI_DEFAULT_MODULE

void *
__wrap_dlopen(const char *filename, int flags)
{
    LOG_TRACE("Called with filename %s and flags %x", filename, flags);
    check_expected_ptr(filename);
    check_expected(flags);
    return mock_type(void *);
}

int
__wrap_dlclose(void *handle)
{
    LOG_TRACE("Called with handle %p", handle);
    check_expected_ptr(handle);
    return mock_type(int);
}

void *
__wrap_dlsym(void *handle, const char *symbol)
{
    LOG_TRACE("Called with handle %p and symbol %s", handle, symbol);
    check_expected_ptr(handle);
    check_expected_ptr(symbol);
    return mock_type(void *);
}

TSS2_RC
__wrap_Tss2_Tcti_Fake_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
                           const char *config)
{
    LOG_TRACE("Called with tctiContext %p, size %p and config %s", tctiContext,
              size, config);
    check_expected(tctiContext);
    check_expected_ptr(size);
    check_expected_ptr(config);
    *size = mock_type(size_t);
    return mock_type(TSS2_RC);
}

TSS2_TCTI_INFO *
__wrap_Tss2_Tcti_Fake_Info(void)
{
    LOG_TRACE("Called.");
    return mock_type(TSS2_TCTI_INFO *);
}

TSS2_RC
__wrap_Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
                             const char *config)
{
    LOG_TRACE("Called with tctiContext %p, size %p and config %s", tctiContext,
              size, config);
    check_expected_ptr(tctiContext);
    check_expected_ptr(size);
    check_expected_ptr(config);
    *size = mock_type(size_t);
    return mock_type(TSS2_RC);
}

TSS2_RC
__wrap_Tss2_Tcti_Mssim_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
                            const char *config)
{
    LOG_TRACE("Called with tctiContext %p, size %p and config %s", tctiContext,
              size, config);
    check_expected_ptr(tctiContext);
    check_expected_ptr(size);
    check_expected_ptr(config);
    *size = mock_type(size_t);
    return mock_type(TSS2_RC);
}

static void
test_fail_null(void **state)
{
    TSS2_RC r = get_tcti_default(NULL, NULL);
    assert_int_equal(r, TSS2_TCTI_RC_BAD_REFERENCE);
}

#ifndef NO_DL
/** Test for tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default(void **state)
{
    size_t lsize = 0x99;
#define HANDLE (void *)123321

    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    TSS2_TCTI_INFO fakeInfo = {
        .version = 2,
        .name = "FakeTCTI",
        .description = "FakeDesc",
        .config_help = "FakeHelp",
        .init = &__wrap_Tss2_Tcti_Fake_Init,
    };
    will_return(__wrap_Tss2_Tcti_Fake_Info, &fakeInfo);

    expect_value(__wrap_Tss2_Tcti_Fake_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Fake_Init, size);
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Fake_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Fake_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default_fail_sym(void **state)
{
    size_t lsize = 0x99;
#define HANDLE (void *)123321

    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, NULL);

    expect_value(__wrap_dlclose, handle, HANDLE);
    will_return(__wrap_dlclose, 0);

    /** Now test
     *{ "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so"},
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    TSS2_TCTI_INFO fakeInfo = {
        .version = 2,
        .name = "FakeTCTI",
        .description = "FakeDesc",
        .config_help = "FakeHelp",
        .init = &__wrap_Tss2_Tcti_Fake_Init,
    };
    will_return(__wrap_Tss2_Tcti_Fake_Info, &fakeInfo);

    expect_value(__wrap_Tss2_Tcti_Fake_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Fake_Init, size);
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Fake_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Fake_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default_fail_info(void **state)
{
    size_t lsize = 0x99;
#define HANDLE (void *)123321

 /** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    will_return(__wrap_Tss2_Tcti_Fake_Info, NULL);

    expect_value(__wrap_dlclose, handle, HANDLE);
    will_return(__wrap_dlclose, 0);

    /** Now test
     *{ "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so"},
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    TSS2_TCTI_INFO fakeInfo = {
        .version = 2,
        .name = "FakeTCTI",
        .description = "FakeDesc",
        .config_help = "FakeHelp",
        .init = &__wrap_Tss2_Tcti_Fake_Init,
    };
    will_return(__wrap_Tss2_Tcti_Fake_Info, &fakeInfo);

    expect_value(__wrap_Tss2_Tcti_Fake_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Fake_Init, size);
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Fake_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Fake_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default_fail_init(void **state)
{
    size_t lsize = 0x99;
#define HANDLE (void *)123321

 /** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    TSS2_TCTI_INFO fakeInfo = {
        .version = 2,
        .name = "FakeTCTI",
        .description = "FakeDesc",
        .config_help = "FakeHelp",
        .init = &__wrap_Tss2_Tcti_Fake_Init,
    };
    will_return(__wrap_Tss2_Tcti_Fake_Info, &fakeInfo);

    expect_value(__wrap_Tss2_Tcti_Fake_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Fake_Init, size);
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Fake_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Fake_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_BASE_RC_GENERAL_FAILURE);

    expect_value(__wrap_dlclose, handle, HANDLE);
    will_return(__wrap_dlclose, 0);

    /** Now test
     *{ "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so"},
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    will_return(__wrap_Tss2_Tcti_Fake_Info, &fakeInfo);

    expect_value(__wrap_Tss2_Tcti_Fake_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Fake_Init, size);
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Fake_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Fake_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for tcti
 * { "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so" }
 */
static void
test_tcti_tabrmd(void **state)
{
#define HANDLE (void *)123321
    size_t lsize = 0x99;

    /** Skip over
     * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /** Now test
     *{ "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so"},
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    TSS2_TCTI_INFO fakeInfo = {
        .version = 2,
        .name = "FakeTCTI",
        .description = "FakeDesc",
        .config_help = "FakeHelp",
        .init = &__wrap_Tss2_Tcti_Fake_Init,
    };
    will_return(__wrap_Tss2_Tcti_Fake_Info, &fakeInfo);

    expect_value(__wrap_Tss2_Tcti_Fake_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Fake_Init, size);
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Fake_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Fake_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Fake_Init, config, "");
    will_return(__wrap_Tss2_Tcti_Fake_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Fake_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}
#endif /* NO_DL */

/** Test for tcti
 * { NULL, Tss2_Tcti_Device_Init, "/dev/tpmrm0", "Access to /dev/tpmrm0" }
 */
static void
test_tcti_tpmrm0(void **state)
{
    size_t lsize = 0x99;
#ifndef NO_DL
    /** Skip over
     * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /** Skip over
     * { "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);
#endif /* NO_DL */

    /** Now test
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpmrm0", "Access to /dev/tpmrm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpmrm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Device_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Device_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpmrm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for tcti
 * { NULL, Tss2_Tcti_Device_Init, "/dev/tpm0", "Access to /dev/tpm0"},
 */
static void
test_tcti_tpm0(void **state)
{
    size_t lsize = 0x99;
#ifndef NO_DL
    /** Skip over
     * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /** Skip over
     * { "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);
#endif /* NO_DL */

    /** Skip over
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpmrm0", "Access to /dev/tpmrm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpmrm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, 0);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_TCTI_RC_IO_ERROR);

    /** Now test
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpmrm0", "Access to /dev/tpm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Device_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Device_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for tcti
 * { NULL, Tss2_Tcti_Mssim_Init, "tcp://127.0.0.1:2321",
 *      "Access to Mssim-simulator for tcp://localhost:2321" }
 */
static void
test_tcti_mssim(void **state)
{
    size_t lsize = 0x99;
#ifndef NO_DL
    /** Skip over
     * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /** Skip over
     * { "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);
#endif /* NO_DL */

    /** Skip over
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpmrm0", "Access to /dev/tpmrm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpmrm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, 0);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_TCTI_RC_IO_ERROR);

    /** Skip over
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpm0", "Access to /dev/tpm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, 0);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_TCTI_RC_IO_ERROR);

    /** Now test
     * { NULL, Tss2_Tcti_Mssim_Init, "tcp://127.0.0.1:2321",
     *      "Access to Mssim-simulator for tcp://localhost:2321" }
     */
    expect_value(__wrap_Tss2_Tcti_Mssim_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Mssim_Init, size);
    expect_string(__wrap_Tss2_Tcti_Mssim_Init, config, "host=localhost,port=2321");
    will_return(__wrap_Tss2_Tcti_Mssim_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Mssim_Init, TSS2_RC_SUCCESS);

    expect_any(__wrap_Tss2_Tcti_Mssim_Init, tctiContext);
    expect_memory(__wrap_Tss2_Tcti_Mssim_Init, size, &lsize, sizeof(lsize));
    expect_string(__wrap_Tss2_Tcti_Mssim_Init, config, "host=localhost,port=2321");
    will_return(__wrap_Tss2_Tcti_Mssim_Init, lsize);
    will_return(__wrap_Tss2_Tcti_Mssim_Init, TSS2_RC_SUCCESS);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
    free(tcti);
}

/** Test for tcti fail all
 * { NULL, Tss2_Tcti_Mssim_Init, "tcp://127.0.0.1:2321",
 *      "Access to Mssim-simulator for tcp://localhost:2321" }
 */
static void
test_tcti_fail_all(void **state)
{
#ifndef NO_DL
    /** Skip over
     * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /** Skip over
     * { "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so" }
     */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);
#endif /* NO_DL */

    /** Skip over
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpmrm0", "Access to /dev/tpmrm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpmrm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, 0);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_TCTI_RC_IO_ERROR);

    /** Skip over
     * { NULL, Tss2_Tcti_Device_Init, "/dev/tpm0", "Access to /dev/tpm0" }
     */
    expect_value(__wrap_Tss2_Tcti_Device_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Device_Init, size);
    expect_string(__wrap_Tss2_Tcti_Device_Init, config, "/dev/tpm0");
    will_return(__wrap_Tss2_Tcti_Device_Init, 0);
    will_return(__wrap_Tss2_Tcti_Device_Init, TSS2_TCTI_RC_IO_ERROR);

    /** Now test
     * { NULL, Tss2_Tcti_Mssim_Init, "tcp://127.0.0.1:2321",
     *      "Access to Mssim-simulator for tcp://localhost:2321" }
     */
    expect_value(__wrap_Tss2_Tcti_Mssim_Init, tctiContext, NULL);
    expect_any(__wrap_Tss2_Tcti_Mssim_Init, size);
    expect_string(__wrap_Tss2_Tcti_Mssim_Init, config, "host=localhost,port=2321");
    will_return(__wrap_Tss2_Tcti_Mssim_Init, 0);
    will_return(__wrap_Tss2_Tcti_Mssim_Init, TSS2_TCTI_RC_IO_ERROR);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = get_tcti_default(&tcti, NULL);
    assert_int_equal(r, TSS2_ESYS_RC_NOT_IMPLEMENTED);
    free(tcti);
}

#endif /* ESYS_TCTI_DEFAULT_MODULE */

int
main(void)
{
#ifdef ESYS_TCTI_DEFAULT_MODULE
    LOG_WARNING("ESYS_TCTI_DEFAULT_MODULE was defined during configuration. "
              "Thus nothing to test here.");
    return 77;

#else /* ESYS_TCTI_DEFAULT_MODULE */

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fail_null),
#ifndef NO_DL
        cmocka_unit_test(test_tcti_default),
        cmocka_unit_test(test_tcti_default_fail_sym),
        cmocka_unit_test(test_tcti_default_fail_info),
        cmocka_unit_test(test_tcti_default_fail_init),
        cmocka_unit_test(test_tcti_tabrmd),
#endif /* NO_DL */
        cmocka_unit_test(test_tcti_tpmrm0),
        cmocka_unit_test(test_tcti_tpm0),
        cmocka_unit_test(test_tcti_mssim),
        cmocka_unit_test(test_tcti_fail_all),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);

#endif /* ESYS_TCTI_DEFAULT_MODULE */
}
