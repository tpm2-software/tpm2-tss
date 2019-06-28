/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include <dlfcn.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_tcti.h"

#include "tss2-tcti/tctildr-interface.h"
#include "tss2-tcti/tctildr-dl.h"
#define LOGMODULE test
#include "util/log.h"

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

TSS2_TCTI_INFO *
__wrap_Tss2_Tcti_Fake_Info(void)
{
    LOG_TRACE("Called.");
    return mock_type(TSS2_TCTI_INFO *);
}

TSS2_RC
__wrap_tcti_from_init(TSS2_TCTI_INIT_FUNC init,
                      const char* conf,
                      TSS2_TCTI_CONTEXT **tcti)
{
    printf("%s", __func__);
    return mock_type (TSS2_RC);
}
TSS2_RC
__wrap_tcti_from_info(TSS2_TCTI_INFO_FUNC infof,
                      const char* conf,
                      TSS2_TCTI_CONTEXT **tcti)
{
    check_expected (infof);
    check_expected (conf);
    check_expected (tcti);
    if (tcti != NULL)
        *tcti = mock_type (TSS2_TCTI_CONTEXT*);
    return mock_type (TSS2_RC);
}

static void
test_fail_null(void **state)
{
    TSS2_RC r = tctildr_get_default(NULL, NULL);
    assert_int_equal(r, TSS2_TCTI_RC_BAD_REFERENCE);
}

#define TEST_TCTI_NAME "test-tcti"
#define TEST_TCTI_CONF "test-conf"
static void
test_tcti_from_file_dlopen_fail (void **state)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    void *handle = NULL;

    expect_string(__wrap_dlopen, filename, TEST_TCTI_NAME);
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    rc = tcti_from_file (TEST_TCTI_NAME, TEST_TCTI_CONF, &tcti_ctx, &handle);
    assert_int_equal (rc, TSS2_ESYS_RC_BAD_REFERENCE);
}

#ifndef ESYS_TCTI_DEFAULT_MODULE

/* global TCTI object reference to be returned by __mock_tcti_from_info */
static TSS2_TCTI_CONTEXT_COMMON_V2 tcti_instance = { 0, };

/** Test for tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default(void **state)
{
#define HANDLE (void *)123321
    TSS2_TCTI_CONTEXT *tcti;

    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    expect_value(__wrap_tcti_from_info, infof, __wrap_Tss2_Tcti_Fake_Info);
    expect_value(__wrap_tcti_from_info, conf, NULL);
    expect_value(__wrap_tcti_from_info, tcti, &tcti);
    will_return(__wrap_tcti_from_info, &tcti_instance);
    will_return(__wrap_tcti_from_info, TSS2_RC_SUCCESS);

    TSS2_RC r;
    void *handle = NULL;
    r = tctildr_get_default(&tcti, &handle);
    assert_int_equal(r, TSS2_RC_SUCCESS);
}

/** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default_fail_sym(void **state)
{
    TSS2_TCTI_CONTEXT *tcti;
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

    expect_value(__wrap_tcti_from_info, infof, __wrap_Tss2_Tcti_Fake_Info);
    expect_value(__wrap_tcti_from_info, conf, NULL);
    expect_value(__wrap_tcti_from_info, tcti, &tcti);
    will_return(__wrap_tcti_from_info, &tcti_instance);
    will_return(__wrap_tcti_from_info, TSS2_RC_SUCCESS);

    TSS2_RC r;
    r = tctildr_get_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
}

/** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
static void
test_tcti_default_fail_info(void **state)
{
    TSS2_TCTI_CONTEXT *tcti;
#define HANDLE (void *)123321
#define TEST_RC 0x55687

 /** Test for failure on tcti
 * { "libtss2-tcti-default.so", NULL, "", "Access libtss2-tcti-default.so" }
 */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, HANDLE);

    expect_value(__wrap_dlsym, handle, HANDLE);
    expect_string(__wrap_dlsym, symbol, TSS2_TCTI_INFO_SYMBOL);
    will_return(__wrap_dlsym, &__wrap_Tss2_Tcti_Fake_Info);

    expect_value(__wrap_tcti_from_info, infof, __wrap_Tss2_Tcti_Fake_Info);
    expect_value(__wrap_tcti_from_info, conf, NULL);
    expect_value(__wrap_tcti_from_info, tcti, &tcti);
    will_return(__wrap_tcti_from_info, &tcti_instance);
    will_return(__wrap_tcti_from_info, TEST_RC);

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

    expect_value(__wrap_tcti_from_info, infof, __wrap_Tss2_Tcti_Fake_Info);
    expect_value(__wrap_tcti_from_info, conf, NULL);
    expect_value(__wrap_tcti_from_info, tcti, &tcti);
    will_return(__wrap_tcti_from_info, &tcti_instance);
    will_return(__wrap_tcti_from_info, TSS2_RC_SUCCESS);

    TSS2_RC r;
    r = tctildr_get_default(&tcti, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);
}

static void
test_tcti_fail_all (void **state)
{
    /* skip over libtss2-tcti-default.so */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-default.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /* Skip over libtss2-tcti-tabrmd.so */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-tabrmd.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /* Skip over libtss2-tcti-device.so, /dev/tpmrm0 */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-device.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    /* Skip over libtss2-tcti-device.so, /dev/tpm0 */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-device.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);
    /* Skip over libtss2-tcti-mssim.so */
    expect_string(__wrap_dlopen, filename, "libtss2-tcti-mssim.so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, NULL);

    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    r = tctildr_get_default(&tcti, NULL);
    assert_int_equal(r, TSS2_TCTI_RC_IO_ERROR);
}
#endif

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tcti_from_file_dlopen_fail),
        cmocka_unit_test(test_fail_null),
#ifndef ESYS_TCTI_DEFAULT_MODULE
        cmocka_unit_test(test_tcti_default),
        cmocka_unit_test(test_tcti_default_fail_sym),
        cmocka_unit_test(test_tcti_default_fail_info),
        cmocka_unit_test(test_tcti_fail_all),
#endif
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
