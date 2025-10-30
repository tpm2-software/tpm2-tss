/* SPDX-FileCopyrightText: 2021, Fraunhofer SIT sponsored by Infineon */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdio.h>         // for NULL, fprintf, stderr
#include <stdlib.h>        // for exit

#include "../helper/cmocka_all.h"        // for will_return, assert_int_equal, cmocka_unit...
#include "tss2_common.h"   // for TSS2_BASE_RC_NOT_IMPLEMENTED, TSS2_RC, TSS...
#include "tss2_esys.h"     // for Esys_Initialize
#include "tss2_fapi.h"     // for Fapi_Initialize, Fapi_Initialize_Async
#include "tss2_mu.h"       // for Tss2_MU_TPM2B_DIGEST_Marshal, Tss2_MU_TPM2...
#include "tss2_rc.h"       // for Tss2_RC_Decode, Tss2_RC_SetHandler, TSS2_R...
#include "tss2_tctildr.h"  // for Tss2_TctiLdr_GetInfo, Tss2_TctiLdr_Initialize


#define DLOPEN_HANDLE ((void *)0xaaffffee)

void *__wrap_dlopen(const char *filename, int flags)
{
    return mock_type (void *);
}

void *__wrap_dlsym(void *handle, const char *symbol)
{
    if (handle != DLOPEN_HANDLE) {
        fprintf(stderr, "dlsym called with weird handle %p\n", handle);
        exit(99);
    }
    return mock_type (void *);
}

static void test_tctildr(void **state)
{
    TSS2_RC r;

    will_return(__wrap_dlopen, NULL);
    r = Tss2_TctiLdr_Initialize_Ex(NULL, NULL, NULL);
    assert_int_equal(r, TSS2_TCTI_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_TctiLdr_Initialize(NULL, NULL);
    assert_int_equal(r, TSS2_TCTI_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_TctiLdr_GetInfo(NULL, NULL);
    assert_int_equal(r, TSS2_TCTI_RC_NOT_IMPLEMENTED);
}

static void test_mu(void **state)
{
    TSS2_RC r;

    will_return(__wrap_dlopen, NULL);
    r = Tss2_MU_UINT8_Marshal(0, NULL, 0, NULL);
    assert_int_equal(r, TSS2_BASE_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_MU_UINT8_Unmarshal(NULL, 0, NULL, NULL);
    assert_int_equal(r, TSS2_BASE_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_MU_TPM2B_DIGEST_Marshal(NULL, NULL, 0, NULL);
    assert_int_equal(r, TSS2_BASE_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_MU_TPM2B_DIGEST_Unmarshal(NULL, 0, NULL, NULL);
    assert_int_equal(r, TSS2_BASE_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_MU_TPMU_HA_Marshal(NULL, 0, NULL, 0, NULL);
    assert_int_equal(r, TSS2_BASE_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Tss2_MU_TPMU_HA_Unmarshal(NULL, 0, NULL, 0, NULL);
    assert_int_equal(r, TSS2_BASE_RC_NOT_IMPLEMENTED);
}

static void test_rc(void **state)
{
    const char *r;
    TSS2_RC_HANDLER h;

    will_return(__wrap_dlopen, NULL);
    r = Tss2_RC_Decode(0);
    assert_string_equal(r, "libtss2-rc.so.0 not found.");

    will_return(__wrap_dlopen, NULL);
    h = Tss2_RC_SetHandler(0, NULL, NULL);
    assert_null(h);
}

static void test_esys(void **state)
{
    TSS2_RC r;

    will_return(__wrap_dlopen, NULL);
    r = Esys_Initialize(NULL, NULL, NULL);
    assert_int_equal(r, TSS2_ESYS_RC_NOT_IMPLEMENTED);
}

static void test_fapi(void **state)
{
    TSS2_RC r;

    will_return(__wrap_dlopen, NULL);
    r = Fapi_Initialize(NULL, NULL);
    assert_int_equal(r, TSS2_FAPI_RC_NOT_IMPLEMENTED);

    will_return(__wrap_dlopen, NULL);
    r = Fapi_Initialize_Async(NULL, NULL);
    assert_int_equal(r, TSS2_FAPI_RC_NOT_IMPLEMENTED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (test_tctildr),
        cmocka_unit_test (test_rc),
        cmocka_unit_test (test_mu),
        cmocka_unit_test (test_esys),
        cmocka_unit_test (test_fapi)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
