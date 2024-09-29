/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2/tss2_esys.h"
#include "tss2/tss2_mu.h"
#include "tss2/tss2_tcti_py.h"

#include "tss2-tcti/tcti-py.h"

/* test/helper/pytcti.py */
#define PY_TCTI "pytcti"

static char expected_response[] = {
  0x00,
  0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x01, 0x00, 0x32,
  0x2e, 0x30, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x01, 0x03, 0x00,
  0x00, 0x00, 0x4b, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x07, 0xe5, 0x00,
  0x00, 0x01, 0x05, 0x49, 0x42, 0x4d, 0x00, 0x00, 0x00, 0x01, 0x06, 0x53,
  0x57, 0x20, 0x20, 0x00, 0x00, 0x01, 0x07, 0x20, 0x54, 0x50, 0x4d, 0x00,
  0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x09, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00,
  0x00, 0x01, 0x0b, 0x20, 0x19, 0x10, 0x23, 0x00, 0x00, 0x01, 0x0c, 0x00,
  0x16, 0x36, 0x36, 0x00, 0x00, 0x01, 0x0d, 0x00, 0x00, 0x04, 0x00, 0x00,
  0x00, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01, 0x0f, 0x00,
  0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00,
  0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01, 0x12, 0x00,
  0x00, 0x00, 0x18, 0x00, 0x00, 0x01, 0x13, 0x00, 0x00, 0x00, 0x03, 0x00,
  0x00, 0x01, 0x14, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x16, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x17, 0x00, 0x00, 0x08, 0x00, 0x00,
  0x00, 0x01, 0x18, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x19, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00,
  0x00, 0x01, 0x1b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x1c, 0x00,
  0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x1d, 0x00, 0x00, 0x00, 0xff, 0x00,
  0x00, 0x01, 0x1e, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x1f, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00,
  0x00, 0x01, 0x21, 0x00, 0x00, 0x0a, 0x84, 0x00, 0x00, 0x01, 0x22, 0x00,
  0x00, 0x01, 0x94, 0x00, 0x00, 0x01, 0x23, 0x32, 0x2e, 0x30, 0x00, 0x00,
  0x00, 0x01, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x25, 0x00,
  0x00, 0x00, 0xa4, 0x00, 0x00, 0x01, 0x26, 0x00, 0x00, 0x00, 0x4b, 0x00,
  0x00, 0x01, 0x27, 0x00, 0x00, 0x07, 0xe5, 0x00, 0x00, 0x01, 0x28, 0x00,
  0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x29, 0x00, 0x00, 0x00, 0x6e, 0x00,
  0x00, 0x01, 0x2a, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x01, 0x2b, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x04, 0x00, 0x00,
  0x00, 0x01, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2e, 0x00,
  0x00, 0x04, 0x00
};

static void
tcti_py_init_context_and_size_null_test (void **state)
{
    TSS2_RC rc;

    rc = Tss2_Tcti_Py_Init (NULL, NULL, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}

static void
tcti_py_init_size_test (void **state)
{
    size_t tcti_size = 0;
    TSS2_RC rc;

    rc = Tss2_Tcti_Py_Init (NULL, &tcti_size, "foomod");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (tcti_size, sizeof (TSS2_TCTI_PY_CONTEXT));
}

static void
tcti_py_test_cmd (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;
    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    ESYS_CONTEXT *ectx = NULL;
    rc = Esys_Initialize(&ectx, tcti, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TPMI_YES_NO yes_no = TPM2_NO;
    TPMS_CAPABILITY_DATA *cap_data = NULL;
    rc = Esys_GetCapability(ectx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED, TPM2_MAX_TPM_PROPERTIES,
            &yes_no, &cap_data);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_non_null(cap_data);

    size_t offset = 0;
    uint8_t buf[sizeof(*cap_data)];
    rc = Tss2_MU_TPMS_CAPABILITY_DATA_Marshal(cap_data, buf, sizeof(buf), &offset);
    Esys_Free(cap_data);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    assert_int_equal(offset, sizeof(expected_response));
    assert_memory_equal(buf, expected_response, offset);
}

static void
tcti_py_test_make_sticky_good (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;
    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TPM2_HANDLE handle = 0xbadcc0de;
    rc = Tss2_Tcti_MakeSticky(tcti, &handle, 1);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal(handle, 0xbadcc0de + 1);

    handle = 0xdeadbeef;
    rc = Tss2_Tcti_MakeSticky(tcti, &handle, 0);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal(handle, 0xdeadbeef);
}

static void
tcti_py_test_make_sticky_bad (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;
    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI":make_sticky");
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TPM2_HANDLE handle = 0xbadcc0de;
    rc = Tss2_Tcti_MakeSticky(tcti, &handle, 1);
    assert_int_not_equal (rc, TSS2_RC_SUCCESS);
    /* value should be left untouched on failure */
    assert_int_equal(handle, 0xbadcc0de);
}

static void
tcti_py_test_set_locality_good (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;
    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    rc = Tss2_Tcti_SetLocality(tcti, 42);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}

static void
tcti_py_test_set_locality_bad (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;
    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI":set_locality");
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    rc = Tss2_Tcti_SetLocality(tcti, 42);
    assert_int_not_equal (rc, TSS2_RC_SUCCESS);
}

static void
tcti_py_test_tcti_init_exception (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;

    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI":init");
    assert_int_not_equal (rc, TSS2_RC_SUCCESS);
}

static void
tcti_py_test_tcti_recv_exception (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;

    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI":receive");
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    ESYS_CONTEXT *ectx = NULL;
    rc = Esys_Initialize(&ectx, tcti, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TPMI_YES_NO yes_no = TPM2_NO;
    TPMS_CAPABILITY_DATA *cap_data = NULL;
    rc = Esys_GetCapability(ectx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED, TPM2_MAX_TPM_PROPERTIES,
            &yes_no, &cap_data);
    assert_int_not_equal (rc, TSS2_RC_SUCCESS);
}

static void
tcti_py_test_tcti_transmit_exception (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;

    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI":transmit");
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    ESYS_CONTEXT *ectx = NULL;
    rc = Esys_Initialize(&ectx, tcti, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    TPMI_YES_NO yes_no = TPM2_NO;
    TPMS_CAPABILITY_DATA *cap_data = NULL;
    rc = Esys_GetCapability(ectx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED, TPM2_MAX_TPM_PROPERTIES,
            &yes_no, &cap_data);
    assert_int_not_equal (rc, TSS2_RC_SUCCESS);
}

static void
tcti_py_test_tcti_finalize_good (void **state)
{
    TSS2_RC rc;

    char _tcti[sizeof(TSS2_TCTI_PY_CONTEXT)];
    size_t tcti_size = sizeof(_tcti);
    TSS2_TCTI_CONTEXT *tcti = (TSS2_TCTI_CONTEXT *)&_tcti;

    rc = Tss2_Tcti_Py_Init (tcti, &tcti_size, PY_TCTI);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    Tss2_Tcti_Finalize(tcti);
}

static void
tcti_py_test_tcti_finalize_bad (void **state)
{
    Tss2_Tcti_Finalize(NULL);
}

static int group_setup(void **state)
{
    return setenv("PYTHONPATH", "test/helper", 1);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_py_init_context_and_size_null_test),
        cmocka_unit_test (tcti_py_init_size_test),
        cmocka_unit_test (tcti_py_test_cmd),
        cmocka_unit_test (tcti_py_test_tcti_init_exception),
        cmocka_unit_test (tcti_py_test_tcti_recv_exception),
        cmocka_unit_test (tcti_py_test_tcti_transmit_exception),
        cmocka_unit_test (tcti_py_test_tcti_finalize_good),
        cmocka_unit_test (tcti_py_test_tcti_finalize_bad),
        cmocka_unit_test (tcti_py_test_make_sticky_good),
        cmocka_unit_test (tcti_py_test_make_sticky_bad),
        cmocka_unit_test (tcti_py_test_set_locality_good),
        cmocka_unit_test (tcti_py_test_set_locality_bad),
    };

    return cmocka_run_group_tests (tests, group_setup, NULL);
}
