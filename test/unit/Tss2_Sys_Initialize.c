#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tpm20.h"
#include "sysapi_util.h"

TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;

/**
 * Sets tssCreator to weird value
 */
static void
Tss2_Sys_Initialize_tssCreator_unit (void **state)
{
    UINT32 contextSize = 1000;
    TSS2_RC rval;
    TSS2_SYS_CONTEXT *sysContext;
    TSS2_ABI_VERSION tstAbiVersion = { 0xF0000000, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

    contextSize = Tss2_Sys_GetContextSize(contextSize);
    sysContext = (TSS2_SYS_CONTEXT *)malloc(contextSize);
    assert_non_null(sysContext);
    rval = Tss2_Sys_Initialize(sysContext, contextSize, resMgrTctiContext, &tstAbiVersion);
    assert_int_equal(rval, TSS2_SYS_RC_ABI_MISMATCH);
    free(sysContext);
}

/**
 * Sets tssFamily to weird value
 */
static void
Tss2_Sys_Initialize_tssFamily_unit (void **state)
{
    UINT32 contextSize = 1000;
    TSS2_RC rval;
    TSS2_SYS_CONTEXT *sysContext;
    TSS2_ABI_VERSION tstAbiVersion = { TSSWG_INTEROP, 0xF0000000, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

    contextSize = Tss2_Sys_GetContextSize(contextSize);
    sysContext = (TSS2_SYS_CONTEXT *)malloc(contextSize);
    assert_non_null(sysContext);
    rval = Tss2_Sys_Initialize(sysContext, contextSize, resMgrTctiContext, &tstAbiVersion);
    assert_int_equal(rval, TSS2_SYS_RC_ABI_MISMATCH);
    free(sysContext);
}

/**
 * Sets tssLevel to weird value
 */
static void
Tss2_Sys_Initialize_tssLevel_unit (void **state)
{
    UINT32 contextSize = 1000;
    TSS2_RC rval;
    TSS2_SYS_CONTEXT *sysContext;
    TSS2_ABI_VERSION tstAbiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, 0xF0000000, TSS_SAPI_FIRST_VERSION };

    contextSize = Tss2_Sys_GetContextSize(contextSize);
    sysContext = (TSS2_SYS_CONTEXT *)malloc(contextSize);
    assert_non_null(sysContext);
    rval = Tss2_Sys_Initialize(sysContext, contextSize, resMgrTctiContext, &tstAbiVersion);
    assert_int_equal(rval, TSS2_SYS_RC_ABI_MISMATCH);
    free(sysContext);
}

/**
 * Sets tssVersion to weird value
 */
static void
Tss2_Sys_Initialize_tssVersion_unit (void **state)
{
    UINT32 contextSize = 1000;
    TSS2_RC rval;
    TSS2_SYS_CONTEXT *sysContext;
    TSS2_ABI_VERSION tstAbiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, 0xF0000000 };

    contextSize = Tss2_Sys_GetContextSize(contextSize);
    sysContext = (TSS2_SYS_CONTEXT *)malloc(contextSize);
    assert_non_null(sysContext);
    rval = Tss2_Sys_Initialize(sysContext, contextSize, resMgrTctiContext, &tstAbiVersion);
    assert_int_equal(rval, TSS2_SYS_RC_ABI_MISMATCH);
    free(sysContext);
}

/**
 * Tests Tss2_Sys_Initialize with a combination of arguments
 */
static void
Tss2_Sys_Initialize_argCombo1_unit (void **state)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = Tss2_Sys_Initialize((TSS2_SYS_CONTEXT *)0, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1);
    assert_int_equal(rval, TSS2_SYS_RC_BAD_REFERENCE);
}

/**
 * Tests Tss2_Sys_Initialize with a combination of arguments
 */
static void
Tss2_Sys_Initialize_argCombo2_unit (void **state)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = Tss2_Sys_Initialize((TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)0, (TSS2_ABI_VERSION *)1);
    assert_int_equal(rval, TSS2_SYS_RC_BAD_REFERENCE);
}

/**
 * Tests Tss2_Sys_Initialize with a combination of arguments
 */
static void
Tss2_Sys_Initialize_argCombo3_unit (void **state)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = Tss2_Sys_Initialize((TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)0);
    assert_int_equal(rval, TSS2_SYS_RC_BAD_REFERENCE);
}

/**
 * Tests Tss2_Sys_Initialize with a combination of arguments
 */
static void
Tss2_Sys_Initialize_argCombo4_unit (void **state)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = Tss2_Sys_Initialize((TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1);
    assert_int_equal(rval, TSS2_SYS_RC_INSUFFICIENT_CONTEXT);
}

/**
 * Tests Tss2_Sys_Initialize with tctiContext
 */
static void
Tss2_Sys_Initialize_tctiContext1_unit (void **state)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    // NOTE: this should never be done in real applications.
    // It is only done here for test purposes.
    TSS2_TCTI_CONTEXT_INTEL tctiContextIntel;

    // NOTE: don't do this in real applications.
    tctiContextIntel.transmit = (TCTI_TRANSMIT_PTR)0;
    tctiContextIntel.receive = (TCTI_RECEIVE_PTR)1;

    rval = Tss2_Sys_Initialize((TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1);
    assert_int_equal(rval, TSS2_SYS_RC_BAD_TCTI_STRUCTURE);
}

/**
 * Tests Tss2_Sys_Initialize with tctiContext
 */
static void
Tss2_Sys_Initialize_tctiContext2_unit (void **state)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    // NOTE: this should never be done in real applications.
    // It is only done here for test purposes.
    TSS2_TCTI_CONTEXT_INTEL tctiContextIntel;

    // NOTE: don't do this in real applications.
    tctiContextIntel.transmit = (TCTI_TRANSMIT_PTR)1;
    tctiContextIntel.receive = (TCTI_RECEIVE_PTR)0;

    rval = Tss2_Sys_Initialize((TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContextIntel, (TSS2_ABI_VERSION *)1);
    assert_int_equal(rval, TSS2_SYS_RC_BAD_TCTI_STRUCTURE);
}

int
main (int   argc,
      char *argv[])
{
    const UnitTest tests [] = {
        unit_test (Tss2_Sys_Initialize_tssCreator_unit),
        unit_test (Tss2_Sys_Initialize_tssFamily_unit),
        unit_test (Tss2_Sys_Initialize_tssLevel_unit),
        unit_test (Tss2_Sys_Initialize_tssVersion_unit),
        unit_test (Tss2_Sys_Initialize_argCombo1_unit),
        unit_test (Tss2_Sys_Initialize_argCombo2_unit),
        unit_test (Tss2_Sys_Initialize_argCombo3_unit),
        unit_test (Tss2_Sys_Initialize_argCombo4_unit),
        unit_test (Tss2_Sys_Initialize_tctiContext1_unit),
        unit_test (Tss2_Sys_Initialize_tctiContext2_unit),
    };
    return run_tests (tests);
}
