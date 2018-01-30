//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include <sapi/tpm20.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define assert_string_prefix(str, prefix) \
    assert_memory_equal(str, prefix, strlen(prefix))

static void
test_layers (
    void **state)
{
    (void) state;

    static const char *known_layers[TSS2_RC_LAYER_COUNT] = {
            "tpm:",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            "fapi:",
            "sys:",
            "mu:",
            "tcti:",
            "rmt",
            "rm",
            "drvr",
    };

    UINT8 layer;
    for (layer = 0; layer < TSS2_RC_LAYER_COUNT; layer++) {
        TSS2_RC rc = TSS2_RC_LAYER(layer);

        const char *got = Tss2_Rc_StrError (rc);

        char buf[256];
        snprintf (buf, sizeof(buf), "%u:", layer);

        const char *expected = known_layers[layer] ? known_layers[layer] : buf;
        assert_string_prefix(got, expected);
    }
}

static void
test_tpm_format_0_version2_0_error (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_SEQUENCE);
    assert_string_equal(m, "tpm:error(2.0): improper use of a sequence"
        " handle");
}

static void
test_tpm_format_0_version2_0_warn (void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_REFERENCE_H0);
    assert_string_equal(m,
        "tpm:warn(2.0): the 1st handle in the handle area references a"
        " transient object or session that is not loaded");
}

static void
test_tpm2_format_0_unkown (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_NOT_USED + 0x80);
    assert_string_equal(m, "tpm:parameter(1):unknown error num: 0x3F");
}

static void
test_tpm_format_1_unk_handle (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_HASH);
    assert_string_equal(m,
        "tpm:handle(unk):hash algorithm not supported or not appropriate");
}

static void
test_tpm_format_1_unk_parameter (void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_HASH + TPM2_RC_P);
    assert_string_equal(m,
        "tpm:parameter(unk):hash algorithm not supported or not appropriate");
}

static void
test_tpm_format_1_unk_session (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_HASH + TPM2_RC_S);
    assert_string_equal(m,
        "tpm:session(unk):hash algorithm not supported or not appropriate");
}

static void
test_tpm_format_1_5_handle (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_HASH + TPM2_RC_5);
    assert_string_equal(m,
        "tpm:handle(5):hash algorithm not supported or not appropriate");
}

static void
test_tpm2_format_1_unkown (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_NOT_USED + 0x80);
    assert_string_equal(m, "tpm:parameter(1):unknown error num: 0x3F");
}

static void
test_tpm2_format_1_success (
    void **state)
{
    (void) state;

    const char *m = Tss2_Rc_StrError (TPM2_RC_SUCCESS);
    assert_string_equal(m, "tpm:success");
}

static const char *
custom_err_handler (
        TSS2_RC rc)
{

    static const char *err_map[] = {
        "error 1", "error 2", "error 3"
    };

    if (rc - 1u >= ARRAY_LEN(err_map)) {
        return NULL;
    }

    return err_map[rc - 1];
}

static void
test_custom_handler (
    void **state)
{
    (void) state;

    /*
     * Test registering a custom handler
     */
    bool res = Tss2_Rc_Set_Handler (1, "cstm", custom_err_handler);
    assert_true(res);

    /*
     * Test getting error strings
     */
    unsigned i;
    for (i = 1; i < 4; i++) {
        // Make a layer 1 error with an error number of i.
        TSS2_RC rc = TSS2_RC_LAYER(1) | i;
        char buf[256];
        snprintf (buf, sizeof(buf), "cstm:error %u", i);

        const char *e = Tss2_Rc_StrError (rc);
        assert_string_equal(e, buf);
    }

    TSS2_RC rc = TSS2_RC_LAYER(1) | 42;

    /*
     * Test an unknown error
     */
    const char *e = Tss2_Rc_StrError (rc);
    assert_string_equal(e, "cstm:0x2A");

    /*
     * Test clearing a handler
     */
    res = Tss2_Rc_Set_Handler (1, "cstm", NULL);
    assert_true(res);

    /*
     * Test an unknown layer
     */
    e = Tss2_Rc_StrError (rc);
    assert_string_equal(e, "1:0x2A");
}

static void
test_zero_length_name (
    void **state)
{
    (void) state;

    bool res = Tss2_Rc_Set_Handler (TSS2_TPM_RC_LAYER, "", custom_err_handler);
    assert_false(res);
}

static void
test_over_length_name (
    void **state)
{
    (void) state;

    bool res = Tss2_Rc_Set_Handler (1, "way to long", custom_err_handler);
    assert_false(res);
}

static void
test_reserved_handler (
    void **state)
{
    (void) state;

    bool res = Tss2_Rc_Set_Handler (TSS2_TPM_RC_LAYER, "nope",
                                    custom_err_handler);
    assert_false(res);
}

static void
test_null_name (
    void **state)
{
    (void) state;

    bool res = Tss2_Rc_Set_Handler (TSS2_TPM_RC_LAYER,
    NULL,
                                    custom_err_handler);
    assert_false(res);
}

static void
test_sys (
    void **state)
{
    (void) state;

    const char *e = Tss2_Rc_StrError (TSS2_SYS_RC_ABI_MISMATCH);
    assert_string_equal(e,
        "sys:Passed in ABI version doesn't match called module's ABI version");
}

static void
test_mu (
    void **state)
{
    (void) state;

    const char *e = Tss2_Rc_StrError (TSS2_MU_RC_BAD_REFERENCE);
    assert_string_equal(e,
        "mu:A pointer is NULL that isn't allowed to be NULL.");

}

static void
test_tcti (
    void **state)
{
    (void) state;

    const char *e = Tss2_Rc_StrError (TSS2_TCTI_RC_NO_CONNECTION);
    assert_string_equal(e, "tcti:Fails to connect to next lower layer");
}

int
main (
    int argc,
    char* argv[])
{
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
            /* Layer tests */
            cmocka_unit_test(test_layers),
            cmocka_unit_test(test_tpm_format_0_version2_0_error),
            cmocka_unit_test(test_tpm_format_0_version2_0_warn),
            cmocka_unit_test(test_tpm2_format_0_unkown),
            cmocka_unit_test(test_tpm_format_1_unk_handle),
            cmocka_unit_test(test_tpm_format_1_unk_parameter),
            cmocka_unit_test(test_tpm_format_1_unk_session),
            cmocka_unit_test(test_tpm_format_1_5_handle),
            cmocka_unit_test(test_tpm2_format_1_unkown),
            cmocka_unit_test(test_tpm2_format_1_success),
            cmocka_unit_test(test_custom_handler),
            cmocka_unit_test(test_zero_length_name),
            cmocka_unit_test(test_over_length_name),
            cmocka_unit_test(test_reserved_handler),
            cmocka_unit_test(test_null_name),
            cmocka_unit_test(test_sys),
            cmocka_unit_test(test_mu),
            cmocka_unit_test(test_tcti),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
