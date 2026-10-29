/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../helper/cmocka_all.h"
#include "ifapi_policyutil_execute.h"
#include <stdlib.h>

/* Exercise the FAPI execution boundary without a TPM or a real Policy engine. */
static FAPI_CONTEXT *active_context;
static TSS2_RC       finish_rc;
static unsigned      flush_count;
static unsigned      finalize_count;
static char          policy_context;
static TPMS_POLICY   signing_policy, nested_policy;

TSS2_RC
__wrap_Tss2_PolicyExecute_Finish(TSS2_POLICY_CTX *policy_ctx, ESYS_CONTEXT *esys, ESYS_TR session) {
    (void)esys;
    assert_ptr_equal(policy_ctx, (TSS2_POLICY_CTX *)&policy_context);
    assert_int_equal(session, 0x03000000);
    IFAPI_POLICYUTIL_STACK *frame = active_context->policy.util_current_policy;
    /* Model a nested Secret authorization borrowing the global load context. */
    frame->cb_ctx.load_ctx.auth_object.authorization_state = AUTH_INIT;
    frame->cb_ctx.load_ctx.auth_object.public.handle = 0x80000002;
    frame->cb_ctx.load_ctx.auth_object.policy = &nested_policy;
    frame->cb_ctx.load_ctx.auth_object.rel_path = "P_ECC/HS/SRK/key-2";
    frame->cb_ctx.cb_state = POL_CB_AUTHORIZE_KEY;
    active_context->loadKey = frame->cb_ctx.load_ctx;
    active_context->createPrimary.pkey_object.public.handle = 0x80000003;
    active_context->current_auth_object = &frame->cb_ctx.load_ctx.auth_object;
    return finish_rc;
}

void
__wrap_Tss2_PolicyFinalize(TSS2_POLICY_CTX **policy_ctx) {
    assert_ptr_equal(*policy_ctx, (TSS2_POLICY_CTX *)&policy_context);
    *policy_ctx = NULL;
    finalize_count++;
}

TSS2_RC
__wrap_Esys_FlushContext(ESYS_CONTEXT *esys, ESYS_TR session) {
    (void)esys;
    assert_int_equal(session, 0x03000000);
    flush_count++;
    return TSS2_RC_SUCCESS;
}

static void
check_outer_state(FAPI_CONTEXT *context) {
    assert_int_equal(context->loadKey.auth_object.authorization_state, AUTH_EXEC_POLICY);
    assert_int_equal(context->loadKey.auth_object.public.handle, 0x80000001);
    assert_ptr_equal(context->loadKey.auth_object.policy, &signing_policy);
    assert_string_equal(context->loadKey.auth_object.rel_path, "P_ECC/HS/SRK/signing-key");
    assert_int_equal(context->createPrimary.pkey_object.public.handle, 0x80000004);
    assert_ptr_equal(context->current_auth_object, &context->loadKey.auth_object);
}

static void
test_nested_policy_restores_outer_state(void **state) {
    (void)state;
    const TSS2_RC results[]
        = { TSS2_POLICY_RC_TRY_AGAIN, TSS2_RC_SUCCESS, TSS2_POLICY_RC_BAD_VALUE };
    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
        FAPI_CONTEXT           *context = calloc(1, sizeof(*context));
        IFAPI_POLICYUTIL_STACK *frame = calloc(1, sizeof(*frame));
        assert_non_null(context);
        assert_non_null(frame);
        context->loadKey.auth_object.authorization_state = AUTH_EXEC_POLICY;
        context->loadKey.auth_object.public.handle = 0x80000001;
        context->loadKey.auth_object.policy = &signing_policy;
        context->loadKey.auth_object.rel_path = "P_ECC/HS/SRK/signing-key";
        context->createPrimary.pkey_object.public.handle = 0x80000004;
        context->current_auth_object = &context->loadKey.auth_object;
        context->policy.policyutil_stack = frame;
        frame->state = POLICY_UTIL_EXEC_POLICY;
        frame->session = 0x03000000;
        frame->pol_exec_ctx = (TSS2_POLICY_CTX *)&policy_context;
        active_context = context;
        flush_count = finalize_count = 0;
        finish_rc = results[i];
        ESYS_TR session = frame->session;

        TSS2_RC r = ifapi_policyutil_execute(context, &session);
        check_outer_state(context);
        if (finish_rc == TSS2_POLICY_RC_TRY_AGAIN) {
            assert_int_equal(r, TSS2_FAPI_RC_TRY_AGAIN);
            assert_ptr_equal(context->policy.policyutil_stack, frame);
            assert_int_equal(frame->cb_ctx.cb_state, POL_CB_AUTHORIZE_KEY);
            assert_ptr_equal(frame->cb_ctx.load_ctx.auth_object.policy, &nested_policy);
            assert_int_equal(finalize_count, 0);
            assert_int_equal(flush_count, 0);
            finish_rc = TSS2_RC_SUCCESS;
            r = ifapi_policyutil_execute(context, &session);
            check_outer_state(context);
        }
        assert_int_equal(r,
                         finish_rc == TSS2_RC_SUCCESS ? TSS2_RC_SUCCESS : TSS2_FAPI_RC_BAD_VALUE);
        assert_int_equal(flush_count, finish_rc == TSS2_RC_SUCCESS ? 0 : 1);
        assert_int_equal(finalize_count, 1);
        assert_ptr_equal(context->policy.policyutil_stack, NULL);
        assert_ptr_equal(context->policy.util_current_policy, NULL);
        free(context);
        active_context = NULL;
    }
}

int
main(void) {
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_nested_policy_restores_outer_state) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
