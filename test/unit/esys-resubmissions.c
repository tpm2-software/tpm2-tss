/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_esys.h"

#include "tss2-esys/esys_iutil.h"
#define LOGMODULE tests
#include "util/log.h"

/**
 * This unit test looks into a set of Esys_<cmd>() functions and tests the
 * resubmission behaviour. The ESAPI is expected to resubmit a command for a
 * certain number of times if the TPM return RC_YIELDED. After this number of
 * times, the ESAPI shall not try it any further but return the TPM's error.
 * For all these resubmissions the command must be the same as before.
 * This shall be extended to cover all functions at some point.
 */

#define TCTI_YIELDER_MAGIC 0x5949454c44455200ULL        /* 'YIELDER\0' */
#define TCTI_YIELDER_VERSION 0x1

/* Esys handles for dummy session and key objects which can be used in ESAPI test calls */
#define DMY_TR_HANDLE_SESSION  ESYS_TR_MIN_OBJECT
#define DMY_TR_HANDLE_KEY ESYS_TR_MIN_OBJECT+1

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
     TSS2_RC(*finalize) (TSS2_TCTI_CONTEXT * tctiContext);
     TSS2_RC(*cancel) (TSS2_TCTI_CONTEXT * tctiContext);
     TSS2_RC(*getPollHandles) (TSS2_TCTI_CONTEXT * tctiContext,
                               TSS2_TCTI_POLL_HANDLE * handles,
                               size_t * num_handles);
     TSS2_RC(*setLocality) (TSS2_TCTI_CONTEXT * tctiContext, uint8_t locality);
    uint32_t count;
    uint8_t cmd[4096];
} TSS2_TCTI_CONTEXT_YIELDER;

static TSS2_TCTI_CONTEXT_YIELDER *
tcti_yielder_cast(TSS2_TCTI_CONTEXT * ctx)
{
    TSS2_TCTI_CONTEXT_YIELDER *ctxi = (TSS2_TCTI_CONTEXT_YIELDER *) ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_YIELDER_MAGIC) {
        LOG_ERROR("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}

static TSS2_RC
tcti_yielder_transmit(TSS2_TCTI_CONTEXT * tctiContext,
                      size_t size, const uint8_t * buffer)
{
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tctiContext);

    if (size > sizeof(tcti_yielder->cmd)) {
        LOG_ERROR("Bad size value.");
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    if (tcti_yielder->count != 0)
        assert_memory_equal(&tcti_yielder->cmd[0], buffer, size);

    tcti_yielder->count++;
    memcpy(&tcti_yielder->cmd[0], buffer, size);

    return TSS2_RC_SUCCESS;
}

const uint8_t yielded_response[] = {
    0x80, 0x01,                 /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A,     /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08      /* TPM_RC_YIELDED */
};

static TSS2_RC
tcti_yielder_receive(TSS2_TCTI_CONTEXT * tctiContext,
                     size_t * response_size,
                     uint8_t * response_buffer, int32_t timeout)
{
    *response_size = sizeof(yielded_response);
    if (response_buffer != NULL)
        memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));

    return TSS2_RC_SUCCESS;
}

static void
tcti_yielder_finalize(TSS2_TCTI_CONTEXT * tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_YIELDER));
}

static TSS2_RC
tcti_yielder_initialize(TSS2_TCTI_CONTEXT * tctiContext, size_t * contextSize)
{
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder =
        (TSS2_TCTI_CONTEXT_YIELDER *) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_yielder);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_yielder, 0, sizeof(*tcti_yielder));
    TSS2_TCTI_MAGIC(tctiContext) = TCTI_YIELDER_MAGIC;
    TSS2_TCTI_VERSION(tctiContext) = TCTI_YIELDER_VERSION;
    TSS2_TCTI_TRANSMIT(tctiContext) = tcti_yielder_transmit;
    TSS2_TCTI_RECEIVE(tctiContext) = tcti_yielder_receive;
    TSS2_TCTI_FINALIZE(tctiContext) = tcti_yielder_finalize;
    TSS2_TCTI_CANCEL(tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES(tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY(tctiContext) = NULL;
    tcti_yielder->count = 0;

    return TSS2_RC_SUCCESS;
}

static int
setup(void **state)
{
    TSS2_RC r;
    ESYS_CONTEXT *ectx;
    size_t size = sizeof(TSS2_TCTI_CONTEXT_YIELDER);
    TSS2_TCTI_CONTEXT *tcti = malloc(size);
    ESYS_TR objectHandle;
    RSRC_NODE_T *objectHandleNode = NULL;

    r = tcti_yielder_initialize(tcti, &size);
    if (r)
        return (int)r;
    r = Esys_Initialize(&ectx, tcti, NULL);
    if (r)
        return (int)r;

    /* Create dummy object to enable usage of SAPI prepare functions in the tests */
    objectHandle = DMY_TR_HANDLE_SESSION;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r)
        return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_SESSION_RSRC;
    objectHandleNode->rsrc.handle = TPM2_POLICY_SESSION_FIRST;
    objectHandle = DMY_TR_HANDLE_KEY;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r)
        return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_KEY_RSRC;
    objectHandleNode->rsrc.handle = TPM2_TRANSIENT_FIRST;

    if (r)
        return (int)r;
    *state = (void *)ectx;
    return 0;
}

static int
teardown(void **state)
{
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(ectx, &tcti);
    Esys_Finalize(&ectx);
    free(tcti);
    return 0;
}

static void
test_Startup(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    TPM2_SU startupType = TPM2_SU_CLEAR;
    r = Esys_Startup(esys_context, startupType);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_Shutdown(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    TPM2_SU shutdownType = TPM2_SU_CLEAR;
    r = Esys_Shutdown(esys_context,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, shutdownType);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_SelfTest(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    r = Esys_SelfTest(esys_context,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 0);
    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_IncrementalSelfTest(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    TPML_ALG toTest;
    TPML_ALG *toDoList;
    r = Esys_IncrementalSelfTest(esys_context,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE, &toTest, &toDoList);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_GetTestResult(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    TPM2B_MAX_BUFFER *outData;
    TPM2_RC testResult;
    r = Esys_GetTestResult(esys_context,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE, ESYS_TR_NONE, &outData, &testResult);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_StartAuthSession(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    ESYS_TR tpmKey_handle = ESYS_TR_NONE;
    ESYS_TR bind_handle = ESYS_TR_NONE;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };
    TPM2_SE sessionType = TPM2_SE_HMAC;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMI_ALG_HASH authHash = TPM2_ALG_SHA1;
    ESYS_TR sessionHandle_handle;
    TPM2B_NONCE *nonceTPM;

    r = Esys_StartAuthSession(esys_context,
                              tpmKey_handle,
                              bind_handle,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &nonceCaller,
                              sessionType,
                              &symmetric,
                              authHash, &sessionHandle_handle, &nonceTPM);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_PolicyRestart(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);

    r = Esys_PolicyRestart(esys_context,
                           DMY_TR_HANDLE_SESSION,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

static void
test_Create(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TSS2_TCTI_CONTEXT_YIELDER *tcti_yielder = tcti_yielder_cast(tcti);
    TPM2B_SENSITIVE_CREATE inSensitive = { 0 };
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm =
                     TPM2_ALG_NULL,
                     .keyBits.aes =
                     128,
                     .mode.aes =
                     TPM2_ALG_ECB,
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_ECDSA,
                      .details = {
                          .ecdsa =
                          {.
                           hashAlg
                           =
                           TPM2_ALG_SHA256}},
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}}
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}},
             },
        },
    };
    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };
    TPM2B_PRIVATE *outPrivate;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_Create(esys_context,
                    DMY_TR_HANDLE_KEY,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &inSensitive,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivate,
                    &outPublic, &creationData, &creationHash, &creationTicket);

    assert_int_equal(r, TPM2_RC_YIELDED);
    assert_int_equal(tcti_yielder->count, 5 /* _ESYS_MAX_SUBMISSIONS */ );
}

int
main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_Startup, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Shutdown, setup, teardown),
        cmocka_unit_test_setup_teardown(test_SelfTest, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IncrementalSelfTest, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_GetTestResult, setup, teardown),
        cmocka_unit_test_setup_teardown(test_StartAuthSession, setup, teardown),
        cmocka_unit_test_setup_teardown(test_PolicyRestart, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Create, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
