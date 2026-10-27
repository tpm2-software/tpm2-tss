/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026
 * All rights reserved.
 *
 * sys-execute fuzz target: drive Tss2_Sys_Execute against the fuzzing
 * TCTI so that the fuzzer-controlled buffer is parsed as a TPM2
 * response (the hostile/compromised TPM threat model the fuzzing TCTI
 * was built for), then exercise a selection of *_Complete response
 * parsers (TPMS_ATTEST, TPMT_SIGNATURE, TPMS_CAPABILITY_DATA,
 * TPMT_PUBLIC, ...) on the same fuzzed response bytes.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define LOGMODULE test
#include "tcti/tcti-fuzzing.h"
#include "tss2_tcti_fuzzing.h"
#include "test.h"
#include "test-common.h"
#include "tss2-sys/sysapi_util.h"
#include "tss2_sys.h"
#include "tss2_tcti.h"
#include "util/log.h"

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    TSS2_TCTI_CONTEXT         *tcti_ctx = NULL;
    TSS2_ABI_VERSION          abi_version = TEST_ABI_VERSION;
    TSS2_TCTI_FUZZING_CONTEXT *tcti_fuzzing = NULL;
    TSS2_SYS_CONTEXT          *sys_ctx = NULL;
    TSS2_SYS_CONTEXT_BLOB     *ctx = NULL;
    TSS2_RC                    rc;
    size_t                     tcti_size = 0;
    size_t                     sys_size;

    /* Response parsers (out parameters). */
    TPM2B_PRIVATE             outPrivate = { 0 };
    TPM2B_PUBLIC              outPublic = { 0 };
    TPM2B_CREATION_DATA       creationData = { 0 };
    TPM2B_DIGEST              creationHash = { 0 };
    TPMT_TK_CREATION          creationTicket = { 0 };
    TPM2B_NAME                name = { 0 };
    TPM2B_NAME                qualifiedName = { 0 };
    TPM2B_NAME                nvName = { 0 };
    TPM2B_NV_PUBLIC           nvPublic = { 0 };
    TPM2B_ATTEST              certifyInfo = { 0 };
    TPMT_SIGNATURE            signature = { 0 };
    TPMT_TK_VERIFIED          validation = { 0 };
    TPMI_YES_NO               moreData = 0;
    TPMS_CAPABILITY_DATA      capabilityData = { 0 };
    TPMI_SH_AUTH_SESSION      sessionHandle = 0;
    TPM2B_NONCE               nonceTPM = { 0 };
    TPM2B_ECC_POINT           eccK = { 0 };
    TPM2B_ECC_POINT           eccL = { 0 };
    TPM2B_ECC_POINT           eccE = { 0 };
    TPM2B_MAX_NV_BUFFER       nvBuffer = { 0 };
    UINT16                    counter = 0;
    TPMS_ALGORITHM_DETAIL_ECC eccParameters = { 0 };
    TPMS_CONTEXT              context = { 0 };
    TPMS_TIME_INFO            currentTime = { 0 };
    TPM2B_TIMEOUT             timeout = { 0 };
    TPMT_TK_AUTH              policyTicket = { 0 };
    TPML_ALG                  toDoList = { 0 };
    TPM2B_MAX_BUFFER          maxBuffer = { 0 };
    TPM2_RC                   testResult = 0;
    TPM2B_IV                  ivOut = { 0 };
    TPM2B_DIGEST              digestOut = { 0 };
    TPMT_TK_HASHCHECK         hashcheck = { 0 };
    UINT32                    pcrUpdateCounter = 0;
    TPML_PCR_SELECTION        pcrSelectionOut = { 0 };
    TPML_DIGEST               pcrValues = { 0 };
    TPML_DIGEST_VALUES        digestValues = { 0 };
    TPMT_HA                   nextDigest = { 0 };
    TPMT_HA                   firstDigest = { 0 };
    TPM2B_DATA                encryptionKeyOut = { 0 };
    TPM2B_ENCRYPTED_SECRET    outSymSeed = { 0 };
    TPML_AC_CAPABILITIES      acCapabilities = { 0 };
    TPMS_AC_OUTPUT            acDataOut = { 0 };
    TPM2B_SENSITIVE_DATA      sensitiveData = { 0 };

    /* Set up the fuzzing TCTI directly (no TCTI loader, no environment). */
    rc = Tss2_Tcti_Fuzzing_Init(NULL, &tcti_size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        return 0;
    }
    tcti_ctx = calloc(1, tcti_size);
    if (tcti_ctx == NULL) {
        return 0;
    }
    rc = Tss2_Tcti_Fuzzing_Init(tcti_ctx, &tcti_size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        free(tcti_ctx);
        return 0;
    }

    sys_size = Tss2_Sys_GetContextSize(0);
    sys_ctx = calloc(1, sys_size);
    if (sys_ctx == NULL) {
        free(tcti_ctx);
        return 0;
    }
    rc = Tss2_Sys_Initialize(sys_ctx, sys_size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        free(sys_ctx);
        free(tcti_ctx);
        return 0;
    }
    ctx = syscontext_cast(sys_ctx);
    if (ctx == NULL) {
        goto out;
    }

    /*
     * The fuzzing TCTI receive callback memcpys the whole fuzz buffer into
     * the response buffer with no capacity check; clamp to the context's
     * buffer capacity to stay within bounds.
     */
    if (Size > ctx->maxCmdSize) {
        Size = ctx->maxCmdSize;
    }

    tcti_fuzzing = tcti_fuzzing_context_cast(tcti_ctx);
    tcti_fuzzing->data = Data;
    tcti_fuzzing->size = Size;

    /* Prepare any command, then Execute: the fuzz data becomes the TPM2
     * response and the response header (tag, responseSize, responseCode)
     * gets parsed and validated. */
    (void)Tss2_Sys_GetRandom_Prepare(sys_ctx, 32);
    (void)Tss2_Sys_Execute(sys_ctx);

    /* Exercise response body parsers on the (fuzzed) response. Each
     * Complete call re-parses independently from the response parameter
     * area; return codes are expected to be errors and are ignored. */
    (void)Tss2_Sys_Create_Complete(sys_ctx, &outPrivate, &outPublic,
                                   &creationData, &creationHash,
                                   &creationTicket);
    (void)Tss2_Sys_CreatePrimary_Complete(sys_ctx, &sessionHandle,
                                          &outPublic, &creationData,
                                          &creationHash, &creationTicket,
                                          &name);
    (void)Tss2_Sys_CreateLoaded_Complete(sys_ctx, &sessionHandle,
                                         &outPrivate, &outPublic, &name);
    (void)Tss2_Sys_ReadPublic_Complete(sys_ctx, &outPublic, &name,
                                       &qualifiedName);
    (void)Tss2_Sys_Unseal_Complete(sys_ctx, &sensitiveData);
    (void)Tss2_Sys_GetRandom_Complete(sys_ctx, &digestOut);
    (void)Tss2_Sys_NV_Read_Complete(sys_ctx, &nvBuffer);
    (void)Tss2_Sys_NV_ReadPublic_Complete(sys_ctx, &nvPublic, &nvName);
    (void)Tss2_Sys_Certify_Complete(sys_ctx, &certifyInfo, &signature);
    (void)Tss2_Sys_NV_Certify_Complete(sys_ctx, &certifyInfo, &signature);
    (void)Tss2_Sys_Quote_Complete(sys_ctx, &certifyInfo, &signature);
    (void)Tss2_Sys_GetTime_Complete(sys_ctx, &certifyInfo, &signature);
    (void)Tss2_Sys_Sign_Complete(sys_ctx, &signature);
    (void)Tss2_Sys_VerifySignature_Complete(sys_ctx, &validation);
    (void)Tss2_Sys_GetCapability_Complete(sys_ctx, &moreData,
                                          &capabilityData);
    (void)Tss2_Sys_StartAuthSession_Complete(sys_ctx, &sessionHandle,
                                             &nonceTPM);
    (void)Tss2_Sys_Commit_Complete(sys_ctx, &eccK, &eccL, &eccE, &counter);
    (void)Tss2_Sys_ECDH_KeyGen_Complete(sys_ctx, &eccK, &eccL);
    (void)Tss2_Sys_ECC_Parameters_Complete(sys_ctx, &eccParameters);
    (void)Tss2_Sys_ContextSave_Complete(sys_ctx, &context);
    (void)Tss2_Sys_ReadClock_Complete(sys_ctx, &currentTime);
    (void)Tss2_Sys_PolicySigned_Complete(sys_ctx, &timeout, &policyTicket);
    (void)Tss2_Sys_IncrementalSelfTest_Complete(sys_ctx, &toDoList);
    (void)Tss2_Sys_GetTestResult_Complete(sys_ctx, &maxBuffer, &testResult);
    (void)Tss2_Sys_EncryptDecrypt2_Complete(sys_ctx, &maxBuffer, &ivOut);
    (void)Tss2_Sys_Hash_Complete(sys_ctx, &digestOut, &hashcheck);
    (void)Tss2_Sys_SequenceComplete_Complete(sys_ctx, &digestOut,
                                             &hashcheck);
    (void)Tss2_Sys_PCR_Read_Complete(sys_ctx, &pcrUpdateCounter,
                                     &pcrSelectionOut, &pcrValues);
    (void)Tss2_Sys_EventSequenceComplete_Complete(sys_ctx, &digestValues);
    (void)Tss2_Sys_FieldUpgradeData_Complete(sys_ctx, &nextDigest,
                                             &firstDigest);
    (void)Tss2_Sys_Duplicate_Complete(sys_ctx, &encryptionKeyOut,
                                      &outPrivate, &outSymSeed);
    (void)Tss2_Sys_AC_GetCapability_Complete(sys_ctx, &moreData,
                                             &acCapabilities);
    (void)Tss2_Sys_AC_Send_Complete(sys_ctx, &acDataOut);

out:
    Tss2_Sys_Finalize(sys_ctx);
    free(sys_ctx);
    free(tcti_ctx);

    return 0; // Non-zero return values are reserved for future use.
}
