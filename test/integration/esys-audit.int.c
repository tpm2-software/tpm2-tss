/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
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
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the ESAPI audit commands.
 * First a key for signing the audit digest is computed.
 * A audit session is started, and for the command GetCapability the
 * command audit digest and the session audit digest is computed.
 * (Esys_GetCommandAuditDigest, Esys_GetSessionAuditDigest). In the
 * last test the audit hash alg is changed with Esys_SetCommandCodeAuditStatus.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    /* Compute a signing key */
    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0},
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
            .size = 0,
            .publicArea = {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA1,
                .objectAttributes = (
                    TPMA_OBJECT_USERWITHAUTH |
                    TPMA_OBJECT_RESTRICTED |
                    TPMA_OBJECT_SIGN_ENCRYPT |
                    TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT |
                    TPMA_OBJECT_SENSITIVEDATAORIGIN
                    ),
                .authPolicy = {
                        .size = 0,
                    },
                .parameters.rsaDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits.aes = 128,
                        .mode.aes = TPM2_ALG_ECB,
                        },
                    .scheme = {
                         .scheme = TPM2_ALG_RSASSA,
                         .details = { .rsassa = { .hashAlg = TPM2_ALG_SHA1 }},

                    },
                    .keyBits = 2048,
                    .exponent = 0,
                },
                .unique.rsa = {
                        .size = 0,
                        .buffer = {},
                    },
            },
        };

    TPM2B_AUTH authValue = {
                .size = 0,
                .buffer = {}
    };

    TPM2B_DATA outsideInfo = {
            .size = 0,
            .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    ESYS_TR signHandle;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                           &inPublic, &outsideInfo, &creationPCR,
                           &signHandle, &outPublic, &creationData,
                           &creationHash, &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    /* Start a audit session */
    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION |
                                     TPMA_SESSION_AUDIT;
    TPM2_SE sessionType = TPM2_SE_HMAC;
    TPMI_ALG_HASH authHash = TPM2_ALG_SHA256;
    TPM2B_NONCE *nonceTpm;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL };
    ESYS_TR session;

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              sessionType, &symmetric, authHash, &session,
                              &nonceTpm);

    goto_if_error(r, "Error Esys_StartAuthSessiony", error);
    r = Esys_TRSess_SetAttributes(esys_context, session, sessionAttributes,
                                  0xff);
    goto_if_error(r, "Error Esys_TRSess_SetAttributes", error);

    /* Execute one command to be audited */
    TPM2_CAP capability = TPM2_CAP_TPM_PROPERTIES;
    UINT32 property = TPM2_PT_LOCKOUT_COUNTER;
    UINT32 propertyCount = 1;
    TPMS_CAPABILITY_DATA *capabilityData;
    TPMI_YES_NO moreData;

    r = Esys_GetCapability(esys_context,
                           session, ESYS_TR_NONE, ESYS_TR_NONE,
                           capability, property, propertyCount,
                           &moreData, &capabilityData);

    goto_if_error(r, "Error esys get capability", error);

    ESYS_TR privacyHandle = ESYS_TR_RH_ENDORSEMENT;
    TPM2B_DATA qualifyingData = {0};
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPM2B_ATTEST *auditInfo;
    TPMT_SIGNATURE *signature;

    /* Test the audit commands */
    r = Esys_GetCommandAuditDigest(
        esys_context,
        privacyHandle,
        signHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        &qualifyingData,
        &inScheme,
        &auditInfo,
        &signature);
    goto_if_error(r, "Error: GetCommandAuditDigest", error);

    r = Esys_GetSessionAuditDigest(
        esys_context,
        privacyHandle,
        signHandle,
        session,
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        &qualifyingData,
        &inScheme,
        &auditInfo,
        &signature);
    goto_if_error(r, "Error: GetSessionAuditDigest", error);

    TPMI_ALG_HASH auditAlg = TPM2_ALG_SHA1;
    TPML_CC clearList = {0};
    TPML_CC setList = {0};

    r = Esys_SetCommandCodeAuditStatus(
        esys_context,
        ESYS_TR_RH_PLATFORM,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        auditAlg,
        &setList,
        &clearList);
    goto_if_error(r, "Error: SetCommandCodeAuditStatus", error);

    r = Esys_FlushContext(esys_context, signHandle);
    goto_if_error(r, "Error: FlushContext", error);

    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error during FlushContext", error);

    return 0;

 error:
    return 1;
}
