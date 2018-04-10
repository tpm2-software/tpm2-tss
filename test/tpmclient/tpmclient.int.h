//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#ifndef TPMCLIENT_INT_H
#define TPMCLIENT_INT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "tss2_sys.h"
#include "util/tpm2b.h"

extern TSS2_TCTI_CONTEXT *resMgrTctiContext;

enum TSS2_APP_RC_CODE
{
    APP_RC_PASSED,
    APP_RC_GET_NAME_FAILED,
    APP_RC_CREATE_SESSION_KEY_FAILED,
    APP_RC_SESSION_SLOT_NOT_FOUND,
    APP_RC_BAD_ALGORITHM,
    APP_RC_SYS_CONTEXT_CREATE_FAILED,
    APP_RC_GET_SESSION_STRUCT_FAILED,
    APP_RC_GET_SESSION_ALG_ID_FAILED,
    APP_RC_INIT_SYS_CONTEXT_FAILED,
    APP_RC_TEARDOWN_SYS_CONTEXT_FAILED,
    APP_RC_BAD_LOCALITY
};

/*
 * Definition of TSS2_RC values returned by application level stuff. We use
 * this "level" for errors returned by functions in the integration test
 * harness.
 */
#define TSS2_APP_RC_LAYER         TSS2_RC_LAYER(0x10)
#define TSS2_APP_ERROR(base_rc)   (TSS2_APP_RC_LAYER | base_rc)
#define TSS2_APP_RC_BAD_REFERENCE  TSS2_APP_ERROR (TSS2_BASE_RC_BAD_REFERENCE)

// Add this to application-specific error codes so they don't overlap
// with TSS ones which may be re-used for app level errors.
#define APP_RC_OFFSET 0xf800

// These are app specific error codes, so they have
// APP_RC_OFFSET added.
#define TSS2_APP_RC_PASSED                      (APP_RC_PASSED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_GET_NAME_FAILED             (APP_RC_GET_NAME_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_CREATE_SESSION_KEY_FAILED   (APP_RC_CREATE_SESSION_KEY_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_SESSION_SLOT_NOT_FOUND      (APP_RC_SESSION_SLOT_NOT_FOUND + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_BAD_ALGORITHM               (APP_RC_BAD_ALGORITHM + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_SYS_CONTEXT_CREATE_FAILED   (APP_RC_SYS_CONTEXT_CREATE_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_GET_SESSION_STRUCT_FAILED   (APP_RC_GET_SESSION_STRUCT_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_GET_SESSION_ALG_ID_FAILED   (APP_RC_GET_SESSION_ALG_ID_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED     (APP_RC_INIT_SYS_CONTEXT_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_TEARDOWN_SYS_CONTEXT_FAILED (APP_RC_TEARDOWN_SYS_CONTEXT_FAILED + APP_RC_OFFSET + TSS2_APP_RC_LAYER)
#define TSS2_APP_RC_BAD_LOCALITY                (APP_RC_BAD_LOCALITY + APP_RC_OFFSET + TSS2_APP_RC_LAYER)

#define TPM2_HT_NO_HANDLE 0xfc000000
#define TPM2_RC_NO_RESPONSE 0xffffffff

#define MAX_NUM_SESSIONS MAX_ACTIVE_SESSIONS

#define APPLICATION_ERROR( errCode ) \
    ( TSS2_APP_RC_LAYER + errCode )

#define APPLICATION_HMAC_ERROR(i) \
    ( TSS2_APP_RC_LAYER + TPM2_RC_S + TPM2_RC_AUTH_FAIL + ( (i ) << 8 ) )

typedef struct {
    // Inputs to StartAuthSession; these need to be saved
    // so that HMACs can be calculated.
    TPMI_DH_OBJECT tpmKey;
    TPMI_DH_ENTITY bind;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPM2B_MAX_BUFFER salt;
    TPM2_SE sessionType;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;

    // Outputs from StartAuthSession; these also need
    // to be saved for calculating HMACs and
    // other session related functions.
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonceTPM;

    // Internal state for the session
    TPM2B_DIGEST sessionKey;
    TPM2B_DIGEST authValueBind;     // authValue of bind object
    TPM2B_NONCE nonceNewer;
    TPM2B_NONCE nonceOlder;
    TPM2B_NONCE nonceTpmDecrypt;
    TPM2B_NONCE nonceTpmEncrypt;
    TPM2B_NAME name;                // Name of the object the session handle
                                    // points to.  Used for computing HMAC for
                                    // any HMAC sessions present.
                                    //
    void *hmacPtr;                  // Pointer to HMAC field in the marshalled
                                    // data stream for the session.
                                    // This allows the function to calculate
                                    // and fill in the HMAC after marshalling
                                    // of all the inputs.
                                    //
                                    // This is only used if the session is an
                                    // HMAC session.
                                    //
    UINT8 nvNameChanged;            // Used for some special case code
                                    // dealing with the NV written state.
} SESSION;

//
// Structure used to maintain entity data.  Right now it just
// consists of handles/authValue pairs.
//
typedef struct{
    TPM2_HANDLE entityHandle;
    TPM2B_AUTH entityAuth;
    UINT8 nvNameChanged;
} ENTITY;

void InitEntities();
TSS2_RC AddEntity( TPM2_HANDLE entityHandle, TPM2B_AUTH *auth );
TSS2_RC DeleteEntity( TPM2_HANDLE entityHandle );
TSS2_RC GetEntityAuth( TPM2_HANDLE entityHandle, TPM2B_AUTH *auth );
TSS2_RC GetEntity( TPM2_HANDLE entityHandle, ENTITY **entity );
TSS2_RC GetSessionStruct( TPMI_SH_AUTH_SESSION authHandle, SESSION **pSession );
TSS2_RC GetSessionAlgId( TPMI_SH_AUTH_SESSION authHandle, TPMI_ALG_HASH *sessionAlgId );
TSS2_RC EndAuthSession( SESSION *session );
TSS2_RC ComputeCommandHmacs(
        TSS2_SYS_CONTEXT *sysContext,
        TPM2_HANDLE handle1,
        TPM2_HANDLE handle2,
        TSS2L_SYS_AUTH_COMMAND *pSessionsData);

TSS2_RC StartAuthSessionWithParams( SESSION **session, TPMI_DH_OBJECT tpmKey, TPM2B_MAX_BUFFER *salt,
    TPMI_DH_ENTITY bind, TPM2B_AUTH *bindAuth, TPM2B_NONCE *nonceCaller, TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM2_SE sessionType, TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH algId, TSS2_TCTI_CONTEXT *tctiContext );

UINT32 TpmComputeSessionHmac(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_AUTH_COMMAND *pSessionDataIn,
    TPM2_HANDLE entityHandle,
    bool command,
    TPM2_HANDLE handle1,
    TPM2_HANDLE handle2,
    TPMA_SESSION sessionAttributes,
    TPM2B_DIGEST *result);

TSS2_RC CheckResponseHMACs(
        TSS2_SYS_CONTEXT *sysContext,
        TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn,
        TPM2_HANDLE handle1,
        TPM2_HANDLE handle2,
        TSS2L_SYS_AUTH_RESPONSE *pSessionsDataOut);

TSS2_RC EncryptCommandParam( SESSION *session, TPM2B_MAX_BUFFER *encryptedData, TPM2B_MAX_BUFFER *clearData, TPM2B_AUTH *authValue );

TSS2_RC DecryptResponseParam( SESSION *session, TPM2B_MAX_BUFFER *clearData, TPM2B_MAX_BUFFER *encryptedData, TPM2B_AUTH *authValue );

TSS2_RC KDFa( TPMI_ALG_HASH hashAlg, TPM2B *key, char *label, TPM2B *contextU, TPM2B *contextV,
    UINT16 bits, TPM2B_MAX_BUFFER *resultKey );

void RollNonces( SESSION *session, TPM2B_NONCE *newNonce  );

#define INIT_SIMPLE_TPM2B_SIZE(type) (type).size = sizeof(type) - 2;

#define YES 1
#define NO 0

#endif
