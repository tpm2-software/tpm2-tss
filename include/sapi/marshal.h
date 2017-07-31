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

#ifndef MARSHAL_H
#define MARSHAL_H

#include <stdlib.h>
#include <sapi/tpm20.h>

#define TSS2_TYPES_RC_LAYER TSS2_ERROR_LEVEL(14)
#define TSS2_TYPES_RC_BAD_REFERENCE \
    ((TSS2_RC)(TSS2_TYPES_RC_LAYER | TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_TYPES_RC_INSUFFICIENT_BUFFER \
    ((TSS2_RC)(TSS2_TYPES_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_BUFFER))

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC
BYTE_Marshal (
    BYTE           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
BYTE_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    BYTE           *dest
    );

TSS2_RC
INT8_Marshal (
    INT8            src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT8_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT8           *dest
    );

TSS2_RC
INT16_Marshal (
    INT16           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT16_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT16          *dest
    );

TSS2_RC
INT32_Marshal (
    INT32           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT32_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT32          *dest
    );

TSS2_RC
INT64_Marshal (
    INT64           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT64_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT64          *dest
    );

TSS2_RC
UINT8_Marshal (
    UINT8           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT8_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT8          *dest
    );

TSS2_RC
UINT16_Marshal (
    UINT16          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT16_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT16         *dest
    );

TSS2_RC
UINT32_Marshal (
    UINT32          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT32_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT32         *dest
    );

TSS2_RC
UINT64_Marshal (
    UINT64          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT64_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT64         *dest
    );

TSS2_RC
TPM_CC_Marshal (
    TPM_CC          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
TPM_CC_Unmarshal (
    uint8_t const   buffer [],
    size_t          buffer_size,
    size_t         *offset,
    TPM_CC         *dest
    );

TSS2_RC
TPM_ST_Marshal (
    TPM_ST          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
TPM_ST_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM_ST         *dest
    );

TSS2_RC
TPMA_ALGORITHM_Marshal (
    TPMA_ALGORITHM  src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t          *offset);

TSS2_RC
TPMA_ALGORITHM_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_ALGORITHM *dest);

TSS2_RC
TPMA_CC_Marshal (
    TPMA_CC         src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_CC_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_CC        *dest);

TSS2_RC
TPMA_LOCALITY_Marshal (
    TPMA_LOCALITY   src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_LOCALITY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_LOCALITY  *dest);
TSS2_RC

TPMA_NV_Marshal (
    TPMA_NV         src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_NV_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_NV        *dest);

TSS2_RC
TPMA_OBJECT_Marshal (
    TPMA_OBJECT     src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_OBJECT_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_OBJECT    *dest);

TSS2_RC
TPMA_PERMANENT_Marshal (
    TPMA_PERMANENT  src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_PERMANENT_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_PERMANENT *dest);

TSS2_RC
TPMA_SESSION_Marshal (
    TPMA_SESSION    src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_SESSION_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_SESSION   *dest);

TSS2_RC
TPMA_STARTUP_CLEAR_Marshal (
    TPMA_STARTUP_CLEAR src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_STARTUP_CLEAR_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_STARTUP_CLEAR *dest);

TSS2_RC
TPM2B_DIGEST_Marshal (
    TPM2B_DIGEST const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_DIGEST_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_DIGEST   *dest);

TSS2_RC
TPM2B_NAME_Marshal (
    TPM2B_NAME const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_NAME_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_NAME     *dest);

TSS2_RC
TPM2B_MAX_NV_BUFFER_Marshal (
    TPM2B_MAX_NV_BUFFER const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_MAX_NV_BUFFER_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_MAX_NV_BUFFER *dest);

TSS2_RC
TPM2B_SENSITIVE_DATA_Marshal (
    TPM2B_SENSITIVE_DATA const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_SENSITIVE_DATA_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_SENSITIVE_DATA *dest);

TSS2_RC
TPM2B_ECC_PARAMETER_Marshal (
    TPM2B_ECC_PARAMETER const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_ECC_PARAMETER_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_ECC_PARAMETER *dest);

TSS2_RC
TPM2B_PUBLIC_KEY_RSA_Marshal (
    TPM2B_PUBLIC_KEY_RSA const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_PUBLIC_KEY_RSA_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_PUBLIC_KEY_RSA *dest);

TSS2_RC
TPM2B_PRIVATE_KEY_RSA_Marshal (
    TPM2B_PRIVATE_KEY_RSA const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_PRIVATE_KEY_RSA_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_PRIVATE_KEY_RSA *dest);

TSS2_RC
TPM2B_CONTEXT_SENSITIVE_Marshal (
    TPM2B_CONTEXT_SENSITIVE const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_CONTEXT_SENSITIVE_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_CONTEXT_SENSITIVE *dest);

TSS2_RC
TPM2B_CONTEXT_DATA_Marshal (
    TPM2B_CONTEXT_DATA const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_CONTEXT_DATA_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_CONTEXT_DATA *dest);

TSS2_RC
TPM2B_DATA_Marshal (
    TPM2B_DATA      const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_DATA_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_DATA     *dest);

TSS2_RC
TPM2B_SYM_KEY_Marshal (
    TPM2B_SYM_KEY   const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPM2B_SYM_KEY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_SYM_KEY  *dest);

TSS2_RC
TPMS_CONTEXT_Marshal (
    TPMS_CONTEXT    const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_CONTEXT_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_CONTEXT   *dest);

TSS2_RC
TPMS_TIME_INFO_Marshal (
    TPMS_TIME_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_TIME_INFO_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_TIME_INFO *dest);

TSS2_RC
TPMS_ECC_POINT_Marshal (
    TPMS_ECC_POINT  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_ECC_POINT_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_ECC_POINT *dest);

TSS2_RC
TPMS_NV_PUBLIC_Marshal (
    TPMS_NV_PUBLIC  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_NV_PUBLIC_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_NV_PUBLIC *dest);

TSS2_RC
TPMS_ALG_PROPERTY_Marshal (
    TPMS_ALG_PROPERTY  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_ALG_PROPERTY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_ALG_PROPERTY *dest);

TSS2_RC
TPMS_ALGORITHM_DESCRIPTION_Marshal (
    TPMS_ALGORITHM_DESCRIPTION  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_ALGORITHM_DESCRIPTION_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_ALGORITHM_DESCRIPTION *dest);

TSS2_RC
TPMS_TAGGED_PROPERTY_Marshal (
    TPMS_TAGGED_PROPERTY  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_TAGGED_PROPERTY_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_TAGGED_PROPERTY *dest);

TSS2_RC
TPMS_CLOCK_INFO_Marshal (
    TPMS_CLOCK_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_CLOCK_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_CLOCK_INFO *dest);

TSS2_RC
TPMS_TIME_ATTEST_INFO_Marshal (
    TPMS_TIME_ATTEST_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_TIME_ATTEST_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_TIME_ATTEST_INFO *dest);

TSS2_RC
TPMS_CERTIFY_INFO_Marshal (
    TPMS_CERTIFY_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_CERTIFY_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_CERTIFY_INFO *dest);

TSS2_RC
TPMS_COMMAND_AUDIT_INFO_Marshal (
    TPMS_COMMAND_AUDIT_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_COMMAND_AUDIT_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_COMMAND_AUDIT_INFO *dest);

TSS2_RC
TPMS_SESSION_AUDIT_INFO_Marshal (
    TPMS_SESSION_AUDIT_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SESSION_AUDIT_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SESSION_AUDIT_INFO *dest);

TSS2_RC
TPMS_CREATION_INFO_Marshal (
    TPMS_CREATION_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_CREATION_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_CREATION_INFO *dest);

TSS2_RC
TPMS_NV_CERTIFY_INFO_Marshal (
    TPMS_NV_CERTIFY_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_NV_CERTIFY_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_NV_CERTIFY_INFO *dest);

TSS2_RC
TPMS_AUTH_COMMAND_Marshal (
    TPMS_AUTH_COMMAND  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_AUTH_COMMAND_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_AUTH_COMMAND *dest);

TSS2_RC
TPMS_AUTH_RESPONSE_Marshal (
    TPMS_AUTH_RESPONSE  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_AUTH_RESPONSE_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_AUTH_RESPONSE *dest);

TSS2_RC
TPMS_SENSITIVE_CREATE_Marshal (
    TPMS_SENSITIVE_CREATE  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SENSITIVE_CREATE_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SENSITIVE_CREATE *dest);

TSS2_RC
TPMS_SCHEME_HASH_Marshal (
    TPMS_SCHEME_HASH  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SCHEME_HASH_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SCHEME_HASH *dest);

TSS2_RC
TPMS_SCHEME_ECDAA_Marshal (
    TPMS_SCHEME_ECDAA  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SCHEME_ECDAA_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SCHEME_ECDAA *dest);

TSS2_RC
TPMS_SCHEME_XOR_Marshal (
    TPMS_SCHEME_XOR  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SCHEME_XOR_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SCHEME_XOR *dest);

TSS2_RC
TPMS_SIGNATURE_RSA_Marshal (
    TPMS_SIGNATURE_RSA  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SIGNATURE_RSA_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SIGNATURE_RSA *dest);

TSS2_RC
TPMS_SIGNATURE_ECC_Marshal (
    TPMS_SIGNATURE_ECC  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_SIGNATURE_ECC_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_SIGNATURE_ECC *dest);

TSS2_RC
TPMS_NV_PIN_COUNTER_PARAMETERS_Marshal (
    TPMS_NV_PIN_COUNTER_PARAMETERS  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_NV_PIN_COUNTER_PARAMETERS_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_NV_PIN_COUNTER_PARAMETERS *dest);

TSS2_RC
TPMS_CONTEXT_DATA_Marshal (
    TPMS_CONTEXT_DATA  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_CONTEXT_DATA_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_CONTEXT_DATA *dest);

TSS2_RC
TPMS_PCR_SELECT_Marshal (
    TPMS_PCR_SELECT  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_PCR_SELECT_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_PCR_SELECT *dest);

TSS2_RC
TPMS_PCR_SELECTION_Marshal (
    TPMS_PCR_SELECTION  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_PCR_SELECTION_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_PCR_SELECTION *dest);

TSS2_RC
TPMS_TAGGED_PCR_SELECT_Marshal (
    TPMS_TAGGED_PCR_SELECT  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_TAGGED_PCR_SELECT_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_TAGGED_PCR_SELECT *dest);

TSS2_RC
TPMS_QUOTE_INFO_Marshal (
    TPMS_QUOTE_INFO  const *src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMS_QUOTE_INFO_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMS_QUOTE_INFO *dest);

TSS2_RC
TPML_CC_Marshal (
    TPML_CC const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_CC_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_CC        *dest);

TSS2_RC
TPML_CCA_Marshal (
    TPML_CCA const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_CCA_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_CCA       *dest);

TSS2_RC
TPML_ALG_Marshal (
    TPML_ALG const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_ALG_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_ALG       *dest);

TSS2_RC
TPML_HANDLE_Marshal (
    TPML_HANDLE const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_HANDLE_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_HANDLE    *dest);

TSS2_RC
TPML_DIGEST_Marshal (
    TPML_DIGEST const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_DIGEST_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_DIGEST    *dest);

TSS2_RC
TPML_DIGEST_VALUES_Marshal (
    TPML_DIGEST_VALUES const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_DIGEST_VALUES_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_DIGEST_VALUES *dest);

TSS2_RC
TPML_PCR_SELECTION_Marshal (
    TPML_PCR_SELECTION const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_PCR_SELECTION_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_PCR_SELECTION *dest);

TSS2_RC
TPML_ALG_PROPERTY_Marshal (
    TPML_ALG_PROPERTY const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_ALG_PROPERTY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_ALG_PROPERTY *dest);

TSS2_RC
TPML_ECC_CURVE_Marshal (
    TPML_ECC_CURVE const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_ECC_CURVE_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_ECC_CURVE *dest);

TSS2_RC
TPML_TAGGED_PCR_PROPERTY_Marshal (
    TPML_TAGGED_PCR_PROPERTY const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_TAGGED_PCR_PROPERTY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_TAGGED_PCR_PROPERTY *dest);

TSS2_RC
TPML_PCR_SELECTION_Marshal (
    TPML_PCR_SELECTION const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_PCR_SELECTION_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_PCR_SELECTION *dest);

TSS2_RC
TPML_TAGGED_TPM_PROPERTY_Marshal (
    TPML_TAGGED_TPM_PROPERTY const *src,
    uint8_t      buffer[],
    size_t       buffer_size,
    size_t      *offset);

TSS2_RC
TPML_TAGGED_TPM_PROPERTY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPML_TAGGED_TPM_PROPERTY *dest);

TSS2_RC
TPMU_HA_Marshal (
    TPMU_HA const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_HA_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_HA       *dest);

TSS2_RC
TPMU_CAPABILITIES_Marshal (
    TPMU_CAPABILITIES const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_CAPABILITIES_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_CAPABILITIES *dest);

TSS2_RC
TPMU_ATTEST_Marshal (
    TPMU_ATTEST const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_ATTEST_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_ATTEST *dest);

TSS2_RC
TPMU_SYM_KEY_BITS_Marshal (
    TPMU_SYM_KEY_BITS const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_SYM_KEY_BITS_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_SYM_KEY_BITS *dest);

TSS2_RC
TPMU_SYM_MODE_Marshal (
    TPMU_SYM_MODE const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_SYM_MODE_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_SYM_MODE *dest);

TSS2_RC
TPMU_SIG_SCHEME_Marshal (
    TPMU_SIG_SCHEME const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_SIG_SCHEME_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_SIG_SCHEME *dest);

TSS2_RC
TPMU_KDF_SCHEME_Marshal (
    TPMU_KDF_SCHEME const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_KDF_SCHEME_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_KDF_SCHEME *dest);

TSS2_RC
TPMU_ASYM_SCHEME_Marshal (
    TPMU_ASYM_SCHEME const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_ASYM_SCHEME_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_ASYM_SCHEME *dest);

TSS2_RC
TPMU_SCHEME_KEYEDHASH_Marshal (
    TPMU_SCHEME_KEYEDHASH const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_SCHEME_KEYEDHASH_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_SCHEME_KEYEDHASH *dest);

TSS2_RC
TPMU_SIGNATURE_Marshal (
    TPMU_SIGNATURE const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_SIGNATURE_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_SIGNATURE *dest);

TSS2_RC
TPMU_SENSITIVE_COMPOSITE_Marshal (
    TPMU_SENSITIVE_COMPOSITE const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_SENSITIVE_COMPOSITE_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_SENSITIVE_COMPOSITE *dest);

TSS2_RC
TPMU_ENCRYPTED_SECRET_Marshal (
    TPMU_ENCRYPTED_SECRET const *src,
    uint32_t       selector_value,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

TSS2_RC
TPMU_ENCRYPTED_SECRET_Unmarshal (
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    uint32_t       selector_value,
    TPMU_ENCRYPTED_SECRET *dest);

#ifdef __cplusplus
}
#endif

#endif /* MARSHAL_H */
