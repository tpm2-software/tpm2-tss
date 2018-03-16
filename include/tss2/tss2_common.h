/***********************************************************************;
 * Copyright (c) 2015-2018, Intel Corporation
 *
 * Copyright 2015, Andreas Fuchs @ Fraunhofer SIT
 *
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
 ***********************************************************************/

#ifndef TSS2_COMMON_H
#define TSS2_COMMON_H
#define TSS2_API_VERSION_1_2_1_108

#include <stdint.h>
/*
 * Type definitions
 */
typedef uint8_t     UINT8;
typedef uint8_t     BYTE;
typedef int8_t      INT8;
typedef int         BOOL;
typedef uint16_t    UINT16;
typedef int16_t     INT16;
typedef uint32_t    UINT32;
typedef int32_t     INT32;
typedef uint64_t    UINT64;
typedef int64_t     INT64;

/*
 * ABI runtime negotiation definitions
 */
typedef struct {
    uint32_t tssCreator;
    uint32_t tssFamily;
    uint32_t tssLevel;
    uint32_t tssVersion;
} TSS2_ABI_VERSION;

#define TSS2_ABI_VERSION_CURRENT {1, 2, 1, 108}

/*
 * Return Codes
 */
/* The return type for all TSS2 functions */
typedef uint32_t TSS2_RC;

/* For return values other than SUCCESS, the second most significant
 * byte of the return value is a layer code indicating the software
 * layer that generated the error.
 */
#define TSS2_RC_LAYER_SHIFT      (16)
#define TSS2_RC_LAYER(level)     ((TSS2_RC)level << TSS2_RC_LAYER_SHIFT)
#define TSS2_RC_LAYER_MASK       TSS2_RC_LAYER(0xff)

/* These layer codes are reserved for software layers defined in the TCG
 * specifications.
 */
#define TSS2_TPM_RC_LAYER             TSS2_RC_LAYER(0)
#define TSS2_FEATURE_RC_LAYER         TSS2_RC_LAYER(6)
#define TSS2_ESAPI_RC_LAYER           TSS2_RC_LAYER(7)
#define TSS2_SYS_RC_LAYER             TSS2_RC_LAYER(8)
#define TSS2_MU_RC_LAYER              TSS2_RC_LAYER(9)
#define TSS2_TCTI_RC_LAYER            TSS2_RC_LAYER(10)
#define TSS2_RESMGR_RC_LAYER          TSS2_RC_LAYER(11)
#define TSS2_RESMGR_TPM_RC_LAYER      TSS2_RC_LAYER(12)
#define TSS2_DRIVER_RC_LAYER          TSS2_RC_LAYER(13)

/* Base return codes.
 * These base codes indicate the error that occurred. They are
 * logical-ORed with a layer code to produce the TSS2 return value.
 */
#define TSS2_BASE_RC_GENERAL_FAILURE            1U /* Catch all for all errors not otherwise specifed */
#define TSS2_BASE_RC_NOT_IMPLEMENTED            2U /* If called functionality isn't implemented */
#define TSS2_BASE_RC_BAD_CONTEXT                3U /* A context structure is bad */
#define TSS2_BASE_RC_ABI_MISMATCH               4U /* Passed in ABI version doesn't match called module's ABI version */
#define TSS2_BASE_RC_BAD_REFERENCE              5U /* A pointer is NULL that isn't allowed to be NULL. */
#define TSS2_BASE_RC_INSUFFICIENT_BUFFER        6U /* A buffer isn't large enough */
#define TSS2_BASE_RC_BAD_SEQUENCE               7U /* Function called in the wrong order */
#define TSS2_BASE_RC_NO_CONNECTION              8U /* Fails to connect to next lower layer */
#define TSS2_BASE_RC_TRY_AGAIN                  9U /* Operation timed out; function must be called again to be completed */
#define TSS2_BASE_RC_IO_ERROR                  10U /* IO failure */
#define TSS2_BASE_RC_BAD_VALUE                 11U /* A parameter has a bad value */
#define TSS2_BASE_RC_NOT_PERMITTED             12U /* Operation not permitted. */
#define TSS2_BASE_RC_INVALID_SESSIONS          13U /* Session structures were sent, but command doesn't use them or doesn't use the specifed number of them */
#define TSS2_BASE_RC_NO_DECRYPT_PARAM          14U /* If function called that uses decrypt parameter, but command doesn't support crypt parameter. */
#define TSS2_BASE_RC_NO_ENCRYPT_PARAM          15U /* If function called that uses encrypt parameter, but command doesn't support encrypt parameter. */
#define TSS2_BASE_RC_BAD_SIZE                  16U /* If size of a parameter is incorrect */
#define TSS2_BASE_RC_MALFORMED_RESPONSE        17U /* Response is malformed */
#define TSS2_BASE_RC_INSUFFICIENT_CONTEXT      18U /* Context not large enough */
#define TSS2_BASE_RC_INSUFFICIENT_RESPONSE     19U /* Response is not long enough */
#define TSS2_BASE_RC_INCOMPATIBLE_TCTI         20U /* Unknown or unusable TCTI version */
#define TSS2_BASE_RC_NOT_SUPPORTED             21U /* Functionality not supported. */
#define TSS2_BASE_RC_BAD_TCTI_STRUCTURE        22U /* TCTI context is bad. */
#define TSS2_BASE_RC_MEMORY                    23U /* memory allocation failed */
#define TSS2_BASE_RC_BAD_TR                    24U /* invalid ESYS_TR handle */
#define TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS 25U /* More than one session with TPMA_SESSION_DECRYPT bit set */
#define TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS 26U /* More than one session with TPMA_SESSION_ENCRYPT bit set */
#define TSS2_BASE_RC_RSP_AUTH_FAILED           27U /* Response HMAC from TPM did not verify */

/* Base return codes in the range 0xf800 - 0xffff are reserved for
 * implementation-specific purposes.
 */
#define TSS2_LAYER_IMPLEMENTATION_SPECIFIC_OFFSET 0xf800
#define TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT 11

/* Success is the same for all software layers */
#define TSS2_RC_SUCCESS ((TSS2_RC) 0)

/* TCTI error codes */
#define TSS2_TCTI_RC_GENERAL_FAILURE            ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                    TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_TCTI_RC_NOT_IMPLEMENTED            ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                    TSS2_BASE_RC_NOT_IMPLEMENTED))
#define TSS2_TCTI_RC_BAD_CONTEXT                ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_CONTEXT))
#define TSS2_TCTI_RC_ABI_MISMATCH               ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_TCTI_RC_BAD_REFERENCE              ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_TCTI_RC_INSUFFICIENT_BUFFER        ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_TCTI_RC_BAD_SEQUENCE               ((TSS2_RC)(TSS2_TCTI_RC_LAYER |  \
                                                     TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_TCTI_RC_NO_CONNECTION              ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_NO_CONNECTION))
#define TSS2_TCTI_RC_TRY_AGAIN                  ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_TRY_AGAIN))
#define TSS2_TCTI_RC_IO_ERROR                   ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_IO_ERROR))
#define TSS2_TCTI_RC_BAD_VALUE                  ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_VALUE))
#define TSS2_TCTI_RC_NOT_PERMITTED              ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_NOT_PERMITTED))
#define TSS2_TCTI_RC_MALFORMED_RESPONSE         ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_TCTI_RC_NOT_SUPPORTED              ((TSS2_RC)(TSS2_TCTI_RC_LAYER | \
                                                     TSS2_BASE_RC_NOT_SUPPORTED))
/* SAPI error codes */
#define TSS2_SYS_RC_GENERAL_FAILURE            ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                    TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_SYS_RC_ABI_MISMATCH                ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_SYS_RC_BAD_REFERENCE               ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_SYS_RC_INSUFFICIENT_BUFFER         ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_SYS_RC_BAD_SEQUENCE                ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_SYS_RC_BAD_VALUE                   ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_VALUE))
#define TSS2_SYS_RC_INVALID_SESSIONS            ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_INVALID_SESSIONS))
#define TSS2_SYS_RC_NO_DECRYPT_PARAM            ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_NO_DECRYPT_PARAM))
#define TSS2_SYS_RC_NO_ENCRYPT_PARAM            ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_NO_ENCRYPT_PARAM))
#define TSS2_SYS_RC_BAD_SIZE                    ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_SIZE))
#define TSS2_SYS_RC_MALFORMED_RESPONSE          ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_SYS_RC_INSUFFICIENT_CONTEXT        ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
#define TSS2_SYS_RC_INSUFFICIENT_RESPONSE       ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
#define TSS2_SYS_RC_INCOMPATIBLE_TCTI           ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_INCOMPATIBLE_TCTI))
#define TSS2_SYS_RC_BAD_TCTI_STRUCTURE          ((TSS2_RC)(TSS2_SYS_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_TCTI_STRUCTURE))

/* MUAPI error codes */
#define TSS2_MU_RC_GENERAL_FAILURE              ((TSS2_RC)(TSS2_MU_RC_LAYER | \
                                                     TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_MU_RC_BAD_REFERENCE                ((TSS2_RC)(TSS2_MU_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_MU_RC_BAD_SIZE                     ((TSS2_RC)(TSS2_MU_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_SIZE))
#define TSS2_MU_RC_BAD_VALUE                    ((TSS2_RC)(TSS2_MU_RC_LAYER | \
                                                     TSS2_BASE_RC_BAD_VALUE))
#define TSS2_MU_RC_INSUFFICIENT_BUFFER          ((TSS2_RC)(TSS2_MU_RC_LAYER | \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))

/* ESAPI Error Codes */
#define TSS2_ESYS_RC_GENERAL_FAILURE             ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_ESYS_RC_ABI_MISMATCH                ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_ESYS_RC_BAD_REFERENCE               ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_ESYS_RC_INSUFFICIENT_BUFFER         ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_ESYS_RC_BAD_SEQUENCE                ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_ESYS_RC_INVALID_SESSIONS            ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_INVALID_SESSIONS))
#define TSS2_ESYS_RC_TRY_AGAIN                   ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_TRY_AGAIN))
#define TSS2_ESYS_RC_IO_ERROR                    ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_IO_ERROR))
#define TSS2_ESYS_RC_BAD_VALUE                   ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_BAD_VALUE))
#define TSS2_ESYS_RC_NO_DECRYPT_PARAM            ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_NO_DECRYPT_PARAM))
#define TSS2_ESYS_RC_NO_ENCRYPT_PARAM            ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_NO_ENCRYPT_PARAM))
#define TSS2_ESYS_RC_BAD_SIZE                    ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_BAD_SIZE))
#define TSS2_ESYS_RC_MALFORMED_RESPONSE          ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_ESYS_RC_INSUFFICIENT_CONTEXT        ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
#define TSS2_ESYS_RC_INSUFFICIENT_RESPONSE       ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
#define TSS2_ESYS_RC_INCOMPATIBLE_TCTI           ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_INCOMPATIBLE_TCTI))
#define TSS2_ESYS_RC_BAD_TCTI_STRUCTURE          ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_BAD_TCTI_STRUCTURE))
#define TSS2_ESYS_RC_MEMORY                      ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_MEMORY))
#define TSS2_ESYS_RC_BAD_TR                      ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                        TSS2_BASE_RC_BAD_TR))
#define TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS   ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                        TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS))
#define TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS   ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                         TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS))
#define TSS2_ESYS_RC_AUTH_MISSING                ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_AUTH_MISSING))
#define TSS2_ESYS_RC_NOT_IMPLEMENTED             ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      TSS2_BASE_RC_NOT_IMPLEMENTED))
#define TSS2_ESYS_RC_BAD_CONTEXT                 ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                        TSS2_BASE_RC_BAD_CONTEXT))
#define TSS2_ESYS_RC_FILE_ERROR                  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | \
                                                      STSS2_BASE_RC_FILE_ERROR))
#endif /* TSS2_COMMON_H */
