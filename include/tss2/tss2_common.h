/***********************************************************************;
 * Copyright (c) 2015, Intel Corporation
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

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files. \
       Do not include this file, #include <tss2/tpm20.h> instead.
#endif  /* TSS2_API_VERSION_1_1_1_1 */

/**
 * Type definitions
 */
#include <stdint.h>

typedef uint8_t     UINT8;      /* unsigned, 8-bit integer */
typedef uint8_t     BYTE;       /* unsigned 8-bit integer */
typedef int8_t      INT8;       /* signed, 8-bit integer */
typedef int         BOOL;       /* a bit in an int  */
typedef uint16_t    UINT16;     /* unsigned, 16-bit integer */
typedef int16_t     INT16;      /* signed, 16-bit integer */
typedef uint32_t    UINT32;     /* unsigned, 32-bit integer */
typedef int32_t     INT32;      /* signed, 32-bit integer */
typedef uint64_t    UINT64;     /* unsigned, 64-bit integer */
typedef int64_t     INT64;      /* signed, 64-bit integer */

typedef UINT32 TSS2_RC; 


/**
 * ABI runetime negotiation structure.
 */
typedef struct {
    UINT32 tssCreator;  /* If == 1, this equals TSSWG-Interop
                   If == 2..9, this is reserved
                   If > TCG_VENDOR_ID_FIRST, this equals Vendor-ID */
    UINT32 tssFamily;   /* Free-to-use for creator > TCG_VENDOR_FIRST */
    UINT32 tssLevel;    /* Free-to-use for creator > TCG_VENDOR_FIRST */
    UINT32 tssVersion;      /* Free-to-use for creator > TCG_VENDOR_FIRST */
} TSS2_ABI_VERSION;


/**
 * Error Levels
 *
 *
 */

// This macro is used to indicate the level of the error:  use 5 and 6th
// nibble for error level.

#define TSS2_RC_LEVEL_SHIFT   16

#define TSS2_ERROR_LEVEL( level )     ( level << TSS2_RC_LEVEL_SHIFT )


//
// Error code levels.   These indicate what level in the software stack
// the error codes are coming from.
//
#define TSS2_TPM_ERROR_LEVEL             TSS2_ERROR_LEVEL(0)
#define TSS2_APP_ERROR_LEVEL             TSS2_ERROR_LEVEL(5)
#define TSS2_FEATURE_ERROR_LEVEL         TSS2_ERROR_LEVEL(6)
#define TSS2_ESAPI_ERROR_LEVEL           TSS2_ERROR_LEVEL(7)
#define TSS2_SYS_ERROR_LEVEL             TSS2_ERROR_LEVEL(8)
#define TSS2_SYS_PART2_ERROR_LEVEL       TSS2_ERROR_LEVEL(9)
#define TSS2_TCTI_ERROR_LEVEL            TSS2_ERROR_LEVEL(10)
#define TSS2_RESMGRTPM_ERROR_LEVEL       TSS2_ERROR_LEVEL(11)
#define TSS2_RESMGR_ERROR_LEVEL          TSS2_ERROR_LEVEL(12)
#define TSS2_DRIVER_ERROR_LEVEL          TSS2_ERROR_LEVEL(13)

#define TSS2_ERROR_LEVEL_MASK            TSS2_ERROR_LEVEL(0xff)

/**
 * Error Codes
 */

//
// Base error codes
// These are not returned directly, but are combined with an ERROR_LEVEL to
// produce the error codes for each layer.
//
#define TSS2_BASE_RC_GENERAL_FAILURE        1 /* Catch all for all errors 
                                                 not otherwise specifed */
#define TSS2_BASE_RC_NOT_IMPLEMENTED        2 /* If called functionality isn't implemented */
#define TSS2_BASE_RC_BAD_CONTEXT            3 /* A context structure is bad */
#define TSS2_BASE_RC_ABI_MISMATCH           4 /* Passed in ABI version doesn't match
                                                 called module's ABI version */
#define TSS2_BASE_RC_BAD_REFERENCE          5 /* A pointer is NULL that isn't allowed to
                                                 be NULL. */
#define TSS2_BASE_RC_INSUFFICIENT_BUFFER    6 /* A buffer isn't large enough */
#define TSS2_BASE_RC_BAD_SEQUENCE           7 /* Function called in the wrong order */
#define TSS2_BASE_RC_NO_CONNECTION          8 /* Fails to connect to next lower layer */
#define TSS2_BASE_RC_TRY_AGAIN              9 /* Operation timed out; function must be
                                                 called again to be completed */
#define TSS2_BASE_RC_IO_ERROR              10 /* IO failure */
#define TSS2_BASE_RC_BAD_VALUE             11 /* A parameter has a bad value */
#define TSS2_BASE_RC_NOT_PERMITTED         12 /* Operation not permitted. */
#define TSS2_BASE_RC_INVALID_SESSIONS      13 /* Session structures were sent, but */
                                              /* command doesn't use them or doesn't use
                                                 the specifed number of them */
#define TSS2_BASE_RC_NO_DECRYPT_PARAM      14 /* If function called that uses decrypt
                                                 parameter, but command doesn't support
                                                 crypt parameter. */
#define TSS2_BASE_RC_NO_ENCRYPT_PARAM      15 /* If function called that uses encrypt 
                                                 parameter, but command doesn't support
                                                 encrypt parameter. */
#define TSS2_BASE_RC_BAD_SIZE              16 /* If size of a parameter is incorrect */
#define TSS2_BASE_RC_MALFORMED_RESPONSE    17 /* Response is malformed */
#define TSS2_BASE_RC_INSUFFICIENT_CONTEXT  18 /* Context not large enough */
#define TSS2_BASE_RC_INSUFFICIENT_RESPONSE 19 /* Response is not long enough */
#define TSS2_BASE_RC_INCOMPATIBLE_TCTI     20 /* Unknown or unusable TCTI version */
#define TSS2_BASE_RC_NOT_SUPPORTED         21 /* Functionality not supported. */
#define TSS2_BASE_RC_BAD_TCTI_STRUCTURE    22 /* TCTI context is bad. */

// Base error codes from 0xf800 - 0xffff are reserved for level- and implementation-specific
// errors.
#define TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT 11
#define TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_OFFSET 0xf800

#define TSS2_RC_SUCCESS                         ((TSS2_RC)0)

//
// TCTI error codes
//

#define TSS2_TCTI_RC_GENERAL_FAILURE            ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                    TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_TCTI_RC_NOT_IMPLEMENTED            ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                    TSS2_BASE_RC_NOT_IMPLEMENTED))
#define TSS2_TCTI_RC_BAD_CONTEXT                ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_CONTEXT))
#define TSS2_TCTI_RC_ABI_MISMATCH               ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_TCTI_RC_BAD_REFERENCE              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_TCTI_RC_INSUFFICIENT_BUFFER        ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_TCTI_RC_BAD_SEQUENCE               ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL |  \
                                                     TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_TCTI_RC_NO_CONNECTION              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_NO_CONNECTION))
#define TSS2_TCTI_RC_TRY_AGAIN                  ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_TRY_AGAIN))
#define TSS2_TCTI_RC_IO_ERROR                   ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_IO_ERROR))
#define TSS2_TCTI_RC_BAD_VALUE                  ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_VALUE))
#define TSS2_TCTI_RC_NOT_PERMITTED              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_NOT_PERMITTED))
#define TSS2_TCTI_RC_MALFORMED_RESPONSE         ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_TCTI_RC_NOT_SUPPORTED              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_NOT_SUPPORTED))
//
// SAPI error codes
//
#define TSS2_SYS_RC_GENERAL_FAILURE            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                    TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_SYS_RC_ABI_MISMATCH                ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_SYS_RC_BAD_REFERENCE               ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_SYS_RC_INSUFFICIENT_BUFFER         ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_SYS_RC_BAD_SEQUENCE                ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_SYS_RC_BAD_VALUE                   ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_VALUE))
#define TSS2_SYS_RC_INVALID_SESSIONS            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_INVALID_SESSIONS))
#define TSS2_SYS_RC_NO_DECRYPT_PARAM            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_NO_DECRYPT_PARAM))
#define TSS2_SYS_RC_NO_ENCRYPT_PARAM            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_NO_ENCRYPT_PARAM))
#define TSS2_SYS_RC_BAD_SIZE                    ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_SIZE))
#define TSS2_SYS_RC_MALFORMED_RESPONSE          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_SYS_RC_INSUFFICIENT_CONTEXT        ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
#define TSS2_SYS_RC_INSUFFICIENT_RESPONSE       ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
#define TSS2_SYS_RC_INCOMPATIBLE_TCTI           ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_INCOMPATIBLE_TCTI))
#define TSS2_SYS_RC_BAD_TCTI_STRUCTURE          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                                     TSS2_BASE_RC_BAD_TCTI_STRUCTURE))

#endif /* TSS2_COMMON_H */
