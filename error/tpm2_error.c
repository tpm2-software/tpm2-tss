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
#include <stdbool.h>

#include <sapi/tpm20.h>

#include "error_handler.h"
#include "tpm2_error.h"

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

/**
 * Queries a TPM format 1 error codes N field. The N field
 * is a 4 bit field located at bits 8:12.
 * @param rc
 *  The rc to query the N field for.
 * @return
 *  The N field value.
 */
static inline UINT8 tpm2_rc_fmt1_N_get(TPM2_RC rc) {
    return ((rc & (0xF << 8)) >> 8);
}

/**
 * Queries the index bits out of the N field contained in a TPM format 1
 * error code. The index bits are the low 3 bits of the N field.
 * @param rc
 *  The TPM format 1 error code to query for the index bits.
 * @return
 *  The index bits from the N field.
 */
static inline UINT8 tpm2_rc_fmt1_N_index_get(TPM2_RC rc) {
    return (tpm2_rc_fmt1_N_get(rc) & 0x7);
}

/**
 * Determines if the N field in a TPM format 1 error code is
 * a handle or not.
 * @param rc
 *  The TPM format 1 error code to query.
 * @return
 *  True if it is a handle, false otherwise.
 */
static inline bool tpm2_rc_fmt1_N_is_handle(TPM2_RC rc) {
    return ((tpm2_rc_fmt1_N_get(rc) & 0x8) == 0);
}

static inline UINT8 tpm2_rc_fmt1_P_get(TPM2_RC rc) {
    return ((rc & (1 << 6)) >> 6);
}

static inline UINT16 tpm2_rc_fmt1_error_get(TPM2_RC rc) {
    return (rc & 0x3F);
}

static inline UINT16 tpm2_rc_fmt0_error_get(TPM2_RC rc) {
    return (rc & 0x7F);
}

static inline UINT8 tpm2_rc_tpm_fmt0_V_get(TPM2_RC rc) {
    return ((rc & (1 << 8)) >> 8);
}

static inline UINT8 tpm2_rc_fmt0_T_get(TPM2_RC rc) {
    return ((rc & (1 << 10)) >> 8);
}

static inline UINT8 tpm2_rc_fmt0_S_get(TSS2_RC rc) {
    return ((rc & (1 << 11)) >> 8);
}

static const char *tpm2_err_handler_fmt1(TPM2_RC rc) {

    /*
     * format 1 error codes start at 1, so
     * add a NULL entry to index 0.
     */
    static const char *fmt1_err_strs[] = {
        // 0x0 - EMPTY
        NULL,
        // 0x1 - TPM2_RC_ASYMMETRIC
        "asymmetric algorithm not supported or not correct",
        // 0x2 - TPM2_RC_ATTRIBUTES
        "inconsistent attributes",
        // 0x3 - TPM2_RC_HASH
        "hash algorithm not supported or not appropriate",
        // 0x4 - TPM2_RC_VALUE
        "value is out of range or is not correct for the context",
        // 0x5 - TPM2_RC_HIERARCHY
        "hierarchy is not enabled or is not correct for the use",
        // 0x6 - EMPTY
        NULL,
        // 0x7 - TPM2_RC_KEY_SIZE
        "key size is not supported",
        // 0x8 - TPM2_RC_MGF
        "mask generation function not supported",
        // 0x9 - TPM2_RC_MODE
        "mode of operation not supported",
        // 0xA - TPM2_RC_TYPE
        "the type of the value is not appropriate for the use",
        // 0xB - TPM2_RC_HANDLE
        "the handle is not correct for the use",
        // 0xC - TPM2_RC_KDF
        "unsupported key derivation function or function not appropriate for "
        "use",
        // 0xD - TPM2_RC_RANGE
        "value was out of allowed range",
        // 0xE - TPM2_RC_AUTH_FAIL
        "the authorization HMAC check failed and DA counter incremented",
        // 0xF - TPM2_RC_NONCE
        "invalid nonce size or nonce value mismatch",
        // 0x10 - TPM2_RC_PP
        "authorization requires assertion of PP",
        // 0x11 - EMPTY
        NULL,
        // 0x12 - TPM2_RC_SCHEME
        "unsupported or incompatible scheme",
        // 0x13 - EMPTY
        NULL,
        // 0x14 - EMPTY
        NULL,
        // 0x15 - TPM2_RC_SIZE
        "structure is the wrong size",
        // 0x16 - TPM2_RC_SYMMETRIC
        "unsupported symmetric algorithm or key size, or not appropriate for"
        " instance",
        // 0x17 - TPM2_RC_TAG
        "incorrect structure tag",
        // 0x18 - TPM2_RC_SELECTOR
        "union selector is incorrect",
        // 0x19 - EMPTY
        NULL,
        // 0x1A - TPM2_RC_INSUFFICIENT
        "the TPM was unable to unmarshal a value because there were not enough"
        " octets in the input buffer",
        // 0x1B - TPM2_RC_SIGNATURE
        "the signature is not valid",
        // 0x1C - TPM2_RC_KEY
        "key fields are not compatible with the selected use",
        // 0x1D - TPM2_RC_POLICY_FAIL
        "a policy check failed",
        // 0x1E - EMPTY
        NULL,
        // 0x1F - TPM2_RC_INTEGRITY
        "integrity check failed",
        // 0x20 - TPM2_RC_TICKET
        "invalid ticket",
        // 0x21 - TPM2_RC_RESERVED_BITS
        "reserved bits not set to zero as required",
        // 0x22 - TPM2_RC_BAD_AUTH
        "authorization failure without DA implications",
        // 0x23 - TPM2_RC_EXPIRED
        "the policy has expired",
        // 0x24 - TPM2_RC_POLICY_CC
        "the commandCode in the policy is not the commandCode of the command"
        " or the command code in a policy command references a command that"
        " is not implemented",
        // 0x25 - TPM2_RC_BINDING
        "public and sensitive portions of an object are not cryptographically bound",
        // 0x26 - TPM2_RC_CURVE
        "curve not supported",
        // 0x27 - TPM2_RC_ECC_POINT
        "point is not on the required curve",
    };

    static char buf[TSS2_ERR_LAYER_ERROR_STR_MAX + 1];

    clearbuf(buf);

    /* Print whether or not the error is caused by a bad
     * handle or parameter. On the case of a Handle (P == 0)
     * then the N field top bit will be set. Un-set this bit
     * to get the handle index by subtracting 8 as N is a 4
     * bit field.
     *
     * the lower 3 bits of N indicate index, and the high bit
     * indicates
     */
    UINT8 index = tpm2_rc_fmt1_N_index_get(rc);

    bool is_handle = tpm2_rc_fmt1_N_is_handle(rc);
    const char *m = tpm2_rc_fmt1_P_get(rc)
            ? "parameter" : is_handle ? "handle" : "session";
    catbuf(buf, "%s", m);

    if (index) {
        catbuf(buf, "(%u):", index);
    } else {
        catbuf(buf, "%s", "(unk):");
    }

    UINT8 errnum = tpm2_rc_fmt1_error_get(rc);
    if (errnum < ARRAY_LEN(fmt1_err_strs)) {
        m = fmt1_err_strs[errnum];
        catbuf(buf, "%s", m);
    } else {
        catbuf(buf, "unknown error num: 0x%X", errnum);
    }

    return buf;
}

static const char *tpm2_err_handler_fmt0(TSS2_RC rc) {

    /*
     * format 0 error codes start at 1, so
     * add a NULL entry to index 0.
     * Thus, no need to offset the error bits
     * and fmt0 and fmt1 arrays can be used
     * in-place of each other for lookups.
     */
    static const char *fmt0_warn_strs[] = {
            // 0x0 - EMPTY
            NULL,
            // 0x1 - TPM2_RC_CONTEXT_GAP
            "gap for context ID is too large",
            // 0x2 - TPM2_RC_OBJECT_MEMORY
            "out of memory for object contexts",
            // 0x3 - TPM2_RC_SESSION_MEMORY
            "out of memory for session contexts",
            // 0x4 - TPM2_RC_MEMORY
            "out of shared object/session memory or need space for internal"
            " operations",
            // 0x5 - TPM2_RC_SESSION_HANDLES
            "out of session handles",
            // 0x6 - TPM2_RC_OBJECT_HANDLES
            "out of object handles",
            // 0x7 - TPM2_RC_LOCALITY
            "bad locality",
            // 0x8 - TPM2_RC_YIELDED
            "the TPM has suspended operation on the command; forward progress"
            " was made and the command may be retried",
            // 0x9 - TPM2_RC_CANCELED
            "the command was canceled",
            // 0xA - TPM2_RC_TESTING
            "TPM is performing self-tests",
            // 0xB - EMPTY
            NULL,
            // 0xC - EMPTY
            NULL,
            // 0xD - EMPTY
            NULL,
            // 0xE - EMPTY
            NULL,
            // 0xF - EMPTY
            NULL,
            // 0x10 - TPM2_RC_REFERENCE_H0
            "the 1st handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x11 - TPM2_RC_REFERENCE_H1
            "the 2nd handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x12 - TPM2_RC_REFERENCE_H2
            "the 3rd handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x13 - TPM2_RC_REFERENCE_H3
            "the 4th handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x14 - TPM2_RC_REFERENCE_H4
            "the 5th handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x15 - TPM2_RC_REFERENCE_H5
            "the 6th handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x16 - TPM2_RC_REFERENCE_H6
            "the 7th handle in the handle area references a transient object"
            " or session that is not loaded",
            // 0x17 - EMPTY,
            // 0x18 - TPM2_RC_REFERENCE_S0
            "the 1st authorization session handle references a session that"
            " is not loaded",
            // 0x19 - TPM2_RC_REFERENCE_S1
            "the 2nd authorization session handle references a session that"
            " is not loaded",
            // 0x1A - TPM2_RC_REFERENCE_S2
            "the 3rd authorization session handle references a session that"
            " is not loaded",
            // 0x1B - TPM2_RC_REFERENCE_S3
            "the 4th authorization session handle references a session that"
            " is not loaded",
            // 0x1C - TPM2_RC_REFERENCE_S4
            "the 5th authorization session handle references a session that"
            " is not loaded",
            // 0x1D - TPM2_RC_REFERENCE_S5
            "the 6th authorization session handle references a session that"
            " is not loaded",
            // 0x1E - TPM2_RC_REFERENCE_S6
            "the 7th authorization session handle references a session that"
            " is not loaded",
            // 0x20 -TPM2_RC_NV_RATE
            "the TPM is rate-limiting accesses to prevent wearout of NV",
            // 0x21 - TPM2_RC_LOCKOUT
            "authorizations for objects subject to DA protection are not"
            " allowed at this time because the TPM is in DA lockout mode",
            // 0x22 - TPM2_RC_RETRY
            "the TPM was not able to start the command",
            // 0x23 - TPM2_RC_NV_UNAVAILABLE
            "the command may require writing of NV and NV is not current"
            " accessible",
    };

    /*
     * format 1 error codes start at 0, so
     * no need to offset the error bits.
     */
    static const char *fmt0_err_strs[] = {
            // 0x0 - TPM2_RC_INITIALIZE
            "TPM not initialized by TPM2_Startup or already initialized",
            // 0x1 - TPM2_RC_FAILURE
            "commands not being accepted because of a TPM failure",
            // 0x2 - EMPTY
            NULL,
            // 0x3 - TPM2_RC_SEQUENCE
            "improper use of a sequence handle",
            // 0x4 - EMPTY
            NULL,
            // 0x5 - EMPTY
            NULL,
            // 0x6 - EMPTY
            NULL,
            // 0x7 - EMPTY
            NULL,
            // 0x8 - EMPTY
            NULL,
            // 0x9 - EMPTY
            NULL,
            // 0xA - EMPTY
            NULL,
            // 0xB - TPM2_RC_PRIVATE
            "not currently used",
            // 0xC - EMPTY
            NULL,
            // 0xD - EMPTY
            NULL,
            // 0xE - EMPTY
            NULL,
            // 0xF - EMPTY
            NULL,
            // 0x10 - EMPTY
            NULL,
            // 0x11 - EMPTY
            NULL,
            // 0x12 - EMPTY
            NULL,
            // 0x13 - EMPTY
            NULL,
            // 0x14 - EMPTY
            NULL,
            // 0x15 - EMPTY
            NULL,
            // 0x16 - EMPTY
            NULL,
            // 0x17 - EMPTY
            NULL,
            // 0x18 - EMPTY
            NULL,
            // 0x19 - TPM2_RC_HMAC
            "not currently used",
            // 0x20 - TPM2_RC_DISABLED
            "the command is disabled",
            // 0x21 - TPM2_RC_EXCLUSIVE
            "command failed because audit sequence required exclusivity",
            // 0x22 - EMPTY
            NULL,
            // 0x32 - EMPTY,
            NULL,
            // 0x24 - TPM2_RC_AUTH_TYPE
            "authorization handle is not correct for command",
            // 0x25 - TPM2_RC_AUTH_MISSING
            "command requires an authorization session for handle and it is"
            " not present",
            // 0x26 - TPM2_RC_POLICY
            "policy failure in math operation or an invalid authPolicy value",
            // 0x27 - TPM2_RC_PCR
            "PCR check fail",
            // 0x28 - TPM2_RC_PCR_CHANGED
            "PCR have changed since checked",
            // 0x29 - EMPTY
            NULL,
            // 0x2A - EMPTY
            NULL,
            // 0x2B - EMPTY
            NULL,
            // 0x2C - EMPTY
            NULL,
            // 0x2D - TPM2_RC_UPGRADE
            "TPM is in field upgrade mode unless called via"
            " TPM2_FieldUpgradeData(), then it is not in field upgrade mode",
            // 0x2E - TPM2_RC_TOO_MANY_CONTEXTS
            "context ID counter is at maximum",
            // 0x2F - TPM2_RC_AUTH_UNAVAILABLE
            "authValue or authPolicy is not available for selected entity",
            // 0x30 - TPM2_RC_REBOOT
            "a _TPM_Init and Startup(CLEAR) is required before the TPM can"
            " resume operation",
            // 0x31 - TPM2_RC_UNBALANCED
            "the protection algorithms (hash and symmetric) are not reasonably"
            " balanced. The digest size of the hash must be larger than the key"
            " size of the symmetric algorithm.",
            // 0x32 - EMPTY
            NULL,
            // 0x33 - EMPTY
            NULL,
            // 0x34 - EMPTY
            NULL,
            // 0x35 - EMPTY
            NULL,
            // 0x36 - EMPTY
            NULL,
            // 0x37 - EMPTY
            NULL,
            // 0x38 - EMPTY
            NULL,
            // 0x39 - EMPTY
            NULL,
            // 0x3A - EMPTY
            NULL,
            // 0x3B - EMPTY
            NULL,
            // 0x3C - EMPTY
            NULL,
            // 0x3D - EMPTY
            NULL,
            // 0x3E - EMPTY
            NULL,
            // 0x3F - EMPTY
            NULL,
            // 0x40 - EMPTY
            NULL,
            // 0x41 - EMPTY
            NULL,
            // 0x42 - TPM2_RC_COMMAND_SIZE
            "command commandSize value is inconsistent with contents of the"
            " command buffer; either the size is not the same as the octets"
            " loaded by the hardware interface layer or the value is not large"
            " enough to hold a command header",
            // 0x43 - TPM2_RC_COMMAND_CODE
            "command code not supported",
            // 0x44 - TPM2_RC_AUTHSIZE
            "the value of authorizationSize is out of range or the number of"
            " octets in the Authorization Area is greater than required",
            // 0x45 - TPM2_RC_AUTH_CONTEXT
            "use of an authorization session with a context command or another"
            " command that cannot have an authorization session",
            // 0x46 - TPM2_RC_NV_RANGE
            "NV offset+size is out of range",
            // 0x47 - TPM2_RC_NV_SIZE
            "Requested allocation size is larger than allowed",
            // 0x48 - TPM2_RC_NV_LOCKED
            "NV access locked",
            // 0x49 - TPM2_RC_NV_AUTHORIZATION
            "NV access authorization fails in command actions",
            // 0x4A - TPM2_RC_NV_UNINITIALIZED
            "an NV Index is used before being initialized or the state saved"
            " by TPM2_Shutdown(STATE) could not be restored",
            // 0x4B - TPM2_RC_NV_SPACE
            "insufficient space for NV allocation",
            // 0x4C - TPM2_RC_NV_DEFINED
            "NV Index or persistent object already defined",
            // 0x4D - EMPTY
            NULL,
            // 0x4E - EMPTY
            NULL,
            // 0x4F - EMPTY
            NULL,
            // 0x50 - TPM2_RC_BAD_CONTEXT
            "context in TPM2_ContextLoad() is not valid",
            // 0x51 - TPM2_RC_CPHASH
            "cpHash value already set or not correct for use",
            // 0x52 - TPM2_RC_PARENT
            "handle for parent is not a valid parent",
            // 0x53 - TPM2_RC_NEEDS_TEST
            "some function needs testing",
            // 0x54 - TPM2_RC_NO_RESULT
            "returned when an internal function cannot process a request due to"
            " an unspecified problem. This code is usually related to invalid"
            " parameters that are not properly filtered by the input"
            " unmarshaling code",
            // 0x55 - TPM2_RC_SENSITIVE
            "the sensitive area did not unmarshal correctly after decryption",
    };

    static char buf[TSS2_ERR_LAYER_ERROR_STR_MAX + 1];

    clearbuf(buf);

    char *e = tpm2_rc_fmt0_S_get(rc) ? "warn" : "error";
    char *v = tpm2_rc_tpm_fmt0_V_get(rc) ? "2.0" : "1.2";
    catbuf(buf, "%s(%s): ", e, v);

    UINT8 errnum = tpm2_rc_fmt0_error_get(rc);
    /* We only have version 2.0 spec codes defined */
    if (tpm2_rc_tpm_fmt0_V_get(rc)) {
        /* TCG specific error code */
        if(tpm2_rc_fmt0_T_get(rc)) {
            catbuf(buf, "Vendor specific error: 0x%X", errnum);
            return buf;
        }

        /* is it a warning (version 2 error string) or is it a 1.2 error? */
        size_t len = tpm2_rc_fmt0_S_get(rc)
                ? ARRAY_LEN(fmt0_warn_strs) : ARRAY_LEN(fmt0_err_strs);
        const char **selection = tpm2_rc_fmt0_S_get(rc)
                ? fmt0_warn_strs : fmt0_err_strs;
        if (errnum >= len) {
            return NULL;
        }

        const char *m = selection[errnum];
        if (!m) {
            return NULL;
        }

        catbuf(buf, "%s", m);
        return buf;
    }

    catbuf(buf, "%s", "unknown version 1.2 error code");

    return buf;
}

/**
 * Retrieves the layer field from a TSS2_RC code.
 * @param rc
 *  The rc to query the layer index of.
 * @return
 *  The layer index.
 */
static inline UINT8
tss2_rc_layer_format_get(
    TSS2_RC rc) {
    return ((rc & (1 << 7)) >> 7);
}

/**
 * Error handler for a TPM2_RC code. Note the return format of this
 * is well documented under: Tss2_Rc_StrError()
 * @param rc
 *  The return code to deciper.
 * @return
 *  A string representing the TPM2_RC specific error.
 */
const char *tpm2_error_handler(TSS2_RC rc) {

    bool is_fmt_1 = tss2_rc_layer_format_get(rc);

    return is_fmt_1 ?
        tpm2_err_handler_fmt1(rc) :
        tpm2_err_handler_fmt0(rc);
}
