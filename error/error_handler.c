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
#include <stdio.h>

#include <sapi/tpm20.h>

#include "error_handler.h"
#include "sys_error.h"
#include "tpm2_error.h"

#define TSS2_RC_ERROR_MASK 0xFFFF

/**
 * Clears out a static buffer by setting index 0 to the null byte.
 * @param buffer
 *  The buffer to clear out.
 */
void
clearbuf (
    char *buffer)
{
    buffer[0] = '\0';
}

/**
 * Prints to a buffer using snprintf(3) using the supplied fmt
 * and varaiadic arguments.
 * @param buf
 *  The buffer to print into.
 * @param len
 *  The length of that buffer.
 * @param fmt
 *  The format string
 * @warning
 *  DO NOT CALL DIRECTLY, use the catbuf() macro.
 */
void __attribute__ ((format (printf, 3, 4)))
_catbuf (
    char *buf,
    size_t len,
    const char *fmt,
    ...)
{
    va_list argptr;
    va_start(argptr, fmt);
    size_t offset = strlen (buf);
    vsnprintf (&buf[offset], len - offset, fmt, argptr);
    va_end(argptr);
}

/**
 * Retrieves the layer number. The layer number is in the 3rd
 * octet and is thus 1 byte big.
 *
 * @param rc
 *  The rc to query for the layer number.
 * @return
 *  The layer number.
 */
static inline UINT8
tss2_rc_layer_number_get (
        TSS2_RC rc)
{
    return ((rc & TSS2_RC_LAYER_MASK) >> TSS2_RC_LAYER_SHIFT);
}

/**
 * Retrieves the error bits from a TSS2_RC. The error bits are
 * contained in the first 2 octets.
 * @param rc
 *  The rc to query for the error bits.
 * @return
 *  The error bits.
 */
static inline UINT16
tss2_rc_layer_error_get (
        TSS2_RC rc)
{
    return ((rc & TSS2_RC_ERROR_MASK));
}

/**
 * Helper macro for adding a layer handler to the layer
 * registration array.
 */
#define ADD_HANDLER(name, handler) \
    { name, handler }

/**
 * Same as ADD_HANDLER but sets it to NULL. Used as a placeholder
 * for non-registered indexes into the handler array.
 */
#define ADD_NULL_HANDLER ADD_HANDLER(NULL, NULL)

static struct {
    const char *name;
    Tss2_Error_Handler handler;
} layer_handler[TSS2_RC_LAYER_COUNT] = {
    ADD_HANDLER("tpm" , tpm2_error_handler),
    ADD_NULL_HANDLER,                       // layer 1  is unused
    ADD_NULL_HANDLER,                       // layer 2  is unused
    ADD_NULL_HANDLER,                       // layer 3  is unused
    ADD_NULL_HANDLER,                       // layer 4  is unused
    ADD_NULL_HANDLER,                       // layer 5  is unused
    ADD_NULL_HANDLER,                       // layer 6  is the feature rc
    ADD_HANDLER("fapi", NULL),              // layer 7  is the esapi rc
    ADD_HANDLER("sys", sys_err_handler),    // layer 8  is the sys rc
    ADD_HANDLER("mu",  sys_err_handler),    // layer 9  is the mu rc
                                            // Defaults to the system handler
    ADD_HANDLER("tcti", sys_err_handler),   // layer 10 is the tcti rc
                                            // Defaults to the system handler
    ADD_HANDLER("rmt", tpm2_error_handler), // layer 11 is the resource manager TPM RC
                                            // The RM usually duplicates TPM responses
                                            // So just default the handler to tpm2.
    ADD_HANDLER("rm", NULL),                // layer 12 is the rm rc
    ADD_HANDLER("drvr", NULL),              // layer 13 is the driver rc
};

/**
 * Determines if the layer allowed to be registered to.
 * @param layer
 *  The layer to determine handler assignment eligibility of.
 * @return
 *  True if it is reserved and thus non-assignable, false otherwise.
 */
static bool
is_reserved_layer (
        UINT8 layer)
{
    return layer == 0;
}

/**
 * If a layer has no handler registered, default to this
 * handler that prints the error number in hex.
 * @param rc
 *  The rc to print the error number of.
 * @return
 *  The string.
 */
static const char *
unkown_layer_handler (
        TSS2_RC rc)
{
    (void) rc;

    static char buf[32];

    clearbuf (buf);
    catbuf(buf, "0x%X", tss2_rc_layer_error_get (rc));

    return buf;
}

/**
 * Register or unregister a custom layer error handler.
 * @param layer
 *  The layer in which to register a handler for. It is an error
 *  to register for the following reserved layers:
 *    - TSS2_TPM_RC_LAYER  - layer  0
 *    - TSS2_SYS_RC_LAYER  - layer  8
 *    - TSS2_MU_RC_LAYER   - layer  9
 *    - TSS2_TCTI_RC_LAYER - layer 10
 * @param name
 *  A friendly layer name. It is an error for the name to be of
 *  length 0 or greater than 4.
 * @param handler
 *  The handler function to register or NULL to unregister.
 * @return
 *  True on success or False on error.
 */
bool
Tss2_Rc_Set_Handler (
    UINT8 layer,
    const char *name,
    Tss2_Error_Handler handler)
{
    /* don't allow setting reserved layers */
    if (is_reserved_layer (layer)) return false;

    /*
     * if they are clearing the handler, name doesn't matter
     * clear it too.
     */
    if (!handler) name = NULL;

    /* Perform a zero and max-name length check if name is being set */
    if (name) {
        size_t len = name ? strlen (name) : 0;
        if (!len || len > TSS2_ERR_LAYER_NAME_MAX) return false;
    }

    layer_handler[layer].handler = handler;
    layer_handler[layer].name = name;

    return true;
}

/**
 * Given a TSS2_RC return code, provides a static error string in the format:
 * <layer-name>:<layer-specific-msg>.
 *
 * The layer-name section will either be the friendly name, or if no layer
 * handler is registered, the base10 layer number.
 *
 * The "layer-specific-msg" is layer specific and will contain details on the
 * error that occurred or the error code if it couldn't look it up.
 *
 * Known layer specific substrings:
 * TPM - The tpm layer produces 2 distinct format codes that allign with:
 *   - Section 6.6 of: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 *   - Section 39.4 of: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
 *
 *   The two formats are format 0 and format 1.
 *   Format 0 string format:
 *     - "<error|warn>(<version>): <description>
 *     - Examples:
 *       - error(1.2): bad tag
 *       - warn(2.0): the 1st handle in the handle area references a transient object or session that is not loaded
 *
 *   Format 1 string format:
 *      - <handle|session|parameter>(<index>):<description>
 *      - Examples:
 *        - handle(unk):value is out of range or is not correct for the context
 *        - tpm:handle(5):value is out of range or is not correct for the context
 *
 *   Note that passing TPM2_RC_SUCCESS results in the layer specific message of "success".
 *
 *   The System, TCTI and Marshaling (MU) layers, all define simple string
 *   returns analogous to strerror(3).
 *
 *   Unknown layers will have the layer number in decimal and then a layer specific string of
 *   a hex value representing the error code. For example: 9:0x3
 *
 * @param rc
 *  The error code to decode.
 * @return
 *  A human understandable error description string.
 */
const char *
Tss2_Rc_StrError (
    TSS2_RC rc)
{
    static char buf[TSS2_ERR_LAYER_NAME_MAX + TSS2_ERR_LAYER_ERROR_STR_MAX + 1];

    clearbuf (buf);

    UINT8 layer = tss2_rc_layer_number_get (rc);

    Tss2_Error_Handler handler = layer_handler[layer].handler;
    const char *lname = layer_handler[layer].name;

    if (lname)
        catbuf(buf, "%s:", lname);
    else
        catbuf(buf, "%u:", layer);

    handler = !handler ? unkown_layer_handler : handler;

    // Handlers only need the error bits. This way they don't
    // need to concern themselves with masking off the layer
    // bits or anything else.
    UINT16 err_bits = tss2_rc_layer_error_get (rc);
    const char *e = err_bits ? handler (err_bits) : "success";
    if (e)
        catbuf(buf, "%s", e);
    else
        catbuf(buf, "0x%X", err_bits);

    return buf;
}
