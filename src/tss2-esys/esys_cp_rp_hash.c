/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2025, Juergen Repp
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h> // for PRIx32, uint8_t, SIZE_MAX, int32_t
#include <stdbool.h>  // for bool, false, true
#include <stdlib.h>   // for NULL, malloc, size_t, calloc
#include <string.h>   // for memcmp

#include "esys_int.h"        // for RSRC_NODE_T, ESYS_CONTEXT, _ESYS_ASSERT...
#include "esys_iutil.h"      // for iesys_compute_cp_hash ...
#include "esys_mu.h"         // for iesys_MU_IESYS_RESOURCE_Marshal, iesys_...
#include "esys_types.h"      // for IESYS_RESOURCE, IESYS_RSRC_UNION, IESYS...
#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_ESYS_RC_...
#include "tss2_esys.h"       // for ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE
#include "tss2_tpm2_types.h" // for TPM2B_NAME, TPM2_HANDLE, TPM2_HR_SHIFT

#define LOGMODULE esys
#include "util/log.h" // for return_if_error, SAFE_FREE, goto_if_error

/** Get the cpHash buffer computed by an ESYS async call.
 *
 * The buffer will be returned if the buffer is found for the passed hashAlg.
 * @param esys_ctxt [in,out] The ESYS_CONTEXT.
 * @param hashAlg [in] The hash alg used to compute the cp hash.
 * @param cpHash [out] The buffer containing the cp hash.
 *        (caller-callocated)
 * @param cpHash_size [out] The size of the cpHash buffer.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_SYS_RC_BAD_SEQUENCE: if the SAPI is not in appropriate state.
 * @retval TSS2_ESYS_RC_BAD_VALUE if hashAlg is not found.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esys_ctx is NULL.
 * @retval TSS2_ESYS_RC_MEMORY if the buffer for the cpHash can't
 *         be allocated.
 */
TSS2_RC
Esys_GetCpHash(ESYS_CONTEXT *esys_ctx,
               TPMI_ALG_HASH hashAlg,
               uint8_t     **cpHash,
               size_t       *cpHash_size) {

    uint8_t cp_hash[sizeof(TPMU_HA)];
    TSS2_RC r;

    return_if_null(esys_ctx, "ESYS context is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    r = iesys_compute_cp_hash(esys_ctx, hashAlg, &cp_hash[0], cpHash_size);
    return_if_error(r, "Compute cp hash");
    *cpHash = malloc(*cpHash_size);
    return_if_null(*cpHash, "Buffer could not be allocated", TSS2_ESYS_RC_MEMORY);
    memcpy(*cpHash, &cp_hash[0], *cpHash_size);
    return TSS2_RC_SUCCESS;
}

/** Get the rpHash buffer computed by an ESYS finalize call.
 *
 * The buffer will be returned if the buffer is found for the passed hashAlg.
 * @param esys_ctx [in,out] The ESYS_CONTEXT.
 * @param hashAlg [in] The hash alg used to compute the rp hash.
 * @param rpHash [out] The buffer containing the rp hash.
 *        (caller-callocated)
 * @param rpHash_size [out] The size of the rpHash buffer.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_SYS_RC_BAD_SEQUENCE: if the SAPI is not in appropriate state.
 * @retval TSS2_ESYS_RC_BAD_VALUE if hashAlg is not found.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esys_ctx is NULL.
 * @retval TSS2_ESYS_RC_MEMORY if the buffer for the rpHash can't
 *         be allocated.
 */
TSS2_RC
Esys_GetRpHash(ESYS_CONTEXT *esys_ctx,
               TPMI_ALG_HASH hashAlg,
               uint8_t     **rpHash,
               size_t       *rpHash_size) {
    uint8_t rp_hash[sizeof(TPMU_HA)];
    TSS2_RC r;

    return_if_null(esys_ctx, "ESYS context is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    r = iesys_compute_rp_hash(esys_ctx, hashAlg, &rp_hash[0], rpHash_size);
    return_if_error(r, "Compute rp hash");
    *rpHash = malloc(*rpHash_size);

    return_if_null(*rpHash, "Buffer could not be allocated", TSS2_ESYS_RC_MEMORY);
    memcpy(*rpHash, &rp_hash[0], *rpHash_size);
    return TSS2_RC_SUCCESS;
}

/** Reset the ESYS state.
 *
 * If only the cp hash will be computed and there will no finish call
 * after the async call the ESYS sate and also the SAPI state has to be
 * reset to allow further ESYS and SAPI calls.
 * @param esys_ctx [in,out] The ESYS_CONTEXT.
 * @param cpHash_size [out] The size of the cpHash buffer.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esys_ctx is NULL.
 */
TSS2_RC
Esys_Abort(ESYS_CONTEXT *esys_ctx) {
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_RC           r;

    return_if_null(esys_ctx, "ESYS context is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    r = Esys_GetSysContext(esys_ctx, &sys_ctx);
    return_if_error(r, "Could not get Sys context");

    r = Tss2_Sys_Abort(sys_ctx);
    return_if_error(r, "Call of Tss2_Sys_Abort failed.");

    esys_ctx->state = ESYS_STATE_INIT;

    return TSS2_RC_SUCCESS;
}
