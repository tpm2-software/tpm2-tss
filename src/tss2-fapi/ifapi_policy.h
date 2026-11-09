/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_POLICY_H
#define IFAPI_POLICY_H

#include <stdbool.h> // for bool
#include <stddef.h>  // for size_t

#include "fapi_int.h"               // for FAPI_CONTEXT, IFAPI_POLICY_CTX
#include "ifapi_io.h"               // for IFAPI_IO
#include "ifapi_policy_callbacks.h" // for ifapi_get_key_public, ifapi_ge...
#include "ifapi_policy_store.h"     // for IFAPI_POLICY_STORE
#include "tss2_common.h"            // for TSS2_RC
#include "tss2_esys.h"              // for ESYS_CONTEXT
#include "tss2_fapi.h"              // for FAPI_CONTEXT
#include "tss2_policy.h"            // for TSS2_POLICY_CALC_CALLBACKS
#include "tss2_tpm2_types.h"        // for TPMI_ALG_HASH, TPM2B_DIGEST

static inline void
ifapi_policy_ctx_init(FAPI_CONTEXT *context) {

    TSS2_POLICY_CALC_CALLBACKS *callbacks = &context->policy.calc_callbacks;
    callbacks->cbname = ifapi_get_object_name;
    callbacks->cbname_userdata = context;
    callbacks->cbpublic = ifapi_get_key_public;
    callbacks->cbpublic_userdata = context;
    callbacks->cbnvpublic = ifapi_get_nv_public;
    callbacks->cbnvpublic_userdata = context;
    callbacks->cbpcr = ifapi_read_pcr;
    callbacks->cbpcr_userdata = context;
}

TSS2_RC
ifapi_calculate_tree_ex(IFAPI_POLICY_CTX    *policyContext,
                        IFAPI_POLICY_STORE  *pstore,
                        IFAPI_IO            *io,
                        const char          *policyPath,
                        struct TPMS_POLICY **policy,
                        TPMI_ALG_HASH        hash_alg,
                        TPM2B_DIGEST        *digest);

TSS2_RC
ifapi_execute_tree_ex(enum IFAPI_STATE_POLICY    *state,
                      TSS2_POLICY_CTX           **policy_ctx,
                      TSS2_POLICY_EXEC_CALLBACKS *callbacks,
                      IFAPI_POLICY_STORE         *pstore,
                      IFAPI_IO                   *io,
                      const char                 *policyPath,
                      struct TPMS_POLICY        **policy,
                      ESYS_CONTEXT               *esys_ctx,
                      ESYS_TR                     session,
                      TPMI_ALG_HASH               hash_alg,
                      bool                        do_flush);

static inline TSS2_RC
ifapi_calculate_tree(FAPI_CONTEXT        *context,
                     const char          *policyPath,
                     struct TPMS_POLICY **policy,
                     TPMI_ALG_HASH        hash_alg,
                     TPM2B_DIGEST        *digest) {

    return ifapi_calculate_tree_ex(&context->policy, &context->pstore, &context->io, policyPath,
                                   policy, hash_alg, digest);
}

#endif /* IFAPI_POLICY_H */
