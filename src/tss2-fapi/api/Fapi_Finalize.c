/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif
#include <stdlib.h>              // for NULL, free

#include "fapi_int.h"            // for FAPI_CONTEXT, IFAPI_CMD_STATE, IFAPI...
#include "fapi_util.h"           // for ifapi_free_objects
#include "ifapi_config.h"        // for IFAPI_CONFIG
#include "ifapi_eventlog.h"      // for IFAPI_EVENTLOG
#include "ifapi_keystore.h"      // for ifapi_cleanup_ifapi_keystore
#include "ifapi_policy_store.h"  // for IFAPI_POLICY_STORE
#include "ifapi_profiles.h"      // for ifapi_profiles_finalize
#include "tss2_esys.h"           // for Esys_Finalize, Esys_GetTcti
#include "tss2_fapi.h"           // for FAPI_CONTEXT, Fapi_Finalize
#include "tss2_tcti.h"           // for TSS2_TCTI_CONTEXT
#include "tss2_tctildr.h"        // for Tss2_TctiLdr_Finalize

#define LOGMODULE fapi
#include "util/aux_util.h"       // for SAFE_FREE
#include "util/log.h"            // for LOG_DEBUG, LOG_TRACE

/** One-Call function for Fapi_Finalize
 *
 * Fapi_Finalize() finalizes a context by closing IPC/RPC connections and freeing
 * its consumed memory.
 *
 * @param[in] context The FAPI_CONTEXT
 */
void
Fapi_Finalize(
    FAPI_CONTEXT **context)
{
    LOG_TRACE("called for context:%p", context);

    /* Check for NULL parameters */
    if (!context || !*context) {
        LOG_DEBUG("Finalizing NULL context.");
        return;
    }

    LOG_DEBUG("called: context: %p, *context: %p", context,
              (context != NULL) ? *context : NULL);

    /* Finalize the profiles module. */
    ifapi_profiles_finalize(&(*context)->profiles);

    /* Finalize the TCTI and ESYS contexts. */
    TSS2_TCTI_CONTEXT *tcti = NULL;

    if ((*context)->esys) {
        Esys_GetTcti((*context)->esys, &tcti);
        Esys_Finalize(&((*context)->esys));
        if (tcti) {
            LOG_TRACE("Finalizing TCTI");
            Tss2_TctiLdr_Finalize(&tcti);
        }
    }

    /* Finalize the keystore module. */
    ifapi_cleanup_ifapi_keystore(&(*context)->keystore);

    /* Finalize the policy module. */
    SAFE_FREE((*context)->pstore.policydir);

    /* Finalize leftovers from provisioning. */
    SAFE_FREE((*context)->cmd.Provision.root_crt);
    SAFE_FREE((*context)->cmd.Provision.intermed_crt);
    SAFE_FREE((*context)->cmd.Provision.pem_cert);

    /* Finalize the config module. */
    SAFE_FREE((*context)->config.profile_dir);
    SAFE_FREE((*context)->config.user_dir);
    SAFE_FREE((*context)->config.keystore_dir);
    SAFE_FREE((*context)->config.profile_name);
    SAFE_FREE((*context)->config.tcti);
    SAFE_FREE((*context)->config.log_dir);
    SAFE_FREE((*context)->config.ek_cert_file);
    SAFE_FREE((*context)->config.web_cert_service);
    SAFE_FREE((*context)->config.firmware_log_file);
    SAFE_FREE((*context)->config.ima_log_file);

    /* Finalize the eventlog module. */
    SAFE_FREE((*context)->eventlog.log_dir);

    /* Finalize all remaining object of the context. */
    ifapi_free_objects(*context);

    /* Free the context's memory. */
    free(*context);
    *context = NULL;

    LOG_DEBUG("finished");
}
