/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef NO_DL
#include <dlfcn.h>
#endif /* NO_DL */
#include <stdlib.h>

#include<unistd.h>

#include "tss2_fapi.h"
#include "tss2_tctildr.h"
#include "fapi_int.h"
#include "fapi_util.h"
#include "tss2_esys.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

/** One-Call function for Fapi_Finalize
 *
 * Fapi_Finalize() finalizes a context by closing IPC/RPC connections and freeing
 * its consumed memory.
 *
 * @param [in] context The FAPI_CONTEXT
 */
void
Fapi_Finalize(
    FAPI_CONTEXT **context)
{
    LOG_TRACE("called for context:%p", context);

    if (!context || !*context) {
        LOG_WARNING("Attempting to free NULL context");
        return;
    }

    LOG_DEBUG("called: context: %p, *context: %p", context,
              (context != NULL) ? *context : NULL);

    ifapi_profiles_finalize(&(*context)->profiles);

    TSS2_TCTI_CONTEXT *tcti = NULL;

    if ((*context)->esys) {
        Esys_GetTcti((*context)->esys, &tcti);
        Esys_Finalize(&((*context)->esys));
        if (tcti) {
            LOG_TRACE("Finalizing TCTI");
            Tss2_TctiLdr_Finalize(&tcti);
        }
    }

    SAFE_FREE((*context)->pstore.policydir);
    SAFE_FREE((*context)->keystore.systemdir);
    SAFE_FREE((*context)->keystore.userdir);
    SAFE_FREE((*context)->keystore.defaultprofile);

    SAFE_FREE((*context)->cmd.Provision.root_crt);
    SAFE_FREE((*context)->cmd.Provision.intermed_crt);
    SAFE_FREE((*context)->cmd.Provision.pem_cert);

    SAFE_FREE((*context)->config.profile_dir);
    SAFE_FREE((*context)->config.user_dir);
    SAFE_FREE((*context)->config.keystore_dir);
    SAFE_FREE((*context)->config.profile_name);
    SAFE_FREE((*context)->config.tcti);
    SAFE_FREE((*context)->config.log_dir);
    ifapi_profiles_finalize(&(*context)->profiles);

    SAFE_FREE((*context)->eventlog.log_dir);

    ifapi_free_objects(*context);
    free(*context);
    *context = NULL;

    LOG_DEBUG("finished");
}
