/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <dlfcn.h>

#include "tss2_tcti.h"
#include "tctildr.h"
#define LOGMODULE tcti
#include "util/log.h"

#define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))

struct {
    char *file;
    char *conf;
    char *description;
} tctis[] = {
    {
        .file = "libtss2-tcti-default.so",
        .description = "Access libtss2-tcti-default.so",
    },
    {
        .file = "libtss2-tcti-tabrmd.so",
        .description = "Access libtss2-tcti-tabrmd.so",
    },
    {
        .file = "libtss2-tcti-device.so",
        .conf = "/dev/tpmrm0",
        .description = "Access libtss2-tcti-device.s0 with /dev/tpmrm0",
    },
    {
        .file = "libtss2-tcti-device.so",
        .conf = "/dev/tpm0",
        .description = "Access libtss2-tcti-device.s0 with /dev/tpmrm0",
    },
    {
        .file = "libtss2-tcti-mssim.so",
        .description = "Access to libtss2-tcti-mssim.so",
    },
};

TSS2_RC
tcti_from_file(const char *file,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti,
               void **dlhandle)
{
    TSS2_RC r;
    void *handle;
    TSS2_TCTI_INFO_FUNC infof;

    LOG_TRACE("Attempting to load TCTI file: %s", file);

    handle = dlopen(file, RTLD_NOW);
    if (handle == NULL) {
        LOG_WARNING("Could not load TCTI file: %s", file);
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    infof = (TSS2_TCTI_INFO_FUNC) dlsym(handle, TSS2_TCTI_INFO_SYMBOL);
    if (infof == NULL) {
        LOG_ERROR("Info not found in TCTI file: %s", file);
        dlclose(handle);
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    r = tcti_from_info(infof, conf, tcti);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Could not initialize TCTI file: %s", file);
        dlclose(handle);
        return r;
    }

    if (dlhandle)
        *dlhandle = handle;

    LOG_DEBUG("Initialized TCTI file: %s", file);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tctildr_get_default(TSS2_TCTI_CONTEXT ** tcticontext, void **dlhandle)
{
    if (tcticontext == NULL) {
        LOG_ERROR("tcticontext must not be NULL");
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    *tcticontext = NULL;
#ifdef ESYS_TCTI_DEFAULT_MODULE

#ifdef ESYS_TCTI_DEFAULT_CONFIG
    const char *config = ESYS_TCTI_DEFAULT_CONFIG;
#else /* ESYS_TCTI_DEFAULT_CONFIG */
    const char *config = NULL;
#endif /* ESYS_TCTI_DEFAULT_CONFIG */

    LOG_DEBUG("Attempting to initialize TCTI defined during compilation: %s:%s",
              ESYS_TCTI_DEFAULT_MODULE, config);
    return tcti_from_file(ESYS_TCTI_DEFAULT_MODULE, config, tcticontext,
                          dlhandle);

#else /* ESYS_TCTI_DEFAULT_MODULE */

    TSS2_RC r;

    for (size_t i = 0; i < ARRAY_SIZE(tctis); i++) {
        LOG_DEBUG("Attempting to connect using standard TCTI: %s",
                  tctis[i].description);
        r = tcti_from_file(tctis[i].file, tctis[i].conf, tcticontext,
                           dlhandle);
        if (r == TSS2_RC_SUCCESS)
            return TSS2_RC_SUCCESS;
        LOG_DEBUG("Failed to load standard TCTI number %zu", i);
    }

    LOG_ERROR("No standard TCTI could be loaded");
    return TSS2_TCTI_RC_IO_ERROR;

#endif /* ESYS_TCTI_DEFAULT_MODULE */
}
TSS2_RC
tctildr_get_tcti(const char *name,
                 const char* conf,
                 TSS2_TCTI_CONTEXT **tcti,
                 void **data)
{
    if (tcti == NULL) {
        LOG_ERROR("tcticontext must not be NULL");
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    *tcti = NULL;
    if (name == NULL) {
        return tctildr_get_default (tcti, data);
    }

    return tcti_from_file (name, conf, tcti, data);
}

void
tctildr_finalize_data (void **data)
{
    if (data != NULL && *data != NULL) {
        dlclose(*data);
        *data = NULL;
    }
}
