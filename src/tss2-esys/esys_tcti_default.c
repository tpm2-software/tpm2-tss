/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#ifndef NO_DL
#include <dlfcn.h>
#endif /* NO_DL */

#include "tss2_tcti.h"
#include "tss2_tcti_mssim.h"
#ifdef _WIN32
#include "tss2_tcti_tbs.h"
#else /* _WIN32 */
#include "tss2_tcti_device.h"
#endif /* else */

#define LOGMODULE esys
#include "util/log.h"

#define _STR(A) #A
#define _XSTR(A) _STR(A)

#define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))

struct {
#ifndef NO_DL
    char *file;
#endif /* NO_DL */
    TSS2_TCTI_INIT_FUNC init;
    char *conf;
    char *description;
} tctis[] = {
#ifndef NO_DL
    { "libtss2-tcti-default.so", NULL, NULL, "Access libtss2-tcti-default.so" },
    { "libtss2-tcti-tabrmd.so", NULL, "", "Access libtss2-tcti-tabrmd.so" },
#endif /* NO_DL */
#ifdef _WIN32
    { .init = Tss2_Tcti_Tbs_Init, .conf = "",
      .description = "Access to TBS" },
#else /* _WIN32 */
    { .init = Tss2_Tcti_Device_Init, .conf = "/dev/tpmrm0",
      .description = "Access to /dev/tpmrm0" },
    { .init = Tss2_Tcti_Device_Init, .conf = "/dev/tpm0",
      .description = "Access to /dev/tpm0" },
#endif /* else */
#ifdef TCTI_MSSIM
    { .init = Tss2_Tcti_Mssim_Init, .conf = "host=localhost,port=2321",
      .description = "Access to Mssim-simulator for tcp://localhost:2321" },
#endif /* TCTI_MSSIM */
};


static TSS2_RC
tcti_from_init(TSS2_TCTI_INIT_FUNC init,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC r;
    size_t size;

    LOG_TRACE("Initializing TCTI for config: %s", conf);

    r = init(NULL, &size, conf);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("TCTI init for function %p failed with %" PRIx32, init, r);
        return r;
    }

    *tcti = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (*tcti == NULL) {
        LOG_ERROR("Memory allocation for tcti failed: %s", strerror(errno));
        return TSS2_ESYS_RC_MEMORY;
    }

    r = init(*tcti, &size, conf);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("TCTI init for function %p failed with %" PRIx32, init, r);
        free(*tcti);
        *tcti=NULL;
        return r;
    }

    LOG_DEBUG("Initialized TCTI for config: %s", conf);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC
tcti_from_info(TSS2_TCTI_INFO_FUNC infof,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC r;
    LOG_TRACE("Attempting to load TCTI info");

    const TSS2_TCTI_INFO* info = infof();
    if (info == NULL) {
        LOG_ERROR("TCTI info function failed");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    LOG_TRACE("Loaded TCTI info named: %s", info->name);
    LOG_TRACE("TCTI description: %s", info->description);
    LOG_TRACE("TCTI config_help: %s", info->config_help);

    r = tcti_from_init(info->init, conf, tcti);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("Could not initialize TCTI named: %s", info->name);
        return r;
    }

    LOG_DEBUG("Initialized TCTI named: %s", info->name);

    return TSS2_RC_SUCCESS;
}

#ifndef NO_DL
static TSS2_RC
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
#endif /* NO_DL */

TSS2_RC
get_tcti_default(TSS2_TCTI_CONTEXT ** tcticontext, void **dlhandle)
{
    if (tcticontext == NULL) {
        LOG_ERROR("tcticontext must not be NULL");
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    *tcticontext = NULL;
#ifdef ESYS_TCTI_DEFAULT_MODULE

#ifdef ESYS_TCTI_DEFAULT_CONFIG
    const char *config = _XSTR(ESYS_TCTI_DEFAULT_CONFIG);
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

        if (tctis[i].init != NULL) {
            r = tcti_from_init(tctis[i].init, tctis[i].conf, tcticontext);
            if (r == TSS2_RC_SUCCESS)
                return TSS2_RC_SUCCESS;
            LOG_DEBUG("Failed to load standard TCTI number %zu", i);
#ifndef NO_DL
        } else if (tctis[i].file != NULL) {
            r = tcti_from_file(tctis[i].file, tctis[i].conf, tcticontext,
                               dlhandle);
            if (r == TSS2_RC_SUCCESS)
                return TSS2_RC_SUCCESS;
            LOG_DEBUG("Failed to load standard TCTI number %zu", i);
#endif /* NO_DL */
        } else {
            LOG_ERROR("Erroneous entry in standard TCTIs");
            return TSS2_ESYS_RC_GENERAL_FAILURE;
        }

    }

    LOG_ERROR("No standard TCTI could be loaded");
    return TSS2_ESYS_RC_NOT_IMPLEMENTED;

#endif /* ESYS_TCTI_DEFAULT_MODULE */
}
