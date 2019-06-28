/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include "tctildr.h"
#include "tss2_tcti_mssim.h"
#ifdef _WIN32
#include "tss2_tcti_tbs.h"
#else /* _WIN32 */
#include "tss2_tcti_device.h"
#endif
#define LOGMODULE tcti
#include "util/log.h"

#define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))

struct {
    TSS2_TCTI_INIT_FUNC init;
    char *conf;
    char *description;
} tctis [] = {
#ifdef _WIN32
    {
        .init = Tss2_Tcti_Tbs_Init,
        .description = "Access to TBS",
    },
#else
#ifdef TCTI_DEVICE
    {
        .init = Tss2_Tcti_Device_Init,
        .conf = "/dev/tpmrm0",
        .description = "Access to /dev/tpmrm0",
    },
    {
        .init = Tss2_Tcti_Device_Init,
        .conf = "/dev/tpm0",
        .description = "Access to /dev/tpm0",
    },
#endif /* TCTI_DEVICE */
#endif /* _WIN32 */
#ifdef TCTI_MSSIM
    {
        .init = Tss2_Tcti_Mssim_Init,
        .conf = "host=localhost,port=2321",
        .description = "Access to Mssim-simulator for tcp://localhost:2321",
    },
#endif /* TCTI_MSSIM */
};
TSS2_RC
tctildr_get_default(TSS2_TCTI_CONTEXT ** tcticontext, void **dlhandle)
{
    TSS2_RC rc;

    (void)dlhandle;
    if (tcticontext == NULL) {
        LOG_ERROR("tcticontext must not be NULL");
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    *tcticontext = NULL;

    for (size_t i = 0; i < ARRAY_SIZE(tctis); i++) {
        LOG_DEBUG("Attempting to connect using standard TCTI: %s",
                  tctis[i].description);
        rc = tcti_from_init (tctis[i].init,
                             tctis[i].conf,
                             tcticontext);
        if (rc == TSS2_RC_SUCCESS)
            return TSS2_RC_SUCCESS;
        LOG_DEBUG("Failed to load standard TCTI number %zu", i);
    }

    LOG_ERROR("No standard TCTI could be loaded");
    return TSS2_TCTI_RC_IO_ERROR;
}
void
tctildr_finalize_data(void **data)
{
    return;
}