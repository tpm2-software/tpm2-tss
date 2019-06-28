/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 * Copyright 2019, Intel Corporation
 * Copyright (c) 2019, Wind River Systems.
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
 *******************************************************************************/

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
#elif defined (__VXWORKS__)
    {
        .init = Tss2_Tcti_Device_Init,
        .conf = "/tpm0",
        .description = "Access to /tpm0",
    },
#else /* _WIN32 */
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
        .description = "Access to simulator using MS protocol, default conf",
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
    (void)data;
    return;
}
