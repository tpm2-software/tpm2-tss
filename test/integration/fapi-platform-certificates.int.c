/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>

#include "tss2_esys.h"
#include "tss2_fapi.h"

#include "test-fapi.h"
#include "fapi_util.h"

#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#define MIN_PLATFORM_CERT_HANDLE 0x01C08000
#define CERTIFICATE_SIZE 15

/** Test the FAPI functions for platform certificates.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_GetPlatformCertificates()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_platform_certificates(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    uint8_t *certs = NULL;
    size_t certsSize = 0;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    TPM2B_AUTH auth = { 0 };

    TPM2B_NV_PUBLIC publicInfo = {
        .nvPublic = {
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = TPMA_NV_PPWRITE | TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD | TPMA_NV_PLATFORMCREATE | TPMA_NV_NO_DA,
            .dataSize = CERTIFICATE_SIZE,
            .nvIndex = MIN_PLATFORM_CERT_HANDLE,
        },
    };

    r = Esys_NV_DefineSpace(context->esys,
                            ESYS_TR_RH_PLATFORM,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle);
    goto_if_error(r, "Error Esys_NV_DefineSpace", error);

    TPM2B_MAX_NV_BUFFER nv_test_data = { .size = CERTIFICATE_SIZE,
                                         .buffer={0x61, 0x61, 0x61, 0x61, 0x61,
                                            0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                                            0x61, 0x61, 0x61, 0x61}};

    r = Esys_NV_Write(context->esys,
                  ESYS_TR_RH_PLATFORM,
                  nvHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &nv_test_data,
                  0);
    goto_if_error(r, "Error Esys_NV_Write", error);

    if ((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH ||
        (r & ~TPM2_RC_N_MASK) == TPM2_RC_HIERARCHY) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        goto skip;
    }

    r = Fapi_GetPlatformCertificates(context, &certs, &certsSize);
    if (r == TSS2_FAPI_RC_NO_CERT)
        goto skip;
    goto_if_error(r, "Error Fapi_GetPlatformCertificates", error);
    assert(certs != NULL);
    assert(certsSize == CERTIFICATE_SIZE);

    Fapi_Free(certs);

    r = Esys_NV_UndefineSpace(context->esys,
                          ESYS_TR_RH_PLATFORM,
                          nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE
                          );
    goto_if_error(r, "Error: NV_UndefineSpace", error);

    /* Cleanup */
    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    return EXIT_FAILURE;

 skip:
    Fapi_Delete(context, "/");
    return EXIT_SKIP;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_platform_certificates(fapi_context);
}
