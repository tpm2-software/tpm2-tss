/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdbool.h>          // for bool, false, true
#include <stdint.h>           // for uint8_t
#include <stdlib.h>           // for NULL, size_t, EXIT_FAILURE, EXIT_SUCCESS

#include "fapi_int.h"         // for FAPI_CONTEXT
#include "test-fapi.h"        // for ASSERT, EXIT_SKIP, test_invoke_fapi
#include "tss2_common.h"      // for INT32, TSS2_FAPI_RC_NO_CERT, TSS2_RC
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_NV_UndefineSpace
#include "tss2_fapi.h"        // for FAPI_CONTEXT, Fapi_Delete, Fapi_Free
#include "tss2_tpm2_types.h"  // for TPM2B_NV_PUBLIC, TPMS_CAPABILITY_DATA

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error, LOG_INFO, number_rc, LOG...

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

TSS2_RC cleanup_nv(FAPI_CONTEXT *context, bool already_defined, ESYS_TR nv_esys_handle) {
    TSS2_RC r;

    if (!already_defined) {
      r = Esys_NV_UndefineSpace(context->esys,
                              ESYS_TR_RH_PLATFORM,
                              nv_esys_handle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
      return_if_error(r, "Error: NV_UndefineSpace");
    }
    return TSS2_RC_SUCCESS;
}


TSS2_RC prepare_test(FAPI_CONTEXT *context,
                     TPM2B_MAX_NV_BUFFER *nv_test_data,
                     TPM2_HANDLE nv_handle, bool nv_already_defined, size_t *cert_size,
                     ESYS_TR *esys_handle, bool *skip) {
    TSS2_RC r;

    if(nv_already_defined){
        TPM2B_NV_PUBLIC *nvPublic = NULL;
        TPM2B_NAME *nvName = NULL;

        r = Esys_TR_FromTPMPublic(context->esys,
                                  nv_handle,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  esys_handle);
        return_if_error(r, "Error: TR from TPM public");

        r = Esys_NV_ReadPublic(context->esys,
                               *esys_handle,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               &nvPublic,
                               &nvName);
        return_if_error(r, "Error: nv read public");

        LOG_INFO("nvPublic Size %d\n", nvPublic->nvPublic.dataSize);

        *cert_size = nvPublic->nvPublic.dataSize;
        LOG_INFO("NV size: %zu", *cert_size);
    }

    if(!nv_already_defined){

        TPM2B_AUTH auth = { 0 };

        TPM2B_NV_PUBLIC publicInfo = {
            .nvPublic = {
                .nameAlg = TPM2_ALG_SHA256,
                .attributes = TPMA_NV_PPWRITE | TPMA_NV_AUTHREAD |
                    TPMA_NV_OWNERREAD | TPMA_NV_PLATFORMCREATE | TPMA_NV_NO_DA,
                .dataSize = CERTIFICATE_SIZE,
                .nvIndex = nv_handle
            },
        };

        r = Esys_NV_DefineSpace(context->esys,
                                ESYS_TR_RH_PLATFORM,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &auth,
                                &publicInfo,
                                esys_handle);

        if (number_rc(r) == TPM2_RC_BAD_AUTH ||
            number_rc(r) == TPM2_RC_HIERARCHY) {
            /* Platform authorization not possible test will be skipped */
            LOG_WARNING("Platform authorization not possible.");
            *skip = true;
        }

        return_if_error(r, "Error Esys_NV_DefineSpace");

        r = Esys_NV_Write(context->esys,
                      ESYS_TR_RH_PLATFORM,
                      *esys_handle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      nv_test_data,
                      0);
        return_if_error(r, "Error Esys_NV_Write");

        *cert_size = CERTIFICATE_SIZE;
    }
    return r;
}

int
test_fapi_platform_certificates(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    uint8_t *certs = NULL;
    size_t certsSize = 0;
    /* In case NV was already defined, do not delete it in clean up */
    bool nv_already_defined1 = false;
    bool nv_already_defined2 = false;
    size_t cert_size1;
    size_t cert_size2;
    ESYS_TR nv_esys_handle1 = ESYS_TR_NONE;
    ESYS_TR nv_esys_handle2 = ESYS_TR_NONE;
    bool skip = false;

    TPM2B_MAX_NV_BUFFER nv_test_data = { .size = CERTIFICATE_SIZE,
                                         .buffer={0x61, 0x61, 0x61, 0x61, 0x61,
                                                  0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                                                  0x61, 0x61, 0x61, 0x61}};

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    TPM2_CAP capability = TPM2_CAP_HANDLES;
    INT32 property = 0x1000000;

    UINT32 propertyCount = 254;
    TPMI_YES_NO moreDataAvailable;
    TPMS_CAPABILITY_DATA *capabilityData;

    capabilityData = NULL;
    r = Esys_GetCapability(context->esys,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        capability, property,
        propertyCount,
        &moreDataAvailable,
        &capabilityData);
    goto_if_error(r, "Error Esys_GetCapability", error);

    size_t count = capabilityData->data.handles.count;
    for(size_t i = 0; i < count; i++){
        if(capabilityData->data.handles.handle[i] == MIN_PLATFORM_CERT_HANDLE){
            nv_already_defined1 = true;
        }
        if(capabilityData->data.handles.handle[i] == MIN_PLATFORM_CERT_HANDLE + 1){
            nv_already_defined2 = true;
        }
    }
    SAFE_FREE(capabilityData);

    r =  prepare_test(context, &nv_test_data, MIN_PLATFORM_CERT_HANDLE, nv_already_defined1,
                      &cert_size1, &nv_esys_handle1, &skip);
    if (skip) {
        goto skip;
    }
    goto_if_error(r, "Prepare NV certificates", error);
    r =  prepare_test(context, &nv_test_data, MIN_PLATFORM_CERT_HANDLE + 1, nv_already_defined2,
                      &cert_size2, &nv_esys_handle2, &skip);
    goto_if_error(r, "Prepare NV certificates", error);
    if (skip) {
        goto skip;
    }


    r = Fapi_GetPlatformCertificates(context, &certs, &certsSize);
    if (r == TSS2_FAPI_RC_NO_CERT)
        goto skip;
    goto_if_error(r, "Error Fapi_GetPlatformCertificates", error);
    ASSERT(certs != NULL);
    ASSERT(certsSize == (cert_size1 + cert_size2));

    Fapi_Free(certs);

    /* Cleanup */

    cleanup_nv(context, nv_already_defined1, nv_esys_handle1);
    cleanup_nv(context, nv_already_defined2, nv_esys_handle2);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    return EXIT_SUCCESS;

error:
    cleanup_nv(context, nv_already_defined1, nv_esys_handle1);
    cleanup_nv(context, nv_already_defined2, nv_esys_handle2);
    if (r) {
        LOG_ERROR("error cleanup");
    }
    Fapi_Delete(context, "/");
    return EXIT_FAILURE;

 skip:
    cleanup_nv(context, nv_already_defined1, nv_esys_handle1);
    cleanup_nv(context, nv_already_defined2, nv_esys_handle2);

    Fapi_Delete(context, "/");
    return EXIT_SKIP;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_platform_certificates(fapi_context);
}
