/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * Test the basic commands for PCR processing: Esys_PCR_Extend, Esys_PCR_Read,
 * Esys_PCR_Reset, Esys_PCR_Event, and Esys_PCR_Allocate
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    ESYS_TR  pcrHandle_handle = 16;
    TPML_DIGEST_VALUES digests
        = {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA1,
                .digest = {
                    .sha1 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                              11, 12, 13, 14, 15, 16, 17, 18, 19}
                }
            },
        }};

    r = Esys_PCR_Extend(
        esys_context,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digests
        );
    goto_if_error(r, "Error: PCR_Extend", error);

    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 2,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA1,
              .sizeofSelect = 3,
              .pcrSelect = { 01, 00, 03},
            },
            { .hash = TPM2_ALG_SHA256,
              .sizeofSelect = 3,
              .pcrSelect = { 01, 00, 03}
            },
        }
    };
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION *pcrSelectionOut;
    TPML_DIGEST *pcrValues;

    r = Esys_PCR_Read(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcrSelectionIn,
        &pcrUpdateCounter,
        &pcrSelectionOut,
        &pcrValues);
    goto_if_error(r, "Error: PCR_Read", error);

    r = Esys_PCR_Reset(
        esys_context,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);

    goto_if_error(r, "Error: PCR_Reset", error);

    TPM2B_EVENT eventData = { .size = 20,
                              .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                       1, 2, 3, 4, 5, 6, 7, 8, 9}};
    TPML_DIGEST_VALUES *digestsEvent;

    r = Esys_PCR_Event(
        esys_context,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &eventData,
        &digestsEvent);

    goto_if_error(r, "Error: PCR_Reset", error);

    TPMI_YES_NO allocationSuccess;
    UINT32 maxPCR;
    UINT32 sizeNeeded;
    UINT32 sizeAvailable;

    r = Esys_PCR_Allocate(
        esys_context,
        ESYS_TR_RH_PLATFORM,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcrSelectionIn,
        &allocationSuccess,
        &maxPCR,
        &sizeNeeded,
        &sizeAvailable);

    if (r == (TPM2_RC_BAD_AUTH | TPM2_RC_S | TPM2_RC_1)) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
    }

    goto_if_error(r, "Error: PCR_Allocate", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;

}
