/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
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
    uint32_t r = 0;

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

    goto_if_error(r, "Error: PCR_Allocate", error);

    return 0;

 error:
    return 1;

}
