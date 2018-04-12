/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
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
#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This tests the Esys_TR_FromTPMPublic and Esys_TR_GetName functions by
 * creating an NV Index and then attempting to retrieve an ESYS_TR object for
 * it. Then we call Esys_TR_GetName to see if the correct public name has been
 * retrieved.
 */

int
test_invoke_esapi(ESYS_CONTEXT * ectx)
{
    uint32_t r = 0;

    ESYS_TR nvHandle;
    TPM2B_NAME *name1, *name2;
    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD,
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 1,
        }
    };

    r = Esys_NV_DefineSpace(ectx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &auth, &publicInfo, &nvHandle);
    goto_if_error(r, "NV define space", error);

    r = Esys_NV_ReadPublic(ectx, nvHandle,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           NULL, &name1);
    goto_if_error(r, "NV read public", error);

    r = Esys_TR_Close(ectx, &nvHandle);
    goto_if_error(r, "TR close on nv object", error_name1);

    r = Esys_TR_FromTPMPublic(ectx, TPM2_NV_INDEX_FIRST,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nvHandle);
    goto_if_error(r, "TR from TPM public", error_name1);

    r = Esys_TR_GetName(ectx, nvHandle, &name2);
    goto_if_error(r, "TR get name", error_name1);

    r = Esys_NV_UndefineSpace(ectx, ESYS_TR_RH_OWNER, nvHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_error(r, "NV UndefineSpace", error_name2);

    if (name1->size != name2->size ||
        memcmp(&name1->name[0], &name2->name[0], name1->size) != 0)
    {
        LOG_ERROR("Names mismatch between NV_GetPublic and TR_GetName");
        goto error_name2;
    }

    free(name1);
    free(name2);

    return 0;

error_name2:
    free(name2);
error_name1:
    free(name1);
error:
    return 1;
}
