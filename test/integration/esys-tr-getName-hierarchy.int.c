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

#include "tss2_mu.h"
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

    TPM2B_NAME name1, *name2;
    size_t offset = 0;

    r = Tss2_MU_TPM2_HANDLE_Marshal(TPM2_RH_OWNER, &name1.name[0],
                                    sizeof(name1.name), &offset);
    goto_if_error(r, "Marshaling name", error);
    name1.size = offset;

    r = Esys_TR_GetName(ectx, ESYS_TR_RH_OWNER, &name2);
    goto_if_error(r, "TR get name", error);

    if (name1.size != name2->size ||
        memcmp(&name1.name[0], &name2->name[0], name1.size) != 0)
    {
        free(name2);
        LOG_ERROR("Names mismatch between NV_GetPublic and TR_GetName");
        return 1;
    }

    free(name2);

    return 0;

 error:
    return 1;
}
