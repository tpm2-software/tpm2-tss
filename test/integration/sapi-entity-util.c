/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
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
 ***********************************************************************/
#include "tss2_tpm2_types.h"
#include "sysapi_util.h"
#include "sapi-util.h"
#include "session-util.h"

static ENTITY *entities = NULL;

int
AddEntity(TPM2_HANDLE handle, TPM2B_AUTH *auth)
{
    ENTITY *e;

    HASH_FIND_INT(entities, &handle, e);

    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e)
            return -1;

        e->entityHandle = handle;
        HASH_ADD_INT(entities, entityHandle, e);
    }
    CopySizedByteBuffer((TPM2B *)&e->entityAuth, (TPM2B *)auth);
    return 0;
}

void
DeleteEntity(TPM2_HANDLE handle)
{
    ENTITY *e;

    HASH_FIND_INT(entities, &handle, e);
    if (!e)
        return;

    HASH_DEL(entities, e);
    free(e);
}

int
GetEntityAuth(TPM2_HANDLE handle, TPM2B_AUTH *auth)
{
    ENTITY *e;

    HASH_FIND_INT(entities, &handle, e);
    if (!e)
        return -1;

    CopySizedByteBuffer((TPM2B *)auth, (TPM2B *)&e->entityAuth);
    return 0;
}

ENTITY *
GetEntity(TPM2_HANDLE handle)
{
    ENTITY *e;

    HASH_FIND_INT(entities, &handle, e);
    return e;
}
