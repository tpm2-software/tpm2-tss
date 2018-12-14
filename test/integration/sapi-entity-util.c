/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
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

        /*
         * Exclude HASH_ADD_INT defined in uthash.h from Clang static analysis,
         * see https://github.com/troydhanson/uthash/issues/166
         */
        #ifndef __clang_analyzer__
        HASH_ADD_INT(entities, entityHandle, e);
        #endif
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
