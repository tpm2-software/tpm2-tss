/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for calloc, free, NULL
#include <uthash.h>           // for UT_hash_handle, HASH_FIND_INT, HASH_ADD...

#include "session-util.h"     // for ENTITY, AddEntity, DeleteEntity, GetEntity
#include "sys-util.h"         // for CopySizedByteBuffer
#include "tss2_tpm2_types.h"  // for TPM2_HANDLE, TPM2B_AUTH
#include "util/tpm2b.h"       // for TPM2B

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
