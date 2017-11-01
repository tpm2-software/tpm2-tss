//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include "sapi/tpm20.h"
#include "sample.h"
#include "../integration/sapi-util.h"
#include <stdlib.h>

#define SESSIONS_ARRAY_COUNT MAX_NUM_SESSIONS+1

typedef struct _SESSION_LIST_ENTRY *SESSION_LIST_ENTRY_PTR;

typedef struct _SESSION_LIST_ENTRY{
    SESSION session;
    SESSION_LIST_ENTRY_PTR nextEntry;
} SESSION_LIST_ENTRY;

SESSION_LIST_ENTRY *sessionsList = 0;
INT16 sessionEntriesUsed = 0;


TPM_RC AddSession( SESSION_LIST_ENTRY **sessionEntry )
{
    SESSION_LIST_ENTRY **lastEntry, *newEntry;

//    DebugPrintf( 0, "In AddSession\n" );

    // find end of list.
    for( lastEntry = &sessionsList; *lastEntry != 0; lastEntry = &( (SESSION_LIST_ENTRY *)*lastEntry)->nextEntry )
        ;

    // allocate space for session structure.
    newEntry = (SESSION_LIST_ENTRY *)malloc( sizeof( SESSION_LIST_ENTRY ) );
    if( newEntry != 0 )
    {
        *sessionEntry = *lastEntry = newEntry;
        newEntry->nextEntry = 0;
        sessionEntriesUsed++;
        return TPM_RC_SUCCESS;
    }
    else
    {
        return TSS2_APP_RC_SESSION_SLOT_NOT_FOUND;
    }
}


void DeleteSession( SESSION *session )
{
    SESSION_LIST_ENTRY *predSession;
    SESSION_LIST_ENTRY *newNextEntry;

//    DebugPrintf( 0, "In DeleteSession\n" );

    if( session == &sessionsList->session )
        sessionsList = 0;
    else
    {
        // Find predecessor.
        for( predSession = sessionsList;
                predSession != 0 && &( ( ( SESSION_LIST_ENTRY *)predSession->nextEntry )->session ) != session;
                predSession = predSession->nextEntry )
            ;

        if( predSession != 0 )
        {
            sessionEntriesUsed--;

            newNextEntry = ( (SESSION_LIST_ENTRY *)predSession->nextEntry)->nextEntry;

            free( predSession->nextEntry );

            predSession->nextEntry = newNextEntry;
        }
    }
}


TPM_RC GetSessionStruct( TPMI_SH_AUTH_SESSION sessionHandle, SESSION **session )
{
    TPM_RC rval = TSS2_APP_RC_GET_SESSION_STRUCT_FAILED;
    SESSION_LIST_ENTRY *sessionEntry;

    DebugPrintf( 0, "In GetSessionStruct\n" );

    if( session != 0 )
    {
        //
        // Get pointer to session structure using the sessionHandle
        //
        for( sessionEntry = sessionsList;
                sessionEntry != 0 && sessionEntry->session.sessionHandle != sessionHandle;
                sessionEntry = sessionEntry->nextEntry )
            ;

        if( sessionEntry != 0 )
        {
            *session = &sessionEntry->session;
            rval = TSS2_RC_SUCCESS;
        }
    }
    return rval;
}

TPM_RC GetSessionAlgId( TPMI_SH_AUTH_SESSION sessionHandle, TPMI_ALG_HASH *sessionAlgId )
{
    TPM_RC rval = TSS2_APP_RC_GET_SESSION_ALG_ID_FAILED;
    SESSION *session;

    DebugPrintf( 0, "In GetSessionAlgId\n" );

    rval = GetSessionStruct( sessionHandle, &session );

    if( rval == TSS2_RC_SUCCESS )
    {
        *sessionAlgId = session->authHash;
        rval = TSS2_RC_SUCCESS;
    }

    return rval;
}

void RollNonces( SESSION *session, TPM2B_NONCE *newNonce  )
{
    session->nonceOlder = session->nonceNewer;
    session->nonceNewer = *newNonce;
}


//
// This is a wrapper function around the TPM2_StartAuthSession command.
// It performs the command, calculates the session key, and updates a
// SESSION structure.
//
TPM_RC StartAuthSession( SESSION *session, TSS2_TCTI_CONTEXT *tctiContext )
{
    TPM_RC rval;
    TPM2B_ENCRYPTED_SECRET key;
    char label[] = "ATH";
    TSS2_SYS_CONTEXT *tmpSysContext;
    UINT16 bytes;
    int i;

    key.size = 0;

    tmpSysContext = InitSysContext( 1000, tctiContext, &abiVersion );
    if( tmpSysContext == 0 )
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;

    if( session->nonceOlder.size == 0 )
    {
        session->nonceOlder.size = GetDigestSize( TPM_ALG_SHA1 );
        for( i = 0; i < session->nonceOlder.size; i++ )
            session->nonceOlder.buffer[i] = 0;
    }

    session->nonceNewer.size = session->nonceOlder.size;
    rval = Tss2_Sys_StartAuthSession( tmpSysContext, session->tpmKey, session->bind, 0,
            &( session->nonceOlder ), &( session->encryptedSalt ), session->sessionType,
            &( session->symmetric ), session->authHash, &( session->sessionHandle ),
            &( session->nonceNewer ), 0 );

    if( rval == TPM_RC_SUCCESS )
    {
        if( session->tpmKey == TPM_RH_NULL )
            session->salt.size = 0;
        if( session->bind == TPM_RH_NULL )
            session->authValueBind.size = 0;

        if( session->tpmKey == TPM_RH_NULL && session->bind == TPM_RH_NULL )
        {
            session->sessionKey.size = 0;
        }
        else
        {
            // Generate the key used as input to the KDF.
            rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&key, (TPM2B *)&session->authValueBind);
            if( rval != TPM_RC_SUCCESS )
            {
                TeardownSysContext( &tmpSysContext );
                return(  rval );
            }

            rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&key, (TPM2B *)&session->salt);
            if( rval != TPM_RC_SUCCESS )
            {
                TeardownSysContext( &tmpSysContext );
                return( rval );
            }

            bytes = GetDigestSize( session->authHash );

            if( key.size == 0 )
            {
                session->sessionKey.size = 0;
            }
            else
            {
                rval = KDFa(session->authHash, (TPM2B *)&key, label, (TPM2B *)&session->nonceNewer,
                            (TPM2B *)&session->nonceOlder, bytes * 8, (TPM2B_MAX_BUFFER *)&session->sessionKey);
            }

            if( rval != TPM_RC_SUCCESS )
            {
                TeardownSysContext( &tmpSysContext );
                return( TSS2_APP_RC_CREATE_SESSION_KEY_FAILED );
            }
        }

        session->nonceTpmDecrypt.size = 0;
        session->nonceTpmEncrypt.size = 0;
        session->nvNameChanged = 0;
    }

    TeardownSysContext( &tmpSysContext );

    return rval;
}

//
// This version of StartAuthSession initializes the fields
// of the session structure using the passed in
// parameters, then calls StartAuthSession
// with just a pointer to the session structure.
// This allows all params to be set in one line of code when
// the function is called; cleaner this way, for
// some uses.
//
TPM_RC StartAuthSessionWithParams( SESSION **session,
    TPMI_DH_OBJECT tpmKey, TPM2B_MAX_BUFFER *salt,
    TPMI_DH_ENTITY bind, TPM2B_AUTH *bindAuth, TPM2B_NONCE *nonceCaller,
    TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM_SE sessionType, TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH algId,
    TSS2_TCTI_CONTEXT *tctiContext )
{
    TPM_RC rval;
    SESSION_LIST_ENTRY *sessionEntry;

    if (session == NULL) {
        return TSS2_APP_RC_BAD_REFERENCE;
    }

    rval = AddSession( &sessionEntry );
    if( rval == TSS2_RC_SUCCESS )
    {
        *session = &sessionEntry->session;

        // Copy handles to session struct.
        (*session)->bind = bind;
        (*session)->tpmKey = tpmKey;

        // Copy nonceCaller to nonceOlder in session struct.
        // This will be used as nonceCaller when StartAuthSession
        // is called.
        CopySizedByteBuffer((TPM2B *)&(*session)->nonceOlder, (TPM2B *)nonceCaller);

        // Copy encryptedSalt
        CopySizedByteBuffer((TPM2B *)&(*session)->encryptedSalt, (TPM2B *)encryptedSalt);

        // Copy sessionType.
        (*session)->sessionType = sessionType;

        // Init symmetric.
        (*session)->symmetric.algorithm = symmetric->algorithm;
        (*session)->symmetric.keyBits.sym = symmetric->keyBits.sym;
        (*session)->symmetric.mode.sym = symmetric->mode.sym;
        (*session)->authHash = algId;

        // Copy bind' authValue.
        if( bindAuth == 0 )
        {
            (*session)->authValueBind.size = 0;
        }
        else
        {
            CopySizedByteBuffer((TPM2B *)&(*session)->authValueBind, (TPM2B *)bindAuth);
        }

        // Calculate sessionKey
        if( (*session)->tpmKey == TPM_RH_NULL )
        {
            (*session)->salt.size = 0;
        }
        else
        {
            CopySizedByteBuffer((TPM2B *)&(*session)->salt, (TPM2B *)salt);
        }

        if( (*session)->bind == TPM_RH_NULL )
            (*session)->authValueBind.size = 0;

        rval = StartAuthSession( *session, tctiContext );
        if( rval != TSS2_RC_SUCCESS )
        {
            DeleteSession( *session );
        }
    }
    else
    {
        DeleteSession( *session );
    }
    return( rval );
}

TPM_RC EndAuthSession( SESSION *session )
{
    TPM_RC rval = TPM_RC_SUCCESS;

    DeleteSession( session );

    return rval;
}

