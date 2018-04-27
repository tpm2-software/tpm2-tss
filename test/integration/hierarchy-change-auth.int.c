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
#include <stdlib.h>

#include "tss2_sys.h"

#include "inttypes.h"
#define LOGMODULE test
#include "util/log.h"
#include "sapi-util.h"
#include "test.h"

/*
 * Test auth value changes for Owner Auth
 */
int
test_owner_auth (TSS2_SYS_CONTEXT *sapi_context)
{
	UINT32 rval;
	TPM2B_AUTH newAuth;
	TPM2B_AUTH resetAuth;
	int i;

    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = {{.sessionHandle = TPM2_RS_PW,
            .sessionAttributes = 0x00,
            .nonce={.size=0},
            .hmac={.size=0}}}};

	LOG_INFO("HIERARCHY_CHANGE_AUTH TESTS:" );

	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0);
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }

	/* Init new auth */
	newAuth.size = 20;
	for( i = 0; i < newAuth.size; i++ )
		newAuth.buffer[i] = i;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }

	/* Create hmac session */
	sessionsData.auths[0].hmac = newAuth;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }

	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 3;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 4;
	/* backup auth value to restore to empty buffer after test */
	resetAuth = newAuth;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Set new auth to zero */
	newAuth.size = 0;
	/* Assert that without setting current auth value the command fails */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH)) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH)) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* test return value for empty hierarchy */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, 0, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_VALUE)) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Set auth to zero again with valid session */
	sessionsData.auths[0].hmac = resetAuth;
	/* change auth value to different value */
	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	return 0;
}

/*
 * Test auth value changes for Platform Auth
 */
int
test_platform_auth (TSS2_SYS_CONTEXT *sapi_context)
{
	UINT32 rval;
	TPM2B_AUTH newAuth;
	TPM2B_AUTH resetAuth;
	int i;

    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = {{.sessionHandle = TPM2_RS_PW,
            .sessionAttributes = 0x00,
            .nonce={.size=0},
            .hmac={.size=0}}}};

	LOG_INFO("HIERARCHY_CHANGE_AUTH TESTS:" );

	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0);
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Init new auth */
	newAuth.size = 20;
	for( i = 0; i < newAuth.size; i++ )
		newAuth.buffer[i] = i;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Create hmac session */
	sessionsData.auths[0].hmac = newAuth;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 3;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 4;
	/* backup auth value to restore to empty buffer after test */
	resetAuth = newAuth;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Set new auth to zero */
	newAuth.size = 0;
	/* Assert that without setting current auth value the command fails */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH)) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH)) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* test return value for empty hierarchy */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, 0, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_VALUE)) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	/* Set auth to zero again with valid session */
	sessionsData.auths[0].hmac = resetAuth;
	/* change auth value to different value */
	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS) {
		LOG_ERROR("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
        exit(1);
    }
	return 0;
}

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{

	test_platform_auth (sapi_context);
	test_owner_auth (sapi_context);

	return 0;
}
