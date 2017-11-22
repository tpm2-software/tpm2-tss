#include "inttypes.h"
#include "log.h"
#include "sapi-util.h"
#include "test.h"
#include "sapi/tpm20.h"

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

	print_log("\nHIERARCHY_CHANGE_AUTH TESTS:\n" );

	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0);
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Init new auth */
	newAuth.size = 20;
	for( i = 0; i < newAuth.size; i++ )
		newAuth.buffer[i] = i;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Create hmac session */
	sessionsData.auths[0].hmac = newAuth;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 3;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 4;
	/* backup auth value to restore to empty buffer after test */
	resetAuth = newAuth;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Set new auth to zero */
	newAuth.size = 0;
	/* Assert that without setting current auth value the command fails */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* test return value for empty hierarchy */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, 0, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_VALUE))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Set auth to zero again with valid session */
	sessionsData.auths[0].hmac = resetAuth;
	/* change auth value to different value */
	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_OWNER, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

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

	print_log("\nHIERARCHY_CHANGE_AUTH TESTS:\n" );

	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0);
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Init new auth */
	newAuth.size = 20;
	for( i = 0; i < newAuth.size; i++ )
		newAuth.buffer[i] = i;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Create hmac session */
	sessionsData.auths[0].hmac = newAuth;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 3;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Provide current auth value in SessionData hmac field */
	sessionsData.auths[0].hmac = newAuth;
	/* change auth value to different value */
	newAuth.buffer[0] = 4;
	/* backup auth value to restore to empty buffer after test */
	resetAuth = newAuth;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Set new auth to zero */
	newAuth.size = 0;
	/* Assert that without setting current auth value the command fails */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* test return value for empty hierarchy */
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, 0, &sessionsData, &newAuth, 0 );
	if (rval != (TPM2_RC_1 + TPM2_RC_VALUE))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	/* Set auth to zero again with valid session */
	sessionsData.auths[0].hmac = resetAuth;
	/* change auth value to different value */
	newAuth.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, TPM2_RH_PLATFORM, &sessionsData, &newAuth, 0 );
	if (rval != TPM2_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	return 0;
}

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{

	test_platform_auth (sapi_context);
	test_owner_auth (sapi_context);

	return 0;
}
