#include "inttypes.h"
#include "log.h"
#include "sapi-util.h"
#include "test.h"
#include "sapi/tpm20.h"

int test_0 (TSS2_SYS_CONTEXT *sapi_context);
int test_1 (TSS2_SYS_CONTEXT *sapi_context);

int tpm_hierarchies[] = {TPM_RH_OWNER, TPM_RH_PLATFORM};
// TODO: TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT do not work in test_1

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{

	test_0 (sapi_context);
	test_1 (sapi_context);
	return 0;
}

/*
 * Test basic auth value changes for Platform Auth, Endorsement Auth, Owner Auth
 */
int
test_1 (TSS2_SYS_CONTEXT *sapi_context)
{

	for (int j=0; j<2; j++)
	{

	UINT32 rval;
	TPM2B_AUTH newAuth;
	TPM2B_AUTH resetAuth;
	TPMS_AUTH_COMMAND sessionData;
	TSS2_SYS_CMD_AUTHS sessionsData;
	int i;

	TPMS_AUTH_COMMAND *sessionDataArray[1];

	sessionDataArray[0] = &sessionData;

	sessionsData.cmdAuths = &sessionDataArray[0];

	print_log("\nHIERARCHY_CHANGE_AUTH TESTS:\n" );

	// Init authHandle
	sessionData.sessionHandle = TPM_RS_PW;

	// Init nonce.
	sessionData.nonce.t.size = 0;

	// init hmac
	sessionData.hmac.t.size = 0;

	// Init session attributes
	*( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

	sessionsData.cmdAuthsCount = 1;
	sessionsData.cmdAuths[0] = &sessionData;



	newAuth.t.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0);
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth for hierarchy 0x%x FAILED! Response Code : 0x%x", tpm_hierarchies[j], rval);

	// Init new auth
	newAuth.t.size = 20;
	for( i = 0; i < newAuth.t.size; i++ )
		newAuth.t.buffer[i] = i;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Create hmac session
	sessionData.hmac = newAuth;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Provide current auth value in SessionData hmac field
	sessionData.hmac = newAuth;
	// change auth value to different value
	newAuth.t.buffer[0] = 3;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Provide current auth value in SessionData hmac field
	sessionData.hmac = newAuth;
	// change auth value to different value
	newAuth.t.buffer[0] = 4;
	resetAuth = newAuth;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Set new auth to zero
	newAuth.t.size = 0;
	// Assert that without setting current auth value the command fails
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != (TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	sessionsData.cmdAuths[0] = &sessionData;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != (TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Set auth to zero again with valid session
	sessionData.hmac = resetAuth;
	// change auth value to different value
	newAuth.t.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, tpm_hierarchies[j], &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);
	}

	return 0;
}

/*
 * Test basic auth value changes for Platform Auth
 */
int
test_0 (TSS2_SYS_CONTEXT *sapi_context)
{
	UINT32 rval;
	TPM2B_AUTH newAuth;
	TPM2B_AUTH resetAuth;
	TPMS_AUTH_COMMAND sessionData;
	TSS2_SYS_CMD_AUTHS sessionsData;
	int i;

	TPMS_AUTH_COMMAND *sessionDataArray[1];

	sessionDataArray[0] = &sessionData;

	sessionsData.cmdAuths = &sessionDataArray[0];

	print_log("\nHIERARCHY_CHANGE_AUTH TESTS:\n" );

	// Init authHandle
	sessionData.sessionHandle = TPM_RS_PW;

	// Init nonce.
	sessionData.nonce.t.size = 0;

	// init hmac
	sessionData.hmac.t.size = 0;

	// Init session attributes
	*( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

	sessionsData.cmdAuthsCount = 1;
	sessionsData.cmdAuths[0] = &sessionData;

	int hierarchy = TPM_RH_PLATFORM;

	newAuth.t.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0);
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Init new auth
	newAuth.t.size = 20;
	for( i = 0; i < newAuth.t.size; i++ )
		newAuth.t.buffer[i] = i;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Create hmac session
	sessionData.hmac = newAuth;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Provide current auth value in SessionData hmac field
	sessionData.hmac = newAuth;
	// change auth value to different value
	newAuth.t.buffer[0] = 3;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Provide current auth value in SessionData hmac field
	sessionData.hmac = newAuth;
	// change auth value to different value
	newAuth.t.buffer[0] = 4;
	resetAuth = newAuth;

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Set new auth to zero
	newAuth.t.size = 0;
	// Assert that without setting current auth value the command fails
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != (TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	sessionsData.cmdAuths[0] = &sessionData;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != (TPM_RC_1 + TPM_RC_S + TPM_RC_BAD_AUTH))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, 0, &sessionsData, &newAuth, 0 );
	if (rval != (TPM_RC_1 + TPM_RC_VALUE))
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	// Set auth to zero again with valid session
	sessionData.hmac = resetAuth;
	// change auth value to different value
	newAuth.t.size = 0;
	rval = Tss2_Sys_HierarchyChangeAuth( sapi_context, hierarchy, &sessionsData, &newAuth, 0 );
	if (rval != TPM_RC_SUCCESS)
		print_fail("HierarchyChangeAuth FAILED! Response Code : 0x%x", rval);

	return 0;
}




