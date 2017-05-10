#define SESSIONS_COUNT 1

// Skipping to avoid unexpected return code of 0x184 (where 0xb018b is expected)
// when calling Tss2_Sys_PolicyLocality() with badSessionHandle
// around line 1534
#define SKIP_BAD_HANDLE_TEST

// Skipping to avoid buffer overflow crash 
#define SKIP_RECEIVE_IO_ERROR_TEST

// Skipping to avoid TPM Error 0x903 when StartAuthSessionWithParams() for auditSession
// around line 6240
#define SKIP_CMD_RSP_AUTH_TEST

// Skipping to avoid TPM Error 0x902 when Tss2_Sys_CreatePrimary() with outPublic.t.size = 0
// around line 7112
#define SKIP_TEST_CREATE1_TEST

// Skipping to avoid TPM Error 0x98e when Tss2_Sys_NV_Write()
// around line 4841
#define SKIP_SIMPLE_HMAC_OR_POLCY_FALSE_TEST

// Skipping to avoid TPM Error 0x902 when Tss2_Sys_HashSequenceStart()
// around line 3292
#define SKIP_HASH_TEST

// Skipping to vaoid TPM Error 0x902 when TpmHashSequence()
// around line 2856
#define SKIP_PASSWORD_PCR_POLICY_TEST

// Skipping to avoid TPM Error 0x902 when ComputeCommandHmacs()
// around line 2999
#define SKIP_AUTH_VALUE_POLICY_TEST

// Skipping to avoid InitSocketTctiContext() hung
// around line 2571
#define SKIP_EVICT_TEST

// Skipping to avoid TPM Error 0x902 when ComputeCommandHmacs() in HmacSessionTest()
// around line 5211
#define SKIP_UNBOUND_UNSALTED_HMAC_TEST

// Skipping to avoid Application Error 0x50102 when StartAuthSessionWithParams() in HMacSessionTest()
// around line 5159
#define SKIP_BOUND_SESSION_HMAC_TEST

// Skipping to avoid Application Error 0x50102 when StartAuthSessionWithParams() in HMacSessionTest()
// around line 5159
#define SKIP_SALTED_SESSION_HMAC_TEST

// Skipping to avoid Application Error 0x50102 when StartAuthSessionWithParams() in HMacSessionTest()
// around line 5159
#define SKIP_BOUND_SALTED_SESSION_HMAC_TEST

// Skipping to avoid hang
#define SKIP_RM_TEST

// Skip go avoid error TCTI Error 0xa000 when RmZeroSizedResponseTest is run
#define SKIP_RM_ZERO_SIZED_RESPONSE_TEST
