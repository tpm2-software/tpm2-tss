#include "tss2_esys.h"

#define goto_error_if_not_failed(rc,msg,label)                          \
	if (rc == TSS2_RC_SUCCESS) {                                        \
		LOG_ERROR("Error %s (%x) in Line %i: \n", msg, __LINE__, rc);   \
		goto label; }


/*
 * This is the prototype for all integration tests in the tpm2-tss
 * project. Integration tests are intended to exercise the combined
 * components in the software stack. This typically means executing some
 * SAPI function using the socket TCTI to communicate with a software
 * TPM2 simulator.
 * Return values:
 * A successful test will return 0, any other value indicates failure.
 */

int test_invoke_esapi(ESYS_CONTEXT * sapi_context);
