#include "sapi/tpm20.h"

#define CheckPassed(rval) {				\
    							\
    DebugPrintf( NO_PREFIX, "\tpassing case:  " );			\
    if ( rval != TPM2_RC_SUCCESS) {					\
      ErrorHandler( rval);						\
      DebugPrintf( NO_PREFIX, "\tFAILED!  %s (%s@%u)\n",		\
		   errorString, __FUNCTION__, __LINE__ );		\
      Cleanup();							\
    } else {								\
      DebugPrintf( NO_PREFIX, "\tPASSED! (%s@%u)\n",			\
		   __FUNCTION__, __LINE__);				\
    }									\
    									\
    Delay(0);							\
  }

#define CheckFailed(rval, expectedTpmErrorCode) {			\
    DebugPrintf( NO_PREFIX, "\tfailing case:");				\
    if ( rval != expectedTpmErrorCode) {				\
      ErrorHandler( rval);						\
      DebugPrintf( NO_PREFIX, "\tFAILED!  Ret code s/b: 0x%x, but was: 0x%x (%s@%u)\n", \
		   expectedTpmErrorCode, rval, __FUNCTION__, __LINE__ ); \
      Cleanup();							\
    }	else {								\
      DebugPrintf( NO_PREFIX, "\tPASSED! (%s@%u)\n",			\
		   __FUNCTION__, __LINE__);				\
    }									\
    Delay(0);							\
  }

/*
 * This is the prototype for all integration tests in the tpm2-tss
 * project. Integration tests are intended to exercise the combined
 * components in the software stack. This typically means executing some
 * SAPI function using the socket TCTI to communicate with a software
 * TPM2 simulator.
 * Return values:
 * A successful test will return 0, any other value indicates failure.
 */
int test_invoke (TSS2_SYS_CONTEXT *sapi_context);
