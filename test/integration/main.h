
#include "common/debug.h"

#define sprintf_s snprintf
#define errorStringSize 200
char errorString[errorStringSize];


void TeardownTctiContextInt(TSS2_TCTI_CONTEXT **tctiContext);
void DelayInt( UINT16 delay);
void ErrorHandlerInt( UINT32 rval );
void CleanupInt();


#define CheckPassedInt(rval) {				\
    							\
    DebugPrintf( NO_PREFIX, "\tpassing case:  " );			\
    if ( rval != TPM_RC_SUCCESS) {					\
      ErrorHandlerInt( rval);						\
      DebugPrintf( NO_PREFIX, "\tFAILED!  %s (%s@%u)\n",		\
		   errorString, __FUNCTION__, __LINE__ );		\
      CleanupInt();							\
    } else {								\
      DebugPrintf( NO_PREFIX, "\tPASSED! (%s@%u)\n",			\
		   __FUNCTION__, __LINE__);				\
    }									\
    									\
    DelayInt(0);							\
  }


#define CheckFailedInt(rval, expectedTpmErrorCode) {			\
    DebugPrintf( NO_PREFIX, "\tfailing case:");				\
    if ( rval != expectedTpmErrorCode) {				\
      ErrorHandlerInt( rval);						\
      DebugPrintf( NO_PREFIX, "\tFAILED!  Ret code s/b: 0x%x, but was: 0x%x (%s@%u)\n", \
		   expectedTpmErrorCode, rval, __FUNCTION__, __LINE__ ); \
      CleanupInt();							\
    }	else {								\
      DebugPrintf( NO_PREFIX, "\tPASSED! (%s@%u)\n",			\
		   __FUNCTION__, __LINE__);				\
    }									\
    DelayInt(0);							\
  }
