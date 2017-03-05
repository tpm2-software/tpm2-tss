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

#include <stdio.h>
#include "sapi/tpm20.h"

#include "criticalsection.h"
#include "debug.h"

//
// This function starts a critical section, e.g. some code that must
// not be interfered with.
//
// Currently this is used to grant a single connection exclusive
// access to the TPM.  But it could be used for other critical sections
// as well.
//
TSS2_RC StartCriticalSection( TPM_MUTEX *tpmMutex, char *dbgString )
{
	TSS2_RC rval = TSS2_RC_SUCCESS;
	UINT8 mutexAcquired = 0;
	DWORD mutexWaitRetVal;

	// Critical section starts here--take the mutex.
	mutexWaitRetVal = WaitForSingleObject( *tpmMutex, MILLISECOND_WAIT );
	if( mutexWaitRetVal != WAIT_OBJECT_0 )
	{
		rval = TSS2_TCTI_RC_TRY_AGAIN;
	}
	else
	{
		mutexAcquired = 1;
	}

#ifdef DEBUG_MUTEX
	if( mutexAcquired )
	{
		DebugPrintf(NO_PREFIX, "In %s, acquired mutex\n", dbgString );
	}
	else
	{
		DebugPrintf(NO_PREFIX, "In %s, failed to release mutex error: %d\n", dbgString, GetLastError() );
	}
#endif

	return rval;
}

//
// This function ends the critical section.
//
TSS2_RC EndCriticalSection( TPM_MUTEX *tpmMutex, char *dbgString )
{
	TSS2_RC rval = TSS2_RC_SUCCESS;
	UINT8 mutexReleased = 0;

	if( 0 == ReleaseMutex( *tpmMutex ) )
	{
		rval = TSS2_TCTI_RC_TRY_AGAIN;
	}
	else
	{
		mutexReleased = 1;
	}

#ifdef DEBUG_MUTEX
	if( mutexReleased )
	{
		DebugPrintf(NO_PREFIX, "In %s, released mutex\n", dbgString );
	}
	else
	{
		DebugPrintf(NO_PREFIX, "In %s, failed to release mutex error: %d\n", dbgString, GetLastError() );
	}
#endif

	return rval;
}
