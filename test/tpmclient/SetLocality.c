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

#include "tss2_sys.h"

#include "sample.h"
#include "../integration/sapi-util.h"

TSS2_RC SetLocality( TSS2_SYS_CONTEXT *sysContext, UINT8 locality )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *tctiContext;

    if( sysContext == 0 )
    {
        rval = TSS2_APP_RC_BAD_REFERENCE;
    }
    else if( locality >= 5 && locality <= 31 )
    {
        rval = TSS2_APP_RC_BAD_LOCALITY;
    }
    else
    {
        rval = Tss2_Sys_GetTctiContext( sysContext, &tctiContext );

        if( rval == TSS2_RC_SUCCESS )
        {
            // Set the locality
            rval = (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->setLocality)( tctiContext, locality );
        }
    }

    return rval;
}
