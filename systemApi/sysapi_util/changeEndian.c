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

#include <tpm20.h>   
#include <tss2_sysapi_util.h>

UINT64 ChangeEndianQword( UINT64 p )
{
    return( ((const UINT64)(((p)& 0xFF) << 56))    | \
          ((const UINT64)(((p)& 0xFF00) << 40))   | \
          ((const UINT64)(((p)& 0xFF0000) << 24)) | \
          ((const UINT64)(((p)& 0xFF000000) << 8)) | \
          ((const UINT64)(((p)& 0xFF00000000) >> 8)) | \
          ((const UINT64)(((p)& 0xFF0000000000) >> 24)) | \
          ((const UINT64)(((p)& 0xFF000000000000) >> 40)) | \
          ((const UINT64)(((p)& 0xFF00000000000000) >> 56)) );
}

UINT32 ChangeEndianDword( UINT32 p )
{
    return( ((const UINT32)(((p)& 0xFF) << 24))    | \
          ((const UINT32)(((p)& 0xFF00) << 8))   | \
          ((const UINT32)(((p)& 0xFF0000) >> 8)) | \
          ((const UINT32)(((p)& 0xFF000000) >> 24)));
}

UINT16 ChangeEndianWord( UINT16 p )
{
    return( ((const UINT16)(((p)& 0xFF) << 8)) | ((const UINT16)(((p)& 0xFF00) >> 8)));
}

