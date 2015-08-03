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

#ifndef ENDIANCONV_H
#define ENDIANCONV_H

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files !
#endif  /* TSS2_API_VERSION_1_1_1_1 */


#ifdef __cplusplus
extern "C" {
#endif


//
// Comment out following line for big endian CPUs.
//
#define LITTLE_ENDIAN_CPU

#ifdef LITTLE_ENDIAN_CPU

UINT64 ChangeEndianQword( UINT64 p );
UINT32 ChangeEndianDword( UINT32 p );
UINT16 ChangeEndianWord( UINT16 p );

// CPU is little endian, so bytes need to be swapped.
#define CHANGE_ENDIAN_WORD(p) ( ChangeEndianWord (p) )

#define CHANGE_ENDIAN_DWORD(p) ( ChangeEndianDword(p) )

#define CHANGE_ENDIAN_QWORD(p) ( ChangeEndianQword(p) )
#else
 // If CPU is big-endian, no need to do endianness swapping.

#define CHANGE_ENDIAN_WORD(p)  p

#define CHANGE_ENDIAN_DWORD(p) p

#define CHANGE_ENDIAN_QWORD(p) p
#endif

#ifdef __cplusplus
}
#endif

#endif
