//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#ifndef ERROR_HANDLER_H_
#define ERROR_HANDLER_H_

#if defined (__GNUC__)
#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))
#else
#define COMPILER_ATTR(...)
#endif


void
clearbuf(
    char *buffer);

void COMPILER_ATTR(format (printf, 3, 4))
    _catbuf(
        char *buf,
        size_t len,
        const char *fmt,
        ...);

/**
 * Concatenates (safely) onto a static buffer given a format and varaidic
 * arguments similar to sprintf.
 * @param b
 *   The static buffer to concatenate onto.
 * @param fmt
 *   The format specifier as understood by printf followed by the variadic
 *   parameters for the specifier.
 */
#define catbuf(b, fmt, ...) _catbuf(b, sizeof(b), fmt, ##__VA_ARGS__)

#endif /* ERROR_ERROR_HANDLER_H_ */
