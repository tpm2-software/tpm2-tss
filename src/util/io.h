/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef UTIL_IO_H
#define UTIL_IO_H
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "tss2_tpm2_types.h"

#define SOCKET int
#define TEMP_RETRY(exp) \
({  int __ret; \
    do { \
        __ret = exp; \
    } while (__ret == -1 && errno == EINTR); \
    __ret; })

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Read 'size' bytes from file descriptor 'fd' into buffer 'buf'. Additionally
 * this function will retry calls to the 'read' function when temporary errors
 * are detected. This is currently limited to interrupted system calls and
 * short reads.
 */
ssize_t
read_all (
    int fd,
    uint8_t *data,
    size_t size);
/*
 * Write 'size' bytes from 'buf' to file descriptor 'fd'. Additionally this
 * function will retry calls to the 'write' function when recoverable errors
 * are detected. This is currently limited to interrupted system calls and
 * short writes.
 */
ssize_t
write_all (
    int fd,
    const uint8_t *buf,
    size_t size);
TSS2_RC
socket_connect (
    const char *hostname,
    uint16_t port,
    SOCKET *socket);
TSS2_RC
socket_close (
    SOCKET *socket);
ssize_t
socket_recv_buf (
    SOCKET sock,
    unsigned char *data,
    size_t size);
TSS2_RC
socket_xmit_buf (
    SOCKET sock,
    const void *buf,
    size_t size);

#ifdef __cplusplus
}
#endif
#endif /* UTIL_IO_H */
