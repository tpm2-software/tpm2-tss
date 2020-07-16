/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 */
#ifndef UTIL_IO_H
#define UTIL_IO_H

#ifdef _WIN32
#include <BaseTsd.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SSIZE_T ssize_t;
#define _HOST_NAME_MAX MAX_COMPUTERNAME_LENGTH

#else
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#define _HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

#include "tss2_tpm2_types.h"

#ifdef _WIN32
#define TEMP_RETRY(dest, exp) \
{   int __ret; \
    do { \
        __ret = exp; \
    } while (__ret == SOCKET_ERROR && WSAGetLastError() == WSAEINTR); \
    dest = __ret; }
#else
#define TEMP_RETRY(dest, exp) \
{   int __ret; \
    do { \
        __ret = exp; \
    } while (__ret == SOCKET_ERROR && errno == EINTR); \
    dest =__ret; }
#endif

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
    SOCKET fd,
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
    SOCKET fd,
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
TSS2_RC
socket_set_nonblock (
    SOCKET *sock);
ssize_t
socket_recv_buf (
    SOCKET sock,
    uint8_t *data,
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
