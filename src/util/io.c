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
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "tss2_tpm2_types.h"

#include "io.h"
#define LOGMODULE tcti
#include "util/log.h"

#define MAX_PORT_STR_LEN    sizeof("65535")

ssize_t
read_all (
    int fd,
    uint8_t *data,
    size_t size)
{
    ssize_t recvd;
    size_t recvd_total = 0;

    LOG_DEBUG ("reading %zu bytes from fd %d to buffer at 0x%" PRIxPTR,
               size, fd, (uintptr_t)data);
    do {
        recvd = TEMP_RETRY (read (fd, &data [recvd_total], size));
        if (recvd < 0) {
            LOG_WARNING ("read on fd %d failed with errno %d: %s",
                         fd, errno, strerror (errno));
            return recvd_total;
        }
        LOGBLOB_DEBUG (&data [recvd_total], recvd, "read %zd bytes from fd %d:", recvd, fd);
        recvd_total += recvd;
        size -= recvd;
    } while (size > 0);

    return recvd_total;
}

ssize_t
write_all (
    int fd,
    const uint8_t *buf,
    size_t size)
{
    ssize_t written = 0;
    size_t written_total = 0;

    do {
        LOG_DEBUG("writing %zu bytes starting at 0x%" PRIxPTR " to fd %d",
                  size - written_total,
                  (uintptr_t)buf + written_total,
                  fd);
        written = TEMP_RETRY (write (fd,
                                     (const char*)&buf [written_total],
                                     size - written_total));
        if (written >= 0) {
            LOG_DEBUG ("wrote %zd bytes to fd %d", written, fd);
            written_total += (size_t)written;
        } else {
            LOG_ERROR ("failed to write to fd %d: %s", fd, strerror (errno));
            return written_total;
        }
    } while (written_total < size);

    return (ssize_t)written_total;
}

ssize_t
socket_recv_buf (
    SOCKET sock,
    uint8_t *data,
    size_t size)
{
    return read_all (sock, data, size);
}

TSS2_RC
socket_xmit_buf (
    SOCKET sock,
    const void *buf,
    size_t size)
{
    int ret;

    LOGBLOB_DEBUG (buf, size, "Writing %zu bytes to socket %d:", size, sock);
    ret = write_all (sock, buf, size);
    if (ret < (ssize_t) size) {
        LOG_ERROR("write to fd %d failed, errno %d: %s", sock, errno, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
socket_close (
    SOCKET *socket)
{
    int ret;

    if (socket == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (*socket == -1) {
        return TSS2_RC_SUCCESS;
    }
    ret = close (*socket);
    if (ret == -1) {
        LOG_WARNING ("Failed to close SOCKET %d. errno %d: %s",
                     *socket, errno, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    *socket = -1;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
socket_connect (
    const char *hostname,
    uint16_t port,
    SOCKET *sock)
{
    static const struct addrinfo hints = { .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC, .ai_protocol = IPPROTO_TCP};
    struct addrinfo *retp = NULL;
    struct addrinfo *p;
    char port_str[MAX_PORT_STR_LEN];
    int ret = 0;
    char host_buff[_POSIX_HOST_NAME_MAX] __attribute__((unused));
    const char *h __attribute__((unused)) = hostname;

    if (hostname == NULL || sock == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    ret = snprintf(port_str, sizeof(port_str), "%u", port);
    if (ret < 0)
        return TSS2_TCTI_RC_BAD_VALUE;


    LOG_DEBUG ("Resolving host %s", hostname);
    ret = getaddrinfo (hostname, port_str, &hints, &retp);
    if (ret != 0) {
        LOG_WARNING ("Host %s does not resolve to a valid address: %d: %s",
            hostname, ret, gai_strerror(ret));
        return TSS2_TCTI_RC_IO_ERROR;
    }

    for (p = retp; p != NULL; p = p->ai_next) {
        *sock = socket (p->ai_family, SOCK_STREAM, 0);
        if (*sock == -1)
            continue;

        h = inet_ntop(p->ai_family, p->ai_addr, &host_buff[0],
            sizeof(host_buff));
        if (h == NULL)
            h = hostname;
        LOG_DEBUG ("Attempting TCP connection to host %s, port %s",
            h, port_str);
        if (connect (*sock, p->ai_addr, p->ai_addrlen) != -1)
            break; /* socket connected OK */
        socket_close(sock);
    }
    freeaddrinfo (retp);
    if (p == NULL) {
        LOG_WARNING ("Failed to connect to host %s, port %s: errno %d: %s",
            h, port_str, errno, strerror (errno));

        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}
