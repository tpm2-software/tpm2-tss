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
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "tss2_tpm2_types.h"

#include "io.h"
#define LOGMODULE tcti
#include "util/log.h"

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
    if (ret < size) {
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
    struct sockaddr_in sockaddr = { 0 };
    int ret = 0;

    if (hostname == NULL || sock == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    LOG_DEBUG ("Creating AF_INET stream socket");
    *sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*sock == -1) {
        LOG_WARNING ("Failed to create socket. errno %d: %s",
                     errno, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr (hostname);
    sockaddr.sin_port = htons (port);

    LOG_DEBUG ("Connecting socket %d to hostname %s on port %" PRIu16,
               *sock, hostname, port);
    ret = connect (*sock, (struct sockaddr*)&sockaddr, sizeof (sockaddr));
    if (ret == -1) {
        LOG_WARNING ("Failed to connect to host %s on port %" PRIu16 ", errno "
                     "%d: %s", hostname, port, errno, strerror (errno));
        socket_close (sock);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}
