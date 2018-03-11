/*
 * Copyright (c) 2018 Intel Corporation
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
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm20.h"
#include "tss2-tcti/sockets.h"

int
__wrap_socket (
    int domain,
    int type,
    int protocol)
{
    errno = mock_type (int);
    return mock_type (int);
}
int
__wrap_connect (
    int sockfd,
    const struct sockaddr *addr,
    socklen_t addrlen)
{
    errno = mock_type (int);
    return mock_type (int);
}

/* When passed all NULL values ensure that we get back the expected RC. */
static void
socket_connect_test (void **state)
{
    TSS2_RC rc;
    SOCKET sock;

    will_return (__wrap_socket, 0);
    will_return (__wrap_socket, 1);
    will_return (__wrap_connect, 0);
    will_return (__wrap_connect, 1);
    rc = socket_connect ("127.0.0.1", 666, &sock);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
static void
socket_connect_socket_fail_test (void **state)
{
    TSS2_RC rc;
    SOCKET sock;

    will_return (__wrap_socket, EINVAL);
    will_return (__wrap_socket, -1);
    rc = socket_connect ("127.0.0.1", 555, &sock);
    assert_int_equal (rc, TSS2_TCTI_RC_IO_ERROR);
}
static void
socket_connect_connect_fail_test (void **state)
{
    TSS2_RC rc;
    SOCKET sock;

    will_return (__wrap_socket, 0);
    will_return (__wrap_socket, 1);
    will_return (__wrap_connect, ENOTSOCK);
    will_return (__wrap_connect, -1);
    rc = socket_connect ("127.0.0.1", 444, &sock);
    assert_int_equal (rc, TSS2_TCTI_RC_IO_ERROR);
}
int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (socket_connect_test),
        cmocka_unit_test (socket_connect_socket_fail_test),
        cmocka_unit_test (socket_connect_connect_fail_test),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
