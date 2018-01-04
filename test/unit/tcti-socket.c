//**********************************************************************;
// Copyright (c) 2017 Intel Corporation
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

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tpm20.h"
#include "tcti/tcti.h"
#include "tcti/tcti_socket.h"

/* When passed all NULL values ensure that we get back the expected RC. */
static void
tcti_socket_init_all_null_test (void **state)
{
    TSS2_RC rc;

    rc = InitSocketTcti (NULL, NULL, NULL, 0);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
/*
 * Determine the size of a TCTI context structure. Requires calling the
 * initialization function for the device TCTI with the first parameter
 * (the TCTI context) NULL.
 */
static void
tcti_socket_init_size_test (void **state)
{
    size_t tcti_size = 0;
    TSS2_RC ret = TSS2_RC_SUCCESS;

    ret = InitSocketTcti (NULL, &tcti_size, NULL, 0);
    assert_int_equal (ret, TSS2_RC_SUCCESS);
    assert_int_equal (tcti_size, sizeof (TSS2_TCTI_CONTEXT_INTEL));
}
/*
 * When passed a non-NULL context blob and size the config structure must
 * also be non-NULL. No way to initialize the TCTI otherwise.
 */
static void
tcti_socket_init_null_config_test (void **state)
{
    size_t tcti_size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT_INTEL tcti_intel = { 0 };
    TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)&tcti_intel;

    rc = InitSocketTcti (tcti_context, &tcti_size, NULL, 0);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
/*
 * Wrap the 'connect' system call. The mock queue for this function must have
 * an integer to return as a response.
 */
int
__wrap_connect (int                    sockfd,
                const struct sockaddr *addr,
                socklen_t              addrlen)
{
    return mock_type (int);
}
/*
 * Wrap the 'recv' system call. The mock queue for this function must have an
 * integer return value (the number of byts recv'd), as well as a pointer to
 * a buffer to copy data from to return to the caller.
 */
ssize_t
__wrap_recv (int sockfd,
             void *buf,
             size_t len,
             int flags)
{
    ssize_t  ret = mock_type (ssize_t);
    uint8_t *buf_in = mock_ptr_type (uint8_t*);

    memcpy (buf, buf_in, ret);
    return ret;
}
/*
 * Wrap the 'select' system call. The mock queue for this function must have
 * an integer to return as a response (the # of fds ready to be read /
 * written).
 */
int
__wrap_select (int             nfds,
               fd_set         *readfds,
               fd_set         *writefds,
               fd_set         *exceptfds,
               struct timeval *timeout)
{
    return mock_type (int);
}
/*
 * Wrap the 'send' system call. The mock queue for this function must have an
 * integer to return as a response.
 */
ssize_t
__wrap_send (int         sockfd,
             const void *buf,
             size_t      len,
             int         flags)

{
    return mock_type (TSS2_RC);
}
/*
 * This is a utility function used by other tests to setup a TCTI context. It
 * effectively wraps the init / allocate / init pattern as well as priming the
 * mock functions necessary for a the successful call to 'InitSocketTcti'.
 */
static TSS2_TCTI_CONTEXT*
tcti_socket_init_from_conf (TCTI_SOCKET_CONF *conf)
{
    size_t tcti_size = 0;
    uint8_t recv_buf[4] = { 0 };
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    ret = InitSocketTcti (NULL, &tcti_size, NULL, 0);
    assert_true (ret == TSS2_RC_SUCCESS);
    ctx = calloc (1, tcti_size);
    assert_non_null (ctx);
    /*
     * two calls to connect, one for the data socket, one for the command
     * socket
     */
    will_return (__wrap_connect, 0);
    will_return (__wrap_connect, 0);
    /*
     * two 'PlatformCommands are sent on initialization, 4 bytes sent for
     * each, 4 byte response received (all 0's) for each.
     */
    will_return (__wrap_send, 4);
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, recv_buf);
    will_return (__wrap_send, 4);
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, recv_buf);
    ret = InitSocketTcti (ctx, &tcti_size, conf, 0);
    assert_int_equal (ret, TSS2_RC_SUCCESS);
    return ctx;
}

/*
 * This is a utility function to setup the "default" TCTI context.
 */
static int
tcti_socket_setup (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_SOCKET_CONF conf = {
        .hostname          = "localhost",
        .port              = 666,
    };

    ctx = tcti_socket_init_from_conf (&conf);
    *state = ctx;
    return 0;
}
/*
 * This is a utility function to teardown a TCTI context allocated by the
 * tcti_socket_setup function.
 */
static int
tcti_socket_teardown (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;

    Tss2_Tcti_Finalize (ctx);
    free (ctx);
    return 0;
}
/*
 * This test exercises the successful code path through the receive function.
 */
static void
tcti_socket_receive_success_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    size_t response_size = 0xc;
    uint8_t response_in [] = { 0x80, 0x02,
                               0x00, 0x00, 0x00, 0x0c,
                               0x00, 0x00, 0x00, 0x00,
                               0x01, 0x02,
    /* simulator appends 4 bytes of 0's to every response */
                               0x00, 0x00, 0x00, 0x00 };
    uint8_t response_out [12] = { 0 };
    uint8_t platform_command_recv [4] = { 0 };

    /* select returns 1 fd ready for recv-ing */
    will_return (__wrap_select, 1);
    /* receive response size */
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, &response_in [2]);
    /* receive tag */
    will_return (__wrap_recv, 2);
    will_return (__wrap_recv, response_in);
    /* receive size (again)  */
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, &response_in [2]);
    /* receive the rest of the command */
    will_return (__wrap_recv, 0xc - sizeof (TPM2_ST) - sizeof (UINT32));
    will_return (__wrap_recv, &response_in [6]);
    /* receive the 4 bytes of 0's appended by the simulator */
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, &response_in [12]);
    /* platform command sends 4 bytes and receives the same */
    will_return (__wrap_send, 4);
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, platform_command_recv);

    rc = Tss2_Tcti_Receive (ctx, &response_size, response_out, TSS2_TCTI_TIMEOUT_BLOCK);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_memory_equal (response_in, response_out, response_size);
}
/*
 * This test exercises the successful code path through the transmit function.
 */
static void
tcti_socket_transmit_success_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    uint8_t command [] = { 0x80, 0x02,
                           0x00, 0x00, 0x00, 0x0c,
                           0x00, 0x00, 0x00, 0x00,
                           0x01, 0x02 };
    size_t  command_size = sizeof (command);

    /* send the TPM2_SEND_COMMAND code */
    will_return (__wrap_send, 4);
    /* send the locality for the command */
    will_return (__wrap_send, 1);
    /* send the number of bytes in command */
    will_return (__wrap_send, 4);
    /* send the command buffer */
    will_return (__wrap_send, 0xc);
    rc = Tss2_Tcti_Transmit (ctx, command_size, command);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_socket_init_all_null_test),
        cmocka_unit_test (tcti_socket_init_size_test),
        cmocka_unit_test (tcti_socket_init_null_config_test),
        cmocka_unit_test_setup_teardown (tcti_socket_receive_success_test,
                                  tcti_socket_setup,
                                  tcti_socket_teardown),
        cmocka_unit_test_setup_teardown (tcti_socket_transmit_success_test,
                                  tcti_socket_setup,
                                  tcti_socket_teardown)
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
