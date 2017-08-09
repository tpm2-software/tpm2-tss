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
#include "sysapi/include/tcti_util.h"
#include "tcti/logging.h"
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
    TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)1;

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
    return (int)mock ();
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
    ssize_t  ret = (ssize_t)mock ();
    uint8_t *buf_in = (uint8_t*)mock ();

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
    return (int)mock ();
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
    return (TSS2_RC)mock ();
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
/* begin tcti_socket_init_log */
/*
 * This test configures the socket TCTI with a logging callback and some user
 * data. It checks to be sure that the initialization function sets the
 * internal data in the TCTI to use / point to this data accordingly.
 */
int
tcti_socket_init_log_callback (void        *data,
                               printf_type  type,
                               const char  *format,
                               ...)
{
    return 0;
}

static void
tcti_socket_init_log_test (void **state)
{
    uint8_t my_data = 0x9;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_SOCKET_CONF conf = {
        "localhost", 666, tcti_socket_init_log_callback, NULL, &my_data
    };

    ctx = tcti_socket_init_from_conf (&conf);
    assert_true (TCTI_LOG_CALLBACK (ctx) == tcti_socket_init_log_callback);
    assert_int_equal (*(uint8_t*)TCTI_LOG_DATA (ctx), my_data);
    if (ctx)
        free (ctx);
}
/* end tcti_socket_init_log */

/* begin tcti_socket_init_buff_log */
/*
 * This test configures the socket TCTI with the buffer logging callback and
 * some user data. It checks to be sure that the initialization function sets
 * the internal data in the TCTI to use / point to this data accordingly.
 */
int
tcti_socket_init_log_buffer_callback (void        *data,
                                      printf_type  type,
                                      uint8_t     *buffer,
                                      uint32_t     length)
{
    return 0;
}

static void
tcti_socket_init_log_buffer_test (void **state)
{
    uint8_t my_data = 0x9;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_SOCKET_CONF conf = {
        "localhost", 666, NULL, tcti_socket_init_log_buffer_callback, &my_data
    };

    ctx = tcti_socket_init_from_conf (&conf);
    assert_true (TCTI_LOG_BUFFER_CALLBACK (ctx) == tcti_socket_init_log_buffer_callback);
    assert_int_equal (*(uint8_t*)TCTI_LOG_DATA (ctx), my_data);
    if (ctx)
        free (ctx);
}
/* end tcti_socket_init_log */

/* begin tcti_socket_log_called_test */
/*
 * This test configures the socket TCTI with a logging callback and some user
 * data. It then invokes the logging function and checks to be sure that the
 * supplied user data is changed in the expected way.
 */
int
tcti_socket_log_called_callback (void        *data,
                                 printf_type  type,
                                 const char  *format,
                                 ...)
{
    *(bool*)data = true;
    return 0;
}

static void
tcti_socket_log_called_test (void **state)
{
    bool called = false;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_SOCKET_CONF conf = {
        "localhost", 666, tcti_socket_log_called_callback, NULL, &called
    };

    ctx = tcti_socket_init_from_conf (&conf);
    TCTI_LOG (ctx, NO_PREFIX, "test log call");
    if (ctx)
        free (ctx);
    assert_true (called);
}
/* end tcti_socket_init_log */
/* begin tcti_socket_log_buffer_called_test */
/*
 * This test configures the socket TCTI with the buffer logging callback and
 * some user data. It checks to be sure that when invoked, the buffer logging
 * callback sets the user data to a known value.
 */
int
tcti_socket_log_buffer_called_callback (void        *data,
                                        printf_type  type,
                                        uint8_t     *buffer,
                                        uint32_t     length)
{
    *(bool*)data = true;
    return 0;
}

static void
tcti_socket_log_buffer_called_test (void **state)
{
    bool called = false;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_SOCKET_CONF conf = {
        "localhost", 666, NULL, tcti_socket_log_buffer_called_callback, &called
    };

    ctx = tcti_socket_init_from_conf (&conf);
    TCTI_LOG_BUFFER (ctx, NO_PREFIX, NULL, 0);
    if (ctx)
        free (ctx);
    assert_true (called);
}
/* end tcti_socket_init_log */

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
        .logCallback       = NULL,
        .logBufferCallback = NULL,
        .logData           = NULL
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

    /* socket TCTI finalize sends two 4 byte "session_end" messages */
    will_return (__wrap_send, 4);
    will_return (__wrap_send, 4);
    tss2_tcti_finalize (ctx);
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
    will_return (__wrap_recv, 0xc - sizeof (TPM_ST) - sizeof (UINT32));
    will_return (__wrap_recv, &response_in [6]);
    /* receive the 4 bytes of 0's appended by the simulator */
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, &response_in [12]);
    /* platform command sends 4 bytes and receives the same */
    will_return (__wrap_send, 4);
    will_return (__wrap_recv, 4);
    will_return (__wrap_recv, platform_command_recv);

    rc = tss2_tcti_receive (ctx, &response_size, response_out, TSS2_TCTI_TIMEOUT_BLOCK);
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

    /* send the TPM_SEND_COMMAND code */
    will_return (__wrap_send, 4);
    /* send the locality for the command */
    will_return (__wrap_send, 1);
    /* send the number of bytes in command */
    will_return (__wrap_send, 4);
    /* send the command buffer */
    will_return (__wrap_send, 0xc);
    rc = tss2_tcti_transmit (ctx, command_size, command);
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
        cmocka_unit_test (tcti_socket_init_log_test),
        cmocka_unit_test (tcti_socket_init_log_buffer_test),
        cmocka_unit_test (tcti_socket_log_called_test),
        cmocka_unit_test (tcti_socket_log_buffer_called_test),
        cmocka_unit_test_setup_teardown (tcti_socket_receive_success_test,
                                  tcti_socket_setup,
                                  tcti_socket_teardown),
        cmocka_unit_test_setup_teardown (tcti_socket_transmit_success_test,
                                  tcti_socket_setup,
                                  tcti_socket_teardown)
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
