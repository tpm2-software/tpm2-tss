/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
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
 ***********************************************************************/
#ifndef TEST_OPTIONS_H
#define TEST_OPTIONS_H

#include <stdint.h>

/* Default TCTI */
#define TCTI_DEFAULT      SOCKET_TCTI
#define TCTI_DEFAULT_STR  "socket"

/* Defaults for Device TCTI */
#define DEVICE_PATH_DEFAULT "/dev/tpm0"

/* Defaults for Socket TCTI connections */
#define HOSTNAME_DEFAULT "127.0.0.1"
#define PORT_DEFAULT     2321

/* environment variables holding TCTI config */
#define ENV_TCTI_NAME      "TPM20TEST_TCTI_NAME"
#define ENV_DEVICE_FILE    "TPM2OTEST_DEVICE_FILE"
#define ENV_SOCKET_ADDRESS "TPM20TEST_SOCKET_ADDRESS"
#define ENV_SOCKET_PORT    "TPM20TEST_SOCKET_PORT"

typedef enum {
    UNKNOWN_TCTI,
    DEVICE_TCTI,
    SOCKET_TCTI,
    N_TCTI,
} TCTI_TYPE;

typedef struct {
    TCTI_TYPE tcti_type;
    char *device_file;
    char *socket_address;
    uint16_t socket_port;
} test_opts_t;

/* functions to get test options from the user and to print helpful stuff */
const char *tcti_name_from_type(TCTI_TYPE tcti_type);
TCTI_TYPE tcti_type_from_name(char const *tcti_str);
int get_test_opts_from_env(test_opts_t * opts);
int sanity_check_test_opts(test_opts_t * opts);
void dump_test_opts(test_opts_t * opts);

#endif                          /* TEST_OPTIONS_H */
