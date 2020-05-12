/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TCTI_NETWORK_H
#define TCTI_NETWORK_H

#include <limits.h>

#include "tcti-common.h"
#include "util/io.h"

/*
 * longest possible conf string:
 * HOST_NAME_MAX + max char uint16 (5) + strlen ("host=,port=") (11)
 */
#define TCTI_NETWORK_CONF_MAX (_HOST_NAME_MAX + 16)
#define TCTI_NETWORK_DEFAULT_HOST "localhost"
#define TCTI_NETWORK_DEFAULT_PORT 29100
#define NETWORK_CONF_DEFAULT_INIT { \
    .host = TCTI_NETWORK_DEFAULT_HOST, \
    .port = TCTI_NETWORK_DEFAULT_PORT, \
}

#define TCTI_NETWORK_MAGIC 0xf05b04cd9f02728dULL

typedef struct {
    char *host;
    uint16_t port;
} network_conf_t;

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    SOCKET socket;
/* Flag indicating if a command has been cancelled.
 * This is a temporary flag, which will be changed into
 * a tcti state when support for asynch operation will be added */
    bool cancel;
} TSS2_TCTI_NETWORK_CONTEXT;

#endif /* TCTI_NETWORK_H */
