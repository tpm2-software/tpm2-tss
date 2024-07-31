/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Infineon Technologies AG
 * All rights reserved.
 */

#ifndef TCTI_START_SIM_H
#define TCTI_START_SIM_H

#include <stdint.h>       // for uint16_t
#include <sys/types.h>    // for size_t, pid_t

#include "tcti-common.h"  // for TSS2_TCTI_COMMON_CONTEXT
#include "tss2_tcti.h"    // for TSS2_TCTI_CONTEXT

#define TCTI_START_SIM_MAGIC 0x535441525453494dULL

typedef int get_command_fn(char *command, size_t command_len, const char *workdir, uint16_t port);

typedef struct {
    const char *name;
    const size_t name_len;
    get_command_fn *get_command_fn;
    uint16_t num_ports;
} tcti_sim_variant;

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TSS2_TCTI_CONTEXT *tcti_child;
    char *tcti_child_name_conf;
    pid_t simulator_pid;
    const tcti_sim_variant *variant;
    uint16_t port;
} TSS2_TCTI_START_SIM_CONTEXT;

#endif /* TCTI_START_SIM_H */
