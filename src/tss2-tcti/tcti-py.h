/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TCTI_CMD_H
#define TCTI_CMD_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <limits.h>

#include <Python.h>

#include "tcti-common.h"
#include "util-io/io.h"

#define TCTI_PY_NAME "tcti-py"
#define TCTI_PY_DESCRIPTION "TCTI module for writing a TCTI in Python3."
#define TCTI_PY_HELP "String used as module:arg passed to tcti_init(arg: str) -> TCTI Object."

typedef struct TSS2_TCTI_PY_CONTEXT TSS2_TCTI_PY_CONTEXT;
struct TSS2_TCTI_PY_CONTEXT {
    TSS2_TCTI_COMMON_CONTEXT common;
    PyObject *py_tcti;
    PyObject *cur_response;
    struct {
        /* no finalize as __del__ will be called for the TCTI instance */
        PyObject *transmit;
        PyObject *receive;
        PyObject *make_sticky;
        PyObject *set_locality;
    } methods;
};

#endif /* TCTI_CMD_H */
