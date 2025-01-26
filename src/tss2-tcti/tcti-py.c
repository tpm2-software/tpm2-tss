/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dlfcn.h>
#include <pthread.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "tss2_tcti_py.h"

#include "tcti-py.h"
#include "tcti-common.h"
#define LOGMODULE tcti
#include "util/log.h"

#include "util/tss2_endian.h"

#define TCTI_PY_VERSION 2

#define SAFE_DECREF(x) \
    do { \
        Py_XDECREF(x); \
        x = NULL; \
    } while(0)

/*
 * I wanted to use constructor and destructor attributes for this, however, gcc was
 * complaining that 'deconstructor' attribute directive ignored. So instead we
 * just do a simple refcnt.
 */
static struct {
    size_t refcnt;
    pthread_mutex_t lock;
    void *dlhandle;
} _global = {
        .lock = PTHREAD_MUTEX_INITIALIZER
};

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the command TCTI context. If passed a NULL context the function
 * returns a NULL ptr. The function doesn't check magic number anymore
 * It should checked by the appropriate tcti_common_checks.
 */
static TSS2_TCTI_PY_CONTEXT*
tcti_py_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx == NULL)
        return NULL;

    return (TSS2_TCTI_PY_CONTEXT*) tcti_ctx;
}
/*
 * This function down-casts the cmd TCTI context to the common context
 * defined in the tcti-common module.
 */
static TSS2_TCTI_COMMON_CONTEXT*
tcti_py_down_cast (TSS2_TCTI_PY_CONTEXT *tcti_cmd)
{
    if (tcti_cmd == NULL) {
        return NULL;
    }
    return &tcti_cmd->common;
}

static TSS2_RC
tcti_py_get_poll_handles_not_implemented (TSS2_TCTI_CONTEXT *tctiContext,
        TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles)
{
    UNUSED(tctiContext);
    UNUSED(handles);
    UNUSED(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static TSS2_RC
tcti_py_transmit (TSS2_TCTI_CONTEXT *tcti_ctx, size_t size,
        const uint8_t *buffer)
{
    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;

    PyObject *py_buf = NULL;
    TSS2_TCTI_PY_CONTEXT *tcti_py = tcti_py_context_cast (tcti_ctx);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_py_down_cast (tcti_py);

    TSS2_RC r = tcti_common_transmit_checks (tcti_common, buffer,
            TSS2_TCTI_MAGIC (tcti_common));
    if (r != TSS2_RC_SUCCESS) {
        return r;
    }

    py_buf = Py_BuildValue("(y#)", buffer, size);
    if (!py_buf) {
        rc = TSS2_TCTI_RC_MEMORY;
        goto py_error;
    }


    PyObject_CallObject(tcti_py->methods.transmit, py_buf);
    if(PyErr_Occurred()) {
        goto py_error;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;
    rc = TSS2_RC_SUCCESS;
out:
    return rc;

py_error:
    PyErr_Print();
    SAFE_DECREF(py_buf);
    goto out;
}

static TSS2_RC
tcti_py_receive (TSS2_TCTI_CONTEXT *tctiContext, size_t *response_size,
        unsigned char *response_buffer, int32_t timeout)
{
    PyObject *py_timeout = NULL, *py_response = NULL;

    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
    TSS2_TCTI_PY_CONTEXT *tcti_py = tcti_py_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_py_down_cast (tcti_py);

    TSS2_RC r = tcti_common_receive_checks (tcti_common, response_size,
            TSS2_TCTI_MAGIC (tcti_common));
    if (r != TSS2_RC_SUCCESS) {
        return r;
    }

    /*
     * we we're called before and have a response that needs to be returned
     * if we don't have a response, go fetch one from the Python TCTI
     */
    if (!tcti_py->cur_response) {

        /* long is at least 32, but may be 64 so just don't pass int32_t
         * or python may read too far if long is 64
         */
        long timeout_long = timeout;
        py_timeout = Py_BuildValue("(l)", timeout_long);
        if (!py_timeout) {
            rc = TSS2_TCTI_RC_MEMORY;
            goto py_error;
        }


        py_response = PyObject_CallObject(tcti_py->methods.receive, py_timeout);
        if (!py_response) {
            *response_size = 0;
            goto py_error;
        }

        if (!PyBytes_Check(py_response)) {
            LOG_ERROR("Expected Python TCTI receive to return a bytes like object");
            rc = TSS2_TCTI_RC_BAD_VALUE;
            goto error;
        }
    } else {
        /* use our remembered response from before */
        py_response = tcti_py->cur_response;
        /* current function takes ownership */
        tcti_py->cur_response = NULL;
    }

    Py_ssize_t py_response_size = PyBytes_Size(py_response);

    /*
     * State: No response buffer calling for size,
     * Action: Remember this buffer until the next call, return OK
     */
    if (!response_buffer) {
        /* take ownership */
        tcti_py->cur_response = py_response;
        py_response = NULL;
        *response_size = py_response_size;

    } else if (py_response_size > (ssize_t)*response_size) {
        /*
         * State: Response buffer provided but too small
         * Action:
         *   if buffer too small return TSS2_TCTI_RC_INSUFFICIENT_BUFFER and
         *   remember buffer for next call
         */

        /* take ownership */
        tcti_py->cur_response = py_response;
        py_response = NULL;

        /* let caller know needed size */
        *response_size = py_response_size;
        rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        goto error;

    } else {

        /*
         * State: Buffer of sufficient size
         * Action: Copy to user and forget remembered buffer
         *
         * Note: The current remembered buffer may or may not be set depending
         * on if this function succeeded on the first try (not set) vs multiple
         * calls.
         */
        char *data = PyBytes_AsString(py_response);
        if (!data) {
            /* forget the internal buffer on error if set and NULL it */
            SAFE_DECREF(tcti_py->cur_response);
            rc = TSS2_TCTI_RC_MEMORY;
            goto py_error;
        }

        /* copy to user */
        memcpy(response_buffer, data, py_response_size);
        SAFE_DECREF(tcti_py->cur_response);


        /*
         * Executing code beyond this point transitions the state machine to
         * TRANSMIT. Another call to this function will not be possible until
         * another command is sent to the TPM.
         */
        tcti_common->header.size = 0;
        tcti_common->state = TCTI_STATE_TRANSMIT;
    }

    rc = TSS2_RC_SUCCESS;
out:
    return rc;

py_error:
    PyErr_Print();
error:
    SAFE_DECREF(py_response);
    SAFE_DECREF(py_timeout);
    goto out;
}

static TSS2_RC
tcti_py_make_sticky (TSS2_TCTI_CONTEXT *tcti_ctx, TPM2_HANDLE *handle,  uint8_t sticky)
{
    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;

    PyObject *py_args = NULL, *py_result = NULL;
    TSS2_TCTI_PY_CONTEXT *tcti_py = tcti_py_context_cast (tcti_ctx);

    if (!tcti_py->methods.make_sticky) {
        return TSS2_TCTI_RC_NOT_IMPLEMENTED;
    }

    py_args = Py_BuildValue("(kb)", *handle, sticky);
    if (!py_args) {
        rc = TSS2_TCTI_RC_MEMORY;
        goto py_error;
    }

    py_result = PyObject_CallObject(tcti_py->methods.make_sticky, py_args);
    if(PyErr_Occurred()) {
        goto py_error;
    }

    if(!PyLong_Check(py_result)) {
        LOG_ERROR("Expected make_sticky to return integer");
        goto error;
    }

    long x = PyLong_AsUnsignedLong(py_result);
    *handle = (TPM2_HANDLE)x;

    rc = TSS2_RC_SUCCESS;
out:
    return rc;

py_error:
    PyErr_Print();
error:
    SAFE_DECREF(py_args);
    SAFE_DECREF(py_result);
    goto out;
}

static TSS2_RC
tcti_py_set_locality (TSS2_TCTI_CONTEXT *tcti_ctx, uint8_t locality)
{
    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;

    PyObject *py_locality = NULL;
    TSS2_TCTI_PY_CONTEXT *tcti_py = tcti_py_context_cast (tcti_ctx);


    if (!tcti_py->methods.set_locality) {
        return TSS2_TCTI_RC_NOT_IMPLEMENTED;
    }

    py_locality = Py_BuildValue("(i)", locality);
    if (!py_locality) {
        PyErr_Print();
        rc = TSS2_TCTI_RC_MEMORY;
        goto py_error;
    }

    PyObject_CallObject(tcti_py->methods.set_locality, py_locality);
    if(PyErr_Occurred()) {
        goto py_error;
    }

    rc = TSS2_RC_SUCCESS;
out:
    return rc;

py_error:
    PyErr_Print();
    SAFE_DECREF(py_locality);
    goto out;
}

static void
tcti_py_finalize (TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_PY_CONTEXT *tcti_py = tcti_py_context_cast (tctiContext);

    if (tcti_py == NULL) {
        return;
    }

    SAFE_DECREF(tcti_py->methods.set_locality);
    SAFE_DECREF(tcti_py->methods.make_sticky);
    SAFE_DECREF(tcti_py->methods.receive);
    SAFE_DECREF(tcti_py->methods.transmit);
    SAFE_DECREF(tcti_py->py_tcti);
    SAFE_DECREF(tcti_py->cur_response);

    /* Decrement the reference count on PYTHON init */
    pthread_mutex_lock(&_global.lock);
    assert(_global.refcnt != 0);
    _global.refcnt--;
    if (_global.refcnt == 0) {
        Py_Finalize();
        if (_global.dlhandle) {
            dlclose(_global.dlhandle);
            _global.dlhandle = NULL;
        }
    }
    pthread_mutex_unlock(&_global.lock);
}

#define GET_TRANSMIT_FROM_PY(tcti_py) _get_method(tcti_py, &tcti_py->methods.transmit, "transmit", "transmit(self, data: bytes) -> None", false)
#define GET_RECIEVE_FROM_PY(tcti_py) _get_method(tcti_py, &tcti_py->methods.receive, "receive", "receive(self, timeout: int) -> bytes", false)
#define GET_MAKE_STICKY_FROM_PY(tcti_py) _get_method(tcti_py, &tcti_py->methods.make_sticky, "make_sticky", "make_sticky(self, handle: int, sticky: bool) -> int", true)
#define GET_SET_LOCALITY_FROM_PY(tcti_py) _get_method(tcti_py, &tcti_py->methods.set_locality, "set_locality", "set_locality(self, locality: int) -> None", true)
static TSS2_RC _get_method(TSS2_TCTI_PY_CONTEXT *tcti_py, PyObject **save, const char *method, const char *signature, bool none_ok) {

    PyObject *py_method = NULL;

    TSS2_RC rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;

    py_method = PyObject_GetAttrString(tcti_py->py_tcti, method);
    if (!py_method) {
        if (none_ok) {
            PyErr_Clear();
            LOG_DEBUG("Python TCTI does not implement method %s", method);
            goto success;
        }
        LOG_ERROR("Expected Python TCTI to have method %s", signature);
        goto py_error;
    }

    if (!PyCallable_Check(py_method)) {
        LOG_ERROR("Expected %s to be a callable method", signature);
        goto py_error;
    }

    /* Take Ownership of the PyObject method */
    *save = py_method;
    py_method = NULL;

success:
    rc = TSS2_RC_SUCCESS;
out:
    return rc;

py_error:
    PyErr_Print();
    SAFE_DECREF(py_method);
    goto out;
}

static TSS2_RC get_magic(TSS2_TCTI_PY_CONTEXT *tcti_py) {

    PyObject *py_magic = NULL;
    TSS2_RC rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_py_down_cast (tcti_py);

    py_magic = PyObject_GetAttrString(tcti_py->py_tcti, "magic");
    if (!py_magic) {
        LOG_ERROR("Expected module to implement attribute magic returning an 8 byte max integer");
        goto py_error;
    }

    if (PyBytes_Check(py_magic)) {
        /* they returned a byte buffer */
        Py_ssize_t len = 0;
        char *buf = NULL;

        if(PyBytes_AsStringAndSize(py_magic, &buf, &len)) {
            LOG_ERROR("Could not get magic bytes");
            goto py_error;
        }

        char mag_buf[8] = { 0 };
        if ((size_t)len > sizeof(mag_buf) || len < 1) {
            LOG_ERROR("Unexpected number of magic bytes");
            goto out;
        }

        memcpy(mag_buf, buf, len);
        TSS2_TCTI_MAGIC (tcti_common) = BE_TO_HOST_64(*((uint64_t *)mag_buf));
    } else if (PyLong_Check(py_magic)) {
        /* they returned an integer */
        TSS2_TCTI_MAGIC (tcti_common) = PyLong_AsUnsignedLongLong(py_magic);
    } else {
        LOG_ERROR("Expected attribute magic to return 8 bytes or int");
        goto out;
    }


    rc = TSS2_RC_SUCCESS;

py_error:
    PyErr_Print();
out:
    SAFE_DECREF(py_magic);

    return rc;
}

TSS2_RC tcti_py_init_py_module (TSS2_TCTI_PY_CONTEXT *tcti_py) {

    TSS2_RC rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_py_down_cast (tcti_py);

    /* optional methods */
    rc = GET_MAKE_STICKY_FROM_PY(tcti_py);
    if (rc) {
        goto error;
    }

    rc = GET_SET_LOCALITY_FROM_PY(tcti_py);
    if (rc) {
        goto error;
    }

    /* required methods */
    rc = get_magic(tcti_py);
    if (rc) {
        goto error;
    }

    rc = GET_TRANSMIT_FROM_PY(tcti_py);
    if (rc) {
        goto error;
    }

    rc = GET_RECIEVE_FROM_PY(tcti_py);
    if (rc) {
        goto error;
    }

    TSS2_TCTI_VERSION (tcti_common) = TCTI_PY_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_common) = tcti_py_transmit;
    TSS2_TCTI_RECEIVE (tcti_common) = tcti_py_receive;
    TSS2_TCTI_FINALIZE (tcti_common) = tcti_py_finalize;

    TSS2_TCTI_MAKE_STICKY (tcti_common) = tcti_py_make_sticky;
    TSS2_TCTI_SET_LOCALITY (tcti_common) = tcti_py_set_locality;

    /* No get_poll_handles for now, as it's OS specific we would need to replicate something like tpm2-pytss PollData */
    TSS2_TCTI_GET_POLL_HANDLES (tcti_common) = tcti_py_get_poll_handles_not_implemented;

    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->locality = 0;

    rc = TSS2_RC_SUCCESS;

error:
    return rc;

}

TSS2_RC
Tss2_Tcti_Py_Init (TSS2_TCTI_CONTEXT *tcti_context, size_t *size,
        const char *conf)
{
    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;

    TSS2_TCTI_PY_CONTEXT *tcti_py = tcti_py_context_cast(tcti_context);

     char *conf_copy = NULL;
    PyObject *py_module = NULL, *py_arg = NULL;

    if (size == NULL) {
        LOG_ERROR("size pointer must be valid");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (!conf) {
        LOG_ERROR("must have a module name to run in conf");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (tcti_context == NULL) {
        *size = sizeof (TSS2_TCTI_PY_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    memset(tcti_context, 0, *size);

    conf_copy = strdup(conf);
    if (!conf_copy) {
        return TSS2_TCTI_RC_MEMORY;
    }

    char *arg = NULL;
    char *module = conf_copy;
    char *sep = strchr(conf_copy, ':');
    if (sep) {
        *sep = '\0';
        arg = &sep[1];
    }

    LOG_DEBUG ("Initializing Python TCTI with module: \"%s\" arg \"%s\"",
            module, arg ? arg : "(null)");

    /* Increment the reference count on PYTHON init */
    pthread_mutex_lock(&_global.lock);
    size_t new_cnt = 0;
    bool overflow = __builtin_add_overflow(_global.refcnt, 1, &new_cnt);
    if (!overflow) {
        _global.refcnt = new_cnt;
        if (new_cnt == 1) {
            /* See: https://stackoverflow.com/questions/60719987/embedding-python-which-uses-numpy-in-c-doesnt-work-in-library-dynamically-loa */
            _global.dlhandle = dlopen (TCTI_PYLIB, RTLD_LAZY|RTLD_GLOBAL);
            if (!_global.dlhandle) {
                LOG_WARNING("Could not dlopen libpython3.so, some things may not work: %s", dlerror());
            }
            Py_Initialize();
        }
    }
    pthread_mutex_unlock(&_global.lock);
    if (overflow) {
        LOG_ERROR("Max instance count limit reached");
        goto error;
    }

    py_arg = Py_BuildValue("(z)", arg);
    if (!py_arg) {
        goto py_error;
    }

    py_module = PyImport_ImportModule(module);
    if (!py_module) {
        goto py_error;
    }

    /* Borrowed reference DO NOT DECREF */
    PyObject *py_dict = PyModule_GetDict(py_module);
    if (!py_dict) {
        goto py_error;
    }

    /*
     * modules implement a method called tcti_init(args) -> Object
     * Where the returned object implements the required attributes.
     * This is also a borrowd ref DO NOT DECREF
     */
    PyObject *py_initfn = PyDict_GetItemString(py_dict, (char*)"tcti_init");
    if (!py_initfn) {
        goto py_error;
    }

    if (!PyCallable_Check(py_initfn)) {
        goto py_error;
    }

    /* This is the instance object that implements the TCTI */
    tcti_py->py_tcti = PyObject_CallObject(py_initfn, py_arg);
    if (!tcti_py->py_tcti) {
        goto py_error;
    }

    rc = tcti_py_init_py_module (tcti_py);
    if (rc != TSS2_RC_SUCCESS) {
        goto py_error;
    }

    rc = TSS2_RC_SUCCESS;

    /* Do NOT DECREMENT py_dict/py_initfn borrowed ref */
    SAFE_DECREF(py_module);

    return rc;

py_error:
    PyErr_Print();
error:
    SAFE_DECREF(py_module);
    tcti_py_finalize(tcti_context);
    return rc;
}

/* public info structure */
const TSS2_TCTI_INFO tss2_tcti_info = {
        .version = TCTI_PY_VERSION,
        .name = TCTI_PY_NAME,
        .description = TCTI_PY_DESCRIPTION,
        .config_help = TCTI_PY_HELP,
        .init = Tss2_Tcti_Py_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
