#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_tcti_device.h"
#include "tss2_tcti_mssim.h"

#include "context-util.h"

/*
 * Initialize a TSS2_TCTI_CONTEXT for the device TCTI.
 */
TSS2_TCTI_CONTEXT *
tcti_device_init(char const *device_path)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = Tss2_Tcti_Device_Init(NULL, &size, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr,
                "Failed to get allocation size for device tcti context: "
                "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        fprintf(stderr,
                "Allocation for device TCTI context failed: %s\n",
                strerror(errno));
        return NULL;
    }
    rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_path);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize device TCTI context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

/*
 * Initialize a socket TCTI instance using the provided options structure.
 * The hostname and port are the only configuration options used.
 * The caller is returned a TCTI context structure that is allocated by this
 * function. This structure must be freed by the caller.
 */
TSS2_TCTI_CONTEXT *
tcti_socket_init(char const *address, uint16_t port)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    char conf_str[256] = { 0 };

    snprintf(conf_str, 256, "tcp://%s:%" PRIu16, address, port);
    rc = Tss2_Tcti_Mssim_Init(NULL, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Faled to get allocation size for tcti context: "
                "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        fprintf(stderr, "Allocation for tcti context failed: %s\n",
                strerror(errno));
        return NULL;
    }
    rc = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize tcti context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

/*
 * Initialize a SAPI context using the TCTI context provided by the caller.
 * This function allocates memory for the SAPI context and returns it to the
 * caller. This memory must be freed by the caller.
 */
TSS2_SYS_CONTEXT *
sapi_init_from_tcti_ctx(TSS2_TCTI_CONTEXT * tcti_ctx)
{
    TSS2_SYS_CONTEXT *sapi_ctx;
    TSS2_RC rc;
    size_t size;
    TSS2_ABI_VERSION abi_version = {
        .tssCreator = 1,
        .tssFamily = 2,
        .tssLevel = 1,
        .tssVersion = 108,
    };

    size = Tss2_Sys_GetContextSize(0);
    sapi_ctx = (TSS2_SYS_CONTEXT *) calloc(1, size);
    if (sapi_ctx == NULL) {
        fprintf(stderr,
                "Failed to allocate 0x%zx bytes for the SAPI context\n", size);
        return NULL;
    }
    rc = Tss2_Sys_Initialize(sapi_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize SAPI context: 0x%x\n", rc);
        free(sapi_ctx);
        return NULL;
    }
    return sapi_ctx;
}

/*
 * Initialize a SAPI context to use a socket TCTI. Get configuration data from
 * the provided structure.
 */
TSS2_SYS_CONTEXT *
sapi_init_from_opts(test_opts_t * options)
{
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_SYS_CONTEXT *sapi_ctx;

    tcti_ctx = tcti_init_from_opts(options);
    if (tcti_ctx == NULL)
        return NULL;
    sapi_ctx = sapi_init_from_tcti_ctx(tcti_ctx);
    if (sapi_ctx == NULL)
        return NULL;
    return sapi_ctx;
}

/*
 * Initialize a TSS2_TCTI_CONTEXT using whatever TCTI data is in the options
 * structure. This is a mechanism that allows the calling application to be
 * mostly ignorant of which TCTI they're creating / initializing.
 */
TSS2_TCTI_CONTEXT *
tcti_init_from_opts(test_opts_t * options)
{
    switch (options->tcti_type) {
    case DEVICE_TCTI:
        return tcti_device_init(options->device_file);
    case SOCKET_TCTI:
        return tcti_socket_init(options->socket_address, options->socket_port);
    default:
        return NULL;
    }
}

/*
 * Teardown / Finalize TCTI context and free memory.
 */
void
tcti_teardown(TSS2_TCTI_CONTEXT * tcti_context)
{
    if (tcti_context) {
        Tss2_Tcti_Finalize(tcti_context);
        free(tcti_context);
    }
}

/*
 * Teardown and free the resources associated with a SAPI context structure.
 */
void
sapi_teardown(TSS2_SYS_CONTEXT * sapi_context)
{
    Tss2_Sys_Finalize(sapi_context);
    free(sapi_context);
}

/*
 * Teardown and free the resources associated with a SAPI context structure.
 * This includes tearing down the TCTI as well.
 */
void
sapi_teardown_full(TSS2_SYS_CONTEXT * sapi_context)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Tss2_Sys_GetTctiContext(sapi_context, &tcti_context);
    if (rc != TSS2_RC_SUCCESS)
        return;

    sapi_teardown(sapi_context);
    tcti_teardown(tcti_context);
}
