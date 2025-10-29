/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <errno.h>              // for errno
#include <inttypes.h>           // for uint8_t, PRIx32, PRIxPTR, uintptr_t
#include <limits.h>             // for PATH_MAX
#include <stddef.h>             // for NULL, size_t
#include <stdlib.h>             // for free, calloc
#if defined(__linux__)
#elif defined(_MSC_VER)
#include <limits.h>             // for PATH_MAX
#include <windows.h>
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH

static char *strndup(const char* s, size_t n)
{
    char *dst = NULL;

    if (n + 1 >= USHRT_MAX)
        return NULL;

    dst = calloc(1, n + 1);

    if (dst == NULL)
        return NULL;

    memcpy(dst, s, n);
    return dst;
}
#endif
#else
#include <limits.h>             // for PATH_MAX
#ifndef PATH_MAX
#define PATH_MAX 256
#endif
#endif
#include <string.h>             // for strerror, strcmp, strndup, strcpy

#include "tcti-common.h"        // for TCTI_VERSION
#include "tctildr-interface.h"  // for tctildr_finalize_data, tctildr_get_info
#include "tctildr.h"
#include "tss2_tcti.h"          // for TSS2_TCTI_INFO, TSS2_TCTI_CONTEXT
#include "tss2_tctildr.h"       // for Tss2_TctiLdr_Finalize, Tss2_TctiLdr_F...
#include "tss2_tpm2_types.h"    // for TPM2_HANDLE
#include "util/aux_util.h"      // for SAFE_FREE

#define LOGMODULE tcti
#include "util/log.h"           // for LOG_ERROR, LOG_DEBUG, LOG_TRACE, LOGM...

TSS2_RC
tcti_from_init(TSS2_TCTI_INIT_FUNC init,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC r;
    size_t size;

    LOG_TRACE("Initializing TCTI for config: %s", conf);

    if (init == NULL || tcti == NULL)
        return TSS2_TCTI_RC_BAD_REFERENCE;
    r = init(NULL, &size, conf);
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("TCTI init for function %p failed with %" PRIx32, init, r);
        return r;
    }

    *tcti = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (*tcti == NULL) {
        LOG_ERROR("Memory allocation for tcti failed: %s", strerror(errno));
        return TSS2_ESYS_RC_MEMORY;
    }

    /* Unless tcti loglevel is log_debug or higher
     * (i.e. TSS2_LOG=tcti+debug) turn the logging
     * from loaded tctis off completely, including warnings
     * and error logs. It makes too much noise when tcti
     * loader tries them all one by one and what we want
     * use is the last one.
     */
    log_level old_loglevel = LOGMODULE_status;
    if (LOGMODULE_status < LOGLEVEL_INFO)
        LOGMODULE_status = LOGLEVEL_NONE;

    r = init(*tcti, &size, conf);
    LOGMODULE_status = old_loglevel;

    if (r != TSS2_RC_SUCCESS) {
        LOG_DEBUG("TCTI init for function %p failed with %" PRIx32, init, r);
        free(*tcti);
        *tcti=NULL;
        return r;
    }

    LOG_DEBUG("Initialized TCTI for config: %s", conf);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_from_info(TSS2_TCTI_INFO_FUNC infof,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC r;
    LOG_TRACE("Attempting to load TCTI info");

    const TSS2_TCTI_INFO* info = infof();
    if (info == NULL) {
        LOG_ERROR("TCTI info function failed");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    LOG_TRACE("Loaded TCTI info named: %s", info->name);
    LOG_TRACE("TCTI description: %s", info->description);
    LOG_TRACE("TCTI config_help: %s", info->config_help);

    r = tcti_from_init(info->init, conf, tcti);
    if (r != TSS2_RC_SUCCESS) {
        LOG_DEBUG("Could not initialize TCTI named: %s", info->name);
        return r;
    }
    LOG_INFO("Initialized TCTI named: %s", info->name);

    return TSS2_RC_SUCCESS;
}
/*
 * name_conf in the form "tcti-name:tcti-conf"
 * copies 'tcti-name' component to 'name' buffer
 * copies 'tcti-conf' component to 'conf' buffer
 * handled name_conf forms:
 * - "", ":" -> both name and conf are left unchanged
 * - "tcti-name", "tcti-name:" -> tcti-name copied to 'name', 'conf'
 *   unchanged
 * - ":tcti-conf" -> tcti-conf copied to 'conf', 'name' unchanged
 * - "tcti-name:tcti-conf" - "tcti-name" copied to 'name,', "tcti-conf"
 *   copied to 'conf'
 */
TSS2_RC
tctildr_conf_parse (const char *name_conf,
                    char *name,
                    char *conf)
{
    char *split;
    size_t combined_length;

    if (name_conf == NULL) {
        LOG_ERROR ("'name_conf' param may NOT be NULL");
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    combined_length = strlen (name_conf);
    if (combined_length > PATH_MAX - 1) {
        LOG_ERROR ("combined conf length must be between 0 and PATH_MAX");
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    LOG_DEBUG ("name_conf: \"%s\"", name_conf);
    if (combined_length == 0)
        return TSS2_RC_SUCCESS;
    split = strchr (name_conf, ':');
    if (name != NULL && split == NULL) {
        /* no ':' tcti name only */
        strcpy (name, name_conf);
        LOG_DEBUG ("TCTI name: \"%s\"", name);
        return TSS2_RC_SUCCESS;
    }
    if (name != NULL && name_conf[0] != '\0' && name_conf[0] != ':') {
        /* name is more than empty string */
        size_t name_length = split - name_conf;
        if (name_length > PATH_MAX) {
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        memcpy (name, name_conf, name_length);
        name [name_length] = '\0';
        LOG_DEBUG ("TCTI name: \"%s\"", name);
    }
    if (conf != NULL && split && split [1] != '\0') {
        /* conf is more than empty string */
        strcpy (conf, &split [1]);
        LOG_DEBUG ("TCTI conf: \"%s\"", conf);
    }

    return TSS2_RC_SUCCESS;
}
/*
 * calls tctildr_conf_parse.
 * allocates memory for name and conf if necessary.
 * does not return empty strings, but NULL instead.
 */
TSS2_RC
tctildr_conf_parse_alloc (const char *name_conf,
                     char **name,
                     char **conf)
{
    size_t combined_length;
    TSS2_RC rc;

    if (name_conf == NULL) {
        *name = NULL;
        *conf = NULL;
        return TSS2_RC_SUCCESS;
    }

    /* Parse name_conf into name and conf */
    combined_length = strlen (name_conf);
    if (combined_length > PATH_MAX - 1) {
        LOG_ERROR ("combined conf length must be between 0 and PATH_MAX");
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    *name = calloc(combined_length + 1, sizeof(char));
    *conf = calloc(combined_length + 1, sizeof(char));
    if (*name == NULL || *conf == NULL) {
        SAFE_FREE(*name);
        SAFE_FREE(*conf);
        return TSS2_TCTI_RC_MEMORY;
    }
    rc = tctildr_conf_parse (name_conf, *name, *conf);
    if (rc != TSS2_RC_SUCCESS) {
        SAFE_FREE(*name);
        SAFE_FREE(*conf);
        return rc;
    }

    /* Set name and conf to NULL if they are empty strings */
    if (!strcmp(*name, "")) {
        SAFE_FREE(*name);
    }
    if (!strcmp(*conf, "")) {
        SAFE_FREE(*conf);
    }

    return TSS2_RC_SUCCESS;
}

TSS2_TCTILDR_CONTEXT*
tctildr_context_cast (TSS2_TCTI_CONTEXT *ctx)
{
    if (ctx != NULL && TSS2_TCTI_MAGIC (ctx) == TCTILDR_MAGIC) {
        return (TSS2_TCTILDR_CONTEXT*)ctx;
    }
    return NULL;
}
TSS2_RC
tctildr_transmit (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    return Tss2_Tcti_Transmit (ldr_ctx->tcti, command_size, command_buffer);
}
TSS2_RC
tctildr_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    return Tss2_Tcti_Receive (ldr_ctx->tcti,
                              response_size,
                              response_buffer,
                              timeout);
}
TSS2_RC
tctildr_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    return Tss2_Tcti_Cancel (ldr_ctx->tcti);
}
TSS2_RC
tctildr_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    return Tss2_Tcti_GetPollHandles (ldr_ctx->tcti, handles, num_handles);
}
TSS2_RC
tctildr_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    return Tss2_Tcti_SetLocality (ldr_ctx->tcti, locality);
}
TSS2_RC
tctildr_make_sticky (
    TSS2_TCTI_CONTEXT *tctiContext,
    TPM2_HANDLE *handle,
    uint8_t sticky)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    return Tss2_Tcti_MakeSticky (ldr_ctx->tcti, handle, sticky);
}

void
tctildr_finalize (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = tctildr_context_cast (tctiContext);
    if (ldr_ctx == NULL) {
        return;
    }
    if (ldr_ctx->tcti != NULL) {
        Tss2_Tcti_Finalize (ldr_ctx->tcti);
        free (ldr_ctx->tcti);
        ldr_ctx->tcti = NULL;
    }
}

void
Tss2_TctiLdr_Finalize (TSS2_TCTI_CONTEXT **tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx;
    if (tctiContext == NULL) {
        return;
    }
    ldr_ctx = tctildr_context_cast (*tctiContext);
    if (ldr_ctx == NULL) {
        return;
    }
    tctildr_finalize (*tctiContext);
    tctildr_finalize_data (&ldr_ctx->library_handle);
    free (ldr_ctx);
    *tctiContext = NULL;
}

TSS2_RC
copy_info (const TSS2_TCTI_INFO *info_src,
           TSS2_TCTI_INFO *info_dst)
{
    TSS2_RC rc = TSS2_RC_SUCCESS;
    const char *tmp = NULL;

    if (info_src == NULL || info_dst == NULL) {
        LOG_ERROR("parameters cannot be NULL");
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    tmp = strndup (info_src->name, PATH_MAX);
    if (tmp != NULL) {
        info_dst->name = tmp;
    } else {
        LOG_ERROR("strndup failed on name: %s", strerror(errno));
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }
    tmp = strndup (info_src->description, PATH_MAX);
    if (tmp != NULL) {
        info_dst->description = tmp;
    } else {
        LOG_ERROR("strndup failed on description: %s", strerror(errno));
        free ((char*)info_dst->name);
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
        goto out;
    }
    tmp = strndup (info_src->config_help, PATH_MAX);
    if (tmp != NULL) {
        info_dst->config_help = tmp;
    } else {
        LOG_ERROR("strndup failed on config_help: %s", strerror(errno));
        free ((char*)info_dst->name);
        free ((char*)info_dst->description);
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
        goto out;
    }
    info_dst->version = info_src->version;
out:
    return rc;
}

TSS2_RC
Tss2_TctiLdr_GetInfo (const char *name,
                      TSS2_TCTI_INFO **info)
{
    TSS2_RC rc;
    const TSS2_TCTI_INFO *info_lib = NULL;
    TSS2_TCTI_INFO *info_tmp = NULL;
    void *data = NULL;
    char name_buf [PATH_MAX] = { 0, }, *name_ptr = NULL;

    if (info == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (name != NULL) {
        rc = tctildr_conf_parse (name, name_buf, NULL);
        if (rc != TSS2_RC_SUCCESS)
            return rc;
        name_ptr = name_buf;
    }
    rc = tctildr_get_info (name_ptr, &info_lib, &data);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    info_tmp = calloc (1, sizeof (*info_tmp));
    if (info_tmp == NULL) {
        LOG_ERROR("calloc failed: %s", strerror (errno));
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
        goto out;
    }
    rc = copy_info (info_lib, info_tmp);
    if (rc != TSS2_RC_SUCCESS) {
        free (info_tmp);
        info_tmp = NULL;
        goto out;
    }
    info_tmp->init = NULL;
out:
    tctildr_finalize_data (&data);
    *info = info_tmp;
    return rc;
}

void
Tss2_TctiLdr_FreeInfo (TSS2_TCTI_INFO **info)
{
    TSS2_TCTI_INFO *info_tmp;

    if (info == NULL || *info == NULL) {
        return;
    }
    info_tmp = *info;
    if (info_tmp->name != NULL) {
        free ((char*)info_tmp->name);
    }
    if (info_tmp->description != NULL) {
        free ((char*)info_tmp->description);
    }
    if (info_tmp->config_help != NULL) {
        free ((char*)info_tmp->config_help);
    }
    free (info_tmp);
    *info = NULL;
}

TSS2_RC
tctildr_init_context_data (TSS2_TCTI_CONTEXT *tctiContext,
                           const char *name,
                           const char *conf)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = NULL;
    TSS2_TCTI_CONTEXT *child_ctx = NULL;
    void *dl_handle = NULL;
    TSS2_RC rc;

    if (tctiContext == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    rc = tctildr_get_tcti(name, conf, &child_ctx, &dl_handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to instantiate TCTI");
        return rc;
    }
    TSS2_TCTI_MAGIC (tctiContext) = TCTILDR_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tctildr_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tctildr_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tctildr_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = tctildr_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = tctildr_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = tctildr_set_locality;
    TSS2_TCTI_MAKE_STICKY (tctiContext) = tctildr_make_sticky;
    ldr_ctx = tctildr_context_cast(tctiContext);
    if (ldr_ctx == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    ldr_ctx->library_handle = dl_handle;
    ldr_ctx->tcti = child_ctx;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_TctiLdr_Initialize_Ex (const char *name,
                            const char *conf,
                            TSS2_TCTI_CONTEXT **tctiContext)
{
    TSS2_TCTILDR_CONTEXT *ldr_ctx = NULL;
    TSS2_RC rc;
    void *dl_handle = NULL;
    const char *local_name = NULL, *local_conf = NULL;

    if (tctiContext == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    *tctiContext = NULL;
    /* Ignore 'name' and 'conf' if they're NULL or empty string */
    if (name != NULL && strcmp (name, "")) {
        local_name = name;
    }
    if (conf != NULL && strcmp (conf, "")) {
        local_conf = conf;
    }
    ldr_ctx = calloc (1, sizeof (TSS2_TCTILDR_CONTEXT));
    if (ldr_ctx == NULL) {
        rc = TSS2_TCTI_RC_MEMORY;
        goto err;
    }

    *tctiContext = (TSS2_TCTI_CONTEXT *) ldr_ctx;
    return tctildr_init_context_data(*tctiContext, local_name, local_conf);

err:
    if (*tctiContext != NULL) {
        Tss2_Tcti_Finalize (*tctiContext);
        free (*tctiContext);
        *tctiContext = NULL;
    }
    tctildr_finalize_data (&dl_handle);
    return rc;
}

TSS2_RC
Tss2_TctiLdr_Initialize (const char *nameConf,
                         TSS2_TCTI_CONTEXT **tctiContext)
{
    char *name = NULL;
    char *conf = NULL;
    TSS2_RC rc;

    rc = tctildr_conf_parse_alloc (nameConf, &name, &conf);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    rc = Tss2_TctiLdr_Initialize_Ex (name, conf, tctiContext);

    SAFE_FREE(name);
    SAFE_FREE(conf);
    return rc;
}

TSS2_RC Tss2_Tcti_TctiLdr_Init (TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
                                const char *nameConf)
{
    TSS2_RC rc;
    char *name = NULL;
    char *conf = NULL;

    LOG_TRACE("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s",
               (uintptr_t)tctiContext, (uintptr_t)size, nameConf);

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTILDR_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    rc = tctildr_conf_parse_alloc (nameConf, &name, &conf);
    if (rc != TSS2_RC_SUCCESS) {
        goto free_name_conf;
    }

    rc = tctildr_init_context_data(tctiContext, name, conf);

free_name_conf:
    SAFE_FREE(name);
    SAFE_FREE(conf);
    return rc;
}

__attribute__((weak))
const TSS2_TCTI_INFO tss2_tctildr_info = {
    .version = TCTI_VERSION,
    .name = "tctildr",
    .description = "TCTI module for dynamically loading other TCTI modules",
    .config_help = "TCTI to load and its configuration. Either"
        " * <child_name>, e.g. device (child_conf will be NULL) OR\n"
        " * <child_name>:<child_conf>, e.g., device:/dev/tpmrm0 OR\n"
        " * NULL, tctildr will attempt to load a child tcti in the following order:\n"
        "   * libtss2-tcti-default.so\n"
        "   * libtss2-tcti-tabrmd.so\n"
        "   * libtss2-tcti-device.so.0:/dev/tpmrm0\n"
        "   * libtss2-tcti-device.so.0:/dev/tpm0\n"
        "   * libtss2-tcti-device.so.0:/dev/tcm0\n"
        "   * libtss2-tcti-swtpm.so\n"
        "   * libtss2-tcti-mssim.so\n"
        "Where child_name: if not empty, tctildr will try to dynamically load the child tcti library in the following order:\n"
        "   * <child_name>\n"
        "   * libtss2-tcti-<child_name>.so.0\n"
        "   * libtss2-tcti-<child_name>.so\n"
        "   * libtss2-<child_name>.so.0\n"
        "   * libtss2-<child_name>.so\n",
    .init = Tss2_Tcti_TctiLdr_Init,
};

__attribute__((weak))
const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tctildr_info;
}
