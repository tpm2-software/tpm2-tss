/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "tss2_esys.h"
#include "tss2_fapi.h"

#include "test-fapi.h"

#define LOGDEFAULT LOGLEVEL_INFO
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#ifndef FAPI_PROFILE
#define FAPI_PROFILE "P_ECC"
#endif /* FAPI_PROFILE */

char *fapi_profile = NULL;
char *tmpdir = NULL;

char *config = NULL;
char *config_path = NULL;
char *config_env = NULL;
char *remove_cmd = NULL;
char *system_dir = NULL;
FAPI_CONTEXT *global_fapi_context = NULL;

bool file_exists (char *path) {
  struct stat   buffer;
  return (stat (path, &buffer) == 0);
}

TSS2_RC
pcr_reset(FAPI_CONTEXT *context, UINT32 pcr)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;

    r = Fapi_GetTcti(context, &tcti);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_Initialize(&esys, tcti, NULL);
    goto_if_error(r, "Error Fapi_GetTcti", error);

    r = Esys_PCR_Reset(esys, pcr,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    Esys_Finalize(&esys);
    goto_if_error(r, "Error Eys_PCR_Reset", error);

error:
    return r;
}

int init_fapi(char *profile, FAPI_CONTEXT **fapi_context)
{
    TSS2_RC rc;
    int ret, size;
    SAFE_FREE(config);
    SAFE_FREE(config_path);
    SAFE_FREE(config_env);
    SAFE_FREE(remove_cmd);
    SAFE_FREE(system_dir);

    FILE *config_file;

    fapi_profile = profile;

    /* First we construct a fapi config file */
#if defined(FAPI_NONTPM)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"none\",\n"
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir);
#elif defined(FAPI_TEST_FINGERPRINT)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_fingerprint\": %s,\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv("TPM20TEST_TCTI"),
                    getenv("FAPI_TEST_FINGERPRINT"));
#elif defined(FAPI_TEST_CERTIFICATE)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_cert_file\": \"%s\",\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv("TPM20TEST_TCTI"),
                    getenv("FAPI_TEST_CERTIFICATE"));
#elif defined(FAPI_TEST_FINGERPRINT_ECC)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_fingerprint\": %s,\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv("TPM20TEST_TCTI"),
                    getenv("FAPI_TEST_FINGERPRINT_ECC"));
#elif defined(FAPI_TEST_CERTIFICATE_ECC)
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#else
                    "     \"ek_cert_file\": \"%s\",\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv("TPM20TEST_TCTI"),
                    getenv("FAPI_TEST_CERTIFICATE_ECC"));
#else /* FAPI_NONTPM */
    size = asprintf(&config, "{\n"
                    "     \"profile_name\": \"%s\",\n"
                    "     \"profile_dir\": \"" TOP_SOURCEDIR "/test/data/fapi/\",\n"
                    "     \"user_dir\": \"%s/user/dir\",\n"
                    "     \"system_dir\": \"%s/system_dir\",\n"
                    "     \"system_pcrs\" : [],\n"
                    "     \"log_dir\" : \"%s\",\n"
                    "     \"tcti\": \"%s\",\n"
#if defined(FAPI_TEST_EK_CERT_LESS)
                    "     \"ek_cert_less\": \"yes\",\n"
#endif
                    "}\n",
                    profile, tmpdir, tmpdir, tmpdir,
                    getenv("TPM20TEST_TCTI"));
#endif /* FAPI_NONTPM */
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }

    size = asprintf(&system_dir, "%s/system_dir/", tmpdir);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }

    if (!file_exists(system_dir)) {
        int rc_mkdir = mkdir(system_dir, 0777);
        if (rc_mkdir != 0) {
            LOG_ERROR("mkdir not possible: %i %s", rc_mkdir, system_dir);
            ret = EXIT_ERROR;
            goto error;
        }
    }

    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    LOG_INFO("Using config:\n%s", config);

    /* We construct the path for the config file */
    size = asprintf(&config_path, "%s/fapi-config.json", tmpdir);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }

    /* We write the config file to disk */
    config_file = fopen(config_path, "w");
    if (!config_file) {
        LOG_ERROR("Opening config file for writing");
        perror(config_path);
        ret = EXIT_ERROR;
        goto error;
    }
    size = fprintf(config_file, "%s", config);
    fclose(config_file);
    if (size < 0) {
        LOG_ERROR("Writing config file");
        perror(config_path);
        ret = EXIT_ERROR;
        goto error;
    }

    /* We set the environment variable for FAPI to consume the config file */
    size = asprintf(&config_env, "TSS2_FAPICONF=%s", config_path);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    putenv(config_env);

    /***********
     * Call FAPI
     ***********/

    rc = Fapi_Initialize(fapi_context, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        ret = EXIT_FAILURE;
        goto error;
    }
    global_fapi_context = *fapi_context;
    return 0;

 error:
    Fapi_Finalize(fapi_context);

    if (system_dir) free(system_dir);
    if (config) free(config);
    if (config_path) free(config_path);
    if (config_env) free(config_env);
    if (remove_cmd) free(remove_cmd);

    return ret;
}

/**
 * This program is a template for integration tests (ones that use the TCTI,
 * the ESAPI, and FAPI contexts / API directly). It does nothing more than
 * parsing  command line options that allow the caller (likely a script)
 * to specifywhich TCTI to use for the test using getenv("TPM20TEST_TCTI").
 */
int
main(int argc, char *argv[])
{
    int ret, size;
    char *config = NULL;
    char *config_path = NULL;
    char *config_env = NULL;
    char *remove_cmd = NULL;
    char *system_dir = NULL;

    char template[] = "/tmp/fapi_tmpdir.XXXXXX";

    tmpdir = mkdtemp(template);

    if (!tmpdir) {
        LOG_ERROR("No temp dir created");
        return EXIT_ERROR;
    }
    ret = init_fapi(FAPI_PROFILE, &global_fapi_context);
    if (ret)
        goto error;

    ret = test_invoke_fapi(global_fapi_context);

    LOG_INFO("Test returned %i", ret);
    if (ret) goto error;

    size = asprintf(&remove_cmd, "rm -r -f %s", tmpdir);
    if (size < 0) {
        LOG_ERROR("Out of memory");
        ret = EXIT_ERROR;
        goto error;
    }
    if (system(remove_cmd) != 0) {
        LOG_ERROR("Directory %s can't be deleted.", tmpdir);
        ret = EXIT_ERROR;
        goto error;
    }

error:
    Fapi_Finalize(&global_fapi_context);

    if (system_dir) free(system_dir);
    if (config) free(config);
    if (config_path) free(config_path);
    if (config_env) free(config_env);
    if (remove_cmd) free(remove_cmd);

    return ret;
}
