/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <json-c/json.h>
#include <json-c/json_util.h>

#include "util/aux_util.h"
#include "ifapi_config.h"
#include "ifapi_json_deserialize.h"
#include "tpm_json_deserialize.h"
#include "ifapi_json_serialize.h"
#include "tpm_json_serialize.h"
#include "ifapi_helpers.h"

#define LOGMODULE fapi
#include "util/log.h"

/**
 * The path of the default config file
 */
#define DEFAULT_CONFIG_FILE (SYSCONFDIR "/tpm2-tss/fapi-config.json")

/** Deserializes a configuration JSON object.
 *
 * @param[in]  jso The JSON object to be deserialized
 * @param[out] out The deserialized configuration object
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if jso or out is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if the JSON object cannot be deserialized
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
static TSS2_RC
ifapi_json_IFAPI_CONFIG_deserialize(json_object *jso, IFAPI_CONFIG *out)
{
    /* Check for NULL parameters */
    return_if_null(out, "out is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(jso, "jso is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Deserialize the JSON object) */
    json_object *jso2;
    TSS2_RC r;
    LOG_TRACE("call");

    if (!ifapi_get_sub_object(jso, "profile_dir", &jso2)) {
        out->profile_dir = NULL;
    } else {
        r = ifapi_json_char_deserialize(jso2, &out->profile_dir);
        return_if_error(r, "Bad value for field \"profile_dir\".");
    }

    if (!ifapi_get_sub_object(jso, "user_dir", &jso2)) {
        out->user_dir = NULL;
    } else {
        r = ifapi_json_char_deserialize(jso2, &out->user_dir);
        return_if_error(r, "Bad value for field \"user_dir\".");
    }

    if (!ifapi_get_sub_object(jso, "system_dir", &jso2)) {
        out->keystore_dir = NULL;
    } else {
        r = ifapi_json_char_deserialize(jso2, &out->keystore_dir);
        return_if_error(r, "Bad value for field \"keystore_dir\".");
    }

    if (!ifapi_get_sub_object(jso, "log_dir", &jso2)) {
        out->log_dir = DEFAULT_LOG_DIR;
    } else {
        r = ifapi_json_char_deserialize(jso2, &out->log_dir);
        return_if_error(r, "Bad value for field \"log_dir\".");
    }

    if (!ifapi_get_sub_object(jso, "profile_name", &jso2)) {
        LOG_ERROR("Field \"profile_name\" not found.");
        return TSS2_FAPI_RC_BAD_VALUE;
    }
    r = ifapi_json_char_deserialize(jso2, &out->profile_name);
    return_if_error(r, "Bad value for field \"profile_name\".");
    if (!ifapi_get_sub_object(jso, "tcti", &jso2)) {
        LOG_ERROR("Field \"tcti\" not found.");
        return TSS2_FAPI_RC_BAD_VALUE;
    }
    r = ifapi_json_char_deserialize(jso2, &out->tcti);
    return_if_error(r, "Bad value for field \"tcti\".");

    if (!ifapi_get_sub_object(jso, "system_pcrs", &jso2)) {
        LOG_ERROR("Field \"system_pcrs\" not found.");
        return TSS2_FAPI_RC_BAD_VALUE;
    }
    r = ifapi_json_TPML_PCR_SELECTION_deserialize(jso2, &out->system_pcrs);
    return_if_error(r, "Bad value for field \"system_pcrs\".");

    if (!ifapi_get_sub_object(jso, "ek_cert_file", &jso2)) {
        out->ek_cert_file = NULL;
    } else {
        r = ifapi_json_char_deserialize(jso2, &out->ek_cert_file);
        return_if_error(r, "Bad value for field \"ek_cert_file\".");
    }

    if (ifapi_get_sub_object(jso, "ek_cert_less", &jso2)) {
        r = ifapi_json_TPMI_YES_NO_deserialize(jso2, &out->ek_cert_less);
        return_if_error(r, "Bad value for field \"ek_cert_less\".");

    } else {
        out->ek_cert_less = TPM2_NO;
    }

    if (ifapi_get_sub_object(jso, "ek_fingerprint", &jso2)) {
        r = ifapi_json_TPMT_HA_deserialize(jso2, &out->ek_fingerprint);
        return_if_error(r, "Bad value for field \"ek_fingerprint\".");
    } else {
        out->ek_fingerprint.hashAlg = 0;
    }

    if (!ifapi_get_sub_object(jso, "intel_cert_service", &jso2)) {
        out->intel_cert_service = NULL;
    } else {
        r = ifapi_json_char_deserialize(jso2, &out->intel_cert_service);
        return_if_error(r, "Bad value for field \"intel_cert_service\".");
    }

    LOG_TRACE("true");
    return TSS2_RC_SUCCESS;
}

/**
 * Starts the initialization of the FAPI configuration.
 *
 * @param[in] io An IO object for file system access
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if io is NULL
 * @retval TSS2_FAPI_RC_IO_ERROR if an error occurred while accessing the
 *         object store.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_config_initialize_async(IFAPI_IO *io)
{
    /* Check for NULL parameters */
    return_if_null(io, "io is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Determine the location of the configuration file */
    const char *configFile = getenv(ENV_FAPI_CONFIG);
    if (!configFile) {
        /* No config file given, falling back to the default */
        configFile = DEFAULT_CONFIG_FILE;
    }

    /* Start reading the config file */
    TSS2_RC r = ifapi_io_read_async(io, configFile);
    return_if_error(r, "Could not read config file ");
    return TSS2_RC_SUCCESS;
}

/**
 * Finishes the initialization of the FAPI configuration.
 * @param[in]  io An IO object for file system access
 * @param[out] config The configuration that is initialized
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if config or io is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if the read configuration file does not hold
 *         a valid configuration
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if JSON parsing fails
 * @retval TSS2_FAPI_RC_BAD_PATH if the configuration path is invalid
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_IO_ERROR if an error occurred while accessing the
 *         object store.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_config_initialize_finish(IFAPI_IO *io, IFAPI_CONFIG *config)
{
    /* Check for NULL parameters */
    return_if_null(config, "config is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(io, "io is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Definitions that must be listed here for the cleanup to work */
    const char *homeDir = NULL;
    json_object *jso = NULL;

    /* Finish reading operation */
    uint8_t *configFileContent = NULL;
    size_t configFileContentSize = 0;
    TSS2_RC r = ifapi_io_read_finish(io, &configFileContent, &configFileContentSize);
    return_try_again(r);
    goto_if_error(r, "Could not finish read operation", cleanup);
    if (configFileContent == NULL || configFileContentSize == 0) {
        LOG_ERROR("Config file is empty");
        r = TSS2_FAPI_RC_BAD_VALUE;
        goto cleanup;
    }

    /* Parse and deserialize the configuration file */
    jso = json_tokener_parse((char *)configFileContent);
    goto_if_null(jso, "Could not parse JSON objects",
            TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);
    r = ifapi_json_IFAPI_CONFIG_deserialize(jso, config);
    goto_if_error(r, "Could not deserialize configuration", cleanup);

    /* Check, if the values of the configuration are valid */
    goto_if_null(config->profile_dir, "No profile directory defined in config file",
                 TSS2_FAPI_RC_BAD_VALUE, cleanup);
    goto_if_null(config->user_dir, "No user directory defined in config file",
                 TSS2_FAPI_RC_BAD_VALUE, cleanup);
    goto_if_null(config->profile_name, "No default profile defined in config file.",
                 TSS2_FAPI_RC_BAD_VALUE, cleanup);

    /* Check whether usage of home directory is provided in config file */
    size_t startPos = 0;
    if (strncmp("~", config->user_dir, 1) == 0) {
        startPos = 1;
    } else if (strncmp("$HOME", config->user_dir, 5) == 0) {
        startPos = 5;
    }

    /* Replace home abbreviation in user path. */
    char *homePath = NULL;
    if (startPos != 0) {
        LOG_DEBUG("Expanding user directory %s to user's home", config->user_dir);
        homeDir = getenv("HOME");
        goto_if_null2(homeDir, "Home directory can't be determined.",
                      r, TSS2_FAPI_RC_BAD_PATH, cleanup);

        r = ifapi_asprintf(&homePath, "%s%s%s", homeDir, IFAPI_FILE_DELIM,
                           &config->user_dir[startPos]);
        goto_if_error(r, "Out of memory.", cleanup);

        SAFE_FREE(config->user_dir);
        config->user_dir = homePath;
    }

    /* Log the contents of the configuration */
    LOG_DEBUG("Configuration profile directory: %s", config->profile_dir);
    LOG_DEBUG("Configuration user directory: %s", config->user_dir);
    LOG_DEBUG("Configuration key storage directory: %s", config->keystore_dir);
    LOG_DEBUG("Configuration profile name: %s", config->profile_name);
    LOG_DEBUG("Configuration TCTI: %s", config->tcti);
    LOG_DEBUG("Configuration log directory: %s", config->log_dir);
cleanup:
    SAFE_FREE(configFileContent);
    if (jso != NULL) {
        json_object_put(jso);
    }
    return r;
}
