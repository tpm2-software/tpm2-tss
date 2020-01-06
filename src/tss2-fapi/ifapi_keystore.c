/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#include <dirent.h>
#endif

#include "ifapi_io.h"
#include "ifapi_helpers.h"
#include "ifapi_keystore.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"
#include "ifapi_json_deserialize.h"
#include "ifapi_json_serialize.h"

static TSS2_RC
initialize_explicit_key_path(
    const char *context_profile,
    const char *ipath,
    NODE_STR_T **list_node1,
    NODE_STR_T **current_list_node,
    NODE_STR_T **result)
{
    *list_node1 = split_string(ipath, IFAPI_FILE_DELIM);
    NODE_STR_T *list_node = *list_node1;
    char const *profile;
    char *hierarchy;
    TSS2_RC r = TSS2_RC_SUCCESS;

    *result = NULL;
    if (list_node == NULL) {
        LOG_ERROR("Invalid path");
        free_string_list(*list_node1);
        return  TSS2_FAPI_RC_BAD_VALUE;
    }
    if (strncmp("P_", list_node->str, 2) == 0) {
        profile = list_node->str;
        list_node = list_node->next;
    } else {
        profile = context_profile;
    }
    *result = init_string_list(profile);
    if (*result == NULL) {
        free_string_list(*list_node1);
        LOG_ERROR("Out of memory");
        return TSS2_FAPI_RC_MEMORY;
    }
    if (list_node == NULL) {
        hierarchy = "HS";
    } else {
        if (strcmp(list_node->str, "HS") == 0 ||
                strcmp(list_node->str, "HE") == 0 ||
                strcmp(list_node->str, "HP") == 0 ||
                strcmp(list_node->str, "HN") == 0 ||
                strcmp(list_node->str, "HP") == 0) {
            hierarchy = list_node->str;
            list_node = list_node->next;
        } else if (strcmp(list_node->str, "EK") == 0) {
            hierarchy = "HE";
        } else if (list_node->next != NULL &&
                   (strcmp(list_node->str, "SRK") == 0 ||
                    strcmp(list_node->str, "SDK") == 0 ||
                    strcmp(list_node->str, "UNK") == 0 ||
                    strcmp(list_node->str, "UDK") == 0)) {
            hierarchy = "HS";
        } else {
            hierarchy = "HS";
        }
    }
    if (!add_string_to_list(*result, hierarchy)) {
        LOG_ERROR("Out of memory");
        r = TSS2_FAPI_RC_MEMORY;
        goto error;
    }
    if (list_node == NULL) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Explicit path can't be determined.",
                   error);
    }
    if (!add_string_to_list(*result, list_node->str)) {
        LOG_ERROR("Out of memory");
        r = TSS2_FAPI_RC_MEMORY;
        goto error;
    }
    *current_list_node = list_node->next;
    return TSS2_RC_SUCCESS;

error:
    free_string_list(*result);
    *result = NULL;
    free_string_list(*list_node1);
    *list_node1 = NULL;
    return r;
}

static TSS2_RC
get_explicit_key_path(
    IFAPI_KEYSTORE *keystore,
    const char *ipath,
    NODE_STR_T **result)
{
    NODE_STR_T *list_node1 = NULL;
    NODE_STR_T *list_node = NULL;
    TSS2_RC r = initialize_explicit_key_path(keystore->defaultprofile, ipath,
                                             &list_node1, &list_node, result);
    goto_if_error(r, "init_explicit_key_path", error);

    while (list_node != NULL) {
        if (!add_string_to_list(*result, list_node->str)) {
            LOG_ERROR("Out of memory");
            r = TSS2_FAPI_RC_MEMORY;
            goto error;
        }
        list_node = list_node->next;
    }
    free_string_list(list_node1);
    return TSS2_RC_SUCCESS;

error:
    if (*result)
        free_string_list(*result);
    if (list_node1)
        free_string_list(list_node1);
    return r;
}

/** Convert full FAPI path to relative path.
 *
 * The relative path will be copied directly into the passed object.
 *
 * @parm[in] keystore The key directories and default profile.
 * @parm[in,out] path The absolute path.
 */
void
full_path_to_fapi_path(IFAPI_KEYSTORE *keystore, char *path)
{
    unsigned int start_pos, end_pos, i;
    const unsigned int path_length = strlen(path);
    size_t keystore_length = strlen(keystore->userdir);
    char fapi_path_delim;

    start_pos = 0;

    /* Check type of path, user or system */
    if (strncmp(&path[0], keystore->userdir, keystore_length) == 0) {
        start_pos = strlen(keystore->userdir);
    } else {
        keystore_length = strlen(keystore->systemdir);
        if (strncmp(&path[0], keystore->systemdir, keystore_length) == 0)
            start_pos = strlen(keystore->systemdir);
    }

    if (!start_pos)
        /* relative path was passed */
        return;

    /* Move relative path */
    end_pos = path_length - start_pos;
    memmove(&path[0], &path[start_pos], end_pos);
    size_t ip = 0;
    size_t lp = strlen(path);

    /* Remove double / */
    while (ip < lp) {
        if (strncmp(&path[ip], "//", 2) == 0) {
            memmove(&path[ip], &path[ip+1], lp-ip);
            lp -= 1;
        } else {
            ip += 1;
        }
    }

    /* A relative policy path will end before the file extension.
       For other objects only the directory name will be uses as
       relative name. */
    if (ifapi_path_type_p(path, IFAPI_POLICY_PATH))
        fapi_path_delim = '.';
    else
        fapi_path_delim = IFAPI_FILE_DELIM_CHAR;

    for (i = end_pos - 2; i > 0; i--) {
        if (path[i] == fapi_path_delim) {
            path[i] = '\0';
            break;
        }
    }
}

static TSS2_RC
expand_path(IFAPI_KEYSTORE *keystore, const char *path, char **file_name)
{
    TSS2_RC r;
    NODE_STR_T *node_list = NULL;
    size_t pos = 0;

    if (ifapi_hierarchy_path_p(path)) {
        if (strncmp(path, "P_", 2) == 0 || strncmp(path, "/P_", 3) == 0) {
            *file_name = strdup(path);
            return_if_null(*file_name, "Out of memory", TSS2_FAPI_RC_MEMORY);
        } else {
            if (strncmp("/", path, 1) == 0)
                pos = 1;
            r  = ifapi_asprintf(file_name, "%s%s%s",  keystore->defaultprofile,
                                IFAPI_FILE_DELIM, &path[pos]);
            return_if_error(r, "Out of memory.");
        }
    } else if (ifapi_path_type_p(path, IFAPI_NV_PATH)
        || ifapi_path_type_p(path, IFAPI_POLICY_PATH)
        || ifapi_path_type_p(path, IFAPI_EXT_PATH)
        || strncmp(path, "/P_", 3) == 0
        || strncmp(path, "P_", 2) == 0) {
        *file_name = strdup(path);
        return_if_null(*file_name, "Out of memory", TSS2_FAPI_RC_MEMORY);

    } else {
        r = get_explicit_key_path(keystore, path, &node_list);
        return_if_error(r, "Out of memory");

        r = ifapi_path_string(file_name, NULL, node_list, NULL);
        goto_if_error(r, "Out of memory", error);

        free_string_list(node_list);
    }
    return TSS2_RC_SUCCESS;

error:
    free_string_list(node_list);
    return r;
}

static TSS2_RC
expand_path_to_object(
    IFAPI_KEYSTORE *keystore,
    const char *path,
    const char *dir,
    char **file_name)
{

    TSS2_RC r;
    char *expanded_path = NULL;

    r = expand_path(keystore, path, &expanded_path);
    return_if_error(r, "Expand path");

    r = ifapi_asprintf(file_name, "%s/%s/%s", dir, expanded_path, IFAPI_OBJECT_FILE);
    SAFE_FREE(expanded_path);
    return r;
}

/** Store keystore parameters in the keystore context.
 *
 * Also the user directory will be created if it does not exist.
 *
 * @parm[out] keystore The keystore to be initialized.
 * @parm[in] config_systemdir The configured system directory.
 * @parm[in] config_userdir The configured user directory.
 * @parm[in] config_defaultprofile The configured profile.
 * @retval TSS2_RC_SUCCESS If the keystore can be initialized.
 * @retval TSS2_FAPI_RC_IO_ERROR If the user part of the keystore can't be
 *         initialized.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated.
 */
TSS2_RC
ifapi_keystore_initialize(
    IFAPI_KEYSTORE *keystore,
    const char *config_systemdir,
    const char *config_userdir,
    const char *config_defaultprofile)
{
    TSS2_RC r;
    char *home_dir;
    char *home_path = NULL;
    size_t start_pos;

    memset(keystore, 0, sizeof(IFAPI_KEYSTORE));

    /* Check whether usage of home directory is provided in config file */
    if (strncmp("~", config_userdir, 1) == 0) {
        start_pos = 1;
    } else if (strncmp("$HOME", config_userdir, 5) == 0) {
        start_pos = 5;
    } else {
        start_pos = 0;
    }

    /* Replace home abbreviation in user path. */
    if (start_pos) {
        LOG_DEBUG("Expanding user directory %s to user's home", config_userdir);
        home_dir = getenv("HOME");
        goto_if_null2(home_dir, "Home directory can't be determined.",
                      r, TSS2_FAPI_RC_BAD_PATH, error);

        r = ifapi_asprintf(&home_path, "%s%s%s", home_dir, IFAPI_FILE_DELIM,
                           &config_userdir[start_pos]);
        goto_if_error(r, "Out of memory.", error);
        keystore->userdir = home_path;

    } else {
        keystore->userdir = strdup(config_userdir);
        goto_if_null2(keystore->userdir, "Out of memory.", r, TSS2_FAPI_RC_MEMORY,
                      error);
    }

    /* Create user directory if necessary */
    r = ifapi_io_check_create_dir(keystore->userdir);
    goto_if_error2(r, "User directory %s can't be created.", error, keystore->userdir);

    keystore->systemdir = strdup(config_systemdir);
    goto_if_null2(keystore->systemdir, "Out of memory.", r, TSS2_FAPI_RC_MEMORY,
                  error);

    keystore->defaultprofile = strdup(config_defaultprofile);
    goto_if_null2(keystore->defaultprofile, "Out of memory.", r, TSS2_FAPI_RC_MEMORY,
                  error);

    SAFE_FREE(home_path);
    return TSS2_RC_SUCCESS;

 error:
    SAFE_FREE(keystore->defaultprofile);
    SAFE_FREE(keystore->userdir);
    SAFE_FREE(keystore->systemdir);
    return r;
}

/** Get absolute object path for FAPI relative path and check whether file exists.
 *
 *  It will be checked whether object exists in user directory, if no
 *  the path in system directory will be returnde
 *
 * @parm[in] keystore The key directories and default profile.
 * @parm[in] rel_path The relative path of the object. For keys the path will
 *           expanded if possible.
 * @parm[out] abs_path The absolute path of the object.
 * @retval TSS2_RC_SUCCESS If the object can be read.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if the file does not exist (for key objects).
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if the file does not exist (for NV and hierarchy objects).
 * @retval TSS2_FAPI_RC_IO_ERROR: If the file could not be read by the IO module.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated to hold the read data.
 */
    static TSS2_RC
rel_path_to_abs_path(
        IFAPI_KEYSTORE *keystore,
        const char *rel_path,
        char **abs_path)
{
    TSS2_RC r;
    char *directory = NULL;

    /* First expand path in user directory  */
    r = expand_path(keystore, rel_path, &directory);
    goto_if_error(r, "Expand path", cleanup);

    r = expand_path_to_object(keystore, directory,
            keystore->userdir, abs_path);
    goto_if_error2(r, "Object path %s could not be created.", cleanup, directory);


    if (!ifapi_io_path_exists(*abs_path)) {
        /* Second try system directory if object not found in user directory */
        SAFE_FREE(*abs_path);
        r = expand_path_to_object(keystore, directory,
                keystore->systemdir, abs_path);
        goto_if_error2(r, "Object path %s could not be created.", cleanup, directory);

        if (ifapi_io_path_exists(*abs_path)) {
            r = TSS2_RC_SUCCESS;
            goto cleanup;
        }

        /* Check type of object which does not exist. */
        if (ifapi_path_type_p(rel_path, IFAPI_NV_PATH) ||
                (ifapi_hierarchy_path_p(rel_path))) {
            /* Hierachy which should be created during provisioning could not be loaded. */
            goto_error(r, TSS2_FAPI_RC_PATH_NOT_FOUND,
                    "Keystore not initialized. Hierachy file %s does not exist.",
                    cleanup, rel_path);
        } else {
            /* Object file for key does not exist in keystore */
            goto_error(r, TSS2_FAPI_RC_KEY_NOT_FOUND,
                    "Key %s not found.", cleanup, rel_path);
        }
    }

cleanup:
    SAFE_FREE(directory);
    return r;
}

/** Start loading FAPI object from key store.
 *
 * Keys objects, NV objects, and hierarchies can be loaded.
 *
 * @parm[in] keystore The key directories and default profile.
 * @parm[in] io  The input/output context being used for file I/O.
 * @parm[in] path The relative path of the object. For keys the path will
 *           expanded if possible.
 * @retval TSS2_RC_SUCCESS If the object can be read.
 * @retval TSS2_FAPI_RC_IO_ERROR: if an I/O error was encountered.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if the file does not exist.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated to hold the read data.
 */
TSS2_RC
ifapi_keystore_load_async(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    const char *path)
{
    TSS2_RC r;
     char *abs_path = NULL;

     LOG_TRACE("Load object: %s", path);

     /* Free old input buffer if buffer exists */
     SAFE_FREE(io->char_rbuffer);

     /* Convert relative path to abolute path in keystore */
     r = rel_path_to_abs_path(keystore, path, &abs_path);
     goto_if_error2(r, "Object %s not found.", cleanup, path);

     /* Prepare read operation */
     r = ifapi_io_read_async(io, abs_path);

 cleanup:
     SAFE_FREE(abs_path);
     return r;
}

/** Finish loading FAPI object from key store.
 *
 * This function needs to be called repeatedly until it does not return TSS2_FAPI_RC_TRY_AGAIN.
 *
 * @parm[in] keystore The key directories and default profile.
 * @param [in, out] io The input/output context being used for file I/O.
 * @parm[in] object The caller allocated object which will loaded from keystore.
 * @retval TSS2_RC_SUCCESS After successfully loading the object.
 * @retval TSS2_FAPI_RC_IO_ERROR: if an I/O error was encountered; such as the file was not found.
 * @retval TSS2_FAPI_RC_TRY_AGAIN: if the asynchronous operation is not yet complete.
 */
TSS2_RC
ifapi_keystore_load_finish(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    IFAPI_OBJECT *object)
{
    TSS2_RC r;
    json_object *jso = NULL;
    uint8_t  *buffer = NULL;
    /* Keystore parameter is used to be prepared if transmission of state information
       between async and finish will be necessary in future extensions. */
    (void)keystore;

    r = ifapi_io_read_finish(io, &buffer, NULL);
    return_try_again(r);
    return_if_error(r, "keystore read_finish failed");

    /* If json objects can't be parse the object store is corrupted */
    jso = json_tokener_parse((char *)buffer);
    SAFE_FREE(buffer);
    return_if_null(jso, "Keystore is corrupted (Json error).", TSS2_FAPI_RC_GENERAL_FAILURE);

    r = ifapi_json_IFAPI_OBJECT_deserialize(jso, object);
    goto_if_error(r, "Deserialize object.", cleanup);

cleanup:
    SAFE_FREE(buffer);
    if (jso)
        json_object_put(jso);
    LOG_TRACE("Return %x", r);
    return r;

}

/**  Start writing FAPI object to the key store.
 *
 *  Keys objects, NV objects, and hierarchies can be written.
 *
 * @parm[in] keystore The key directories and default profile.
 * @parm[in] io  The input/output context being used for file I/O.
 * @parm[in] path The relative path of the object. For keys the path will
 *           expanded if possible.
 * @parm[in] object The object to be written to the keystore.
 * @retval TSS2_RC_SUCCESS if the object is written successfully.
 * @retval TSS2_FAPI_RC_IO_ERROR: if an I/O error was encountered;
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated to hold the output data.
 */
TSS2_RC
ifapi_keystore_store_async(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    const char *path,
    const IFAPI_OBJECT *object)
{
    TSS2_RC r;
    char *directory = NULL;
    char *file = NULL;
    char *jso_string = NULL;
    json_object *jso = NULL;

    LOG_TRACE("Store object: %s", path);

    /* Prepare write operation: Create directories and valid object path */
    r = expand_path(keystore, path, &directory);
    goto_if_error(r, "Expand path", cleanup);

    if (object->system) {
        r = ifapi_create_dirs(keystore->systemdir, directory);
        goto_if_error2(r, "Directory %s could not be created.", cleanup, directory);

        r = expand_path_to_object(keystore, directory,
                                  keystore->systemdir, &file);
    } else {
        r = ifapi_create_dirs(keystore->userdir, directory);
        goto_if_error2(r, "Directory %s could not be created.", cleanup, directory);

        r = expand_path_to_object(keystore, directory,
                                  keystore->userdir, &file);
    }
    goto_if_error2(r, "Object path %s could not be created.", cleanup, directory);

    /* Generate JSON string to be written to store */
    r = ifapi_json_IFAPI_OBJECT_serialize(object, &jso);
    goto_if_error2(r, "Object for %s could not be serialized.", cleanup, file);

    jso_string = strdup(json_object_to_json_string_ext(jso,
                                                       JSON_C_TO_STRING_PRETTY));
    goto_if_null2(jso_string, "Converting json to string", r, TSS2_FAPI_RC_MEMORY,
                  cleanup);

    /* Start writing the json string to disk */
    r = ifapi_io_write_async(io, file, (uint8_t *) jso_string, strlen(jso_string));
    free(jso_string);
    goto_if_error(r, "write_async failed", cleanup);

 cleanup:
    if (jso)
        json_object_put(jso);
    SAFE_FREE(directory);
    SAFE_FREE(file);
    return r;
}

/** Finish writing a FAPI object to the keystore.
 *
 * This function needs to be called repeatedly until it does not return TSS2_FAPI_RC_TRY_AGAIN.
 *
 * @param [in, out] io The input/output context being used for file I/O.
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_IO_ERROR: if an I/O error was encountered; such as the file was not found.
 * @retval TSS2_FAPI_RC_TRY_AGAIN: if the asynchronous operation is not yet complete.
           Call this function again later.
 */
TSS2_RC
ifapi_keystore_store_finish(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io)
{
    TSS2_RC r;

    /* Keystore parameter is used to be prepared if transmission of state infomation
       between async and finish will be necessary in future extensions. */
    (void)keystore;
    /* Finish writing the object */
    r = ifapi_io_write_finish(io);
    return_try_again(r);

    LOG_TRACE("Return %x", r);
    return_if_error(r, "read_finish failed");

    return TSS2_RC_SUCCESS;
}

static TSS2_RC
keystore_list_all_abs
(
    IFAPI_KEYSTORE *keystore,
    const char *searchpath,
    char ***results,
    size_t *numresults)
{
    TSS2_RC r;
    char *expanded_search_path = NULL, *full_search_path = NULL;
    size_t num_paths_system, num_paths_user, i, j;
    char **file_ary, **file_ary_system, **file_ary_user;

    *numresults = 0;
    file_ary_user = NULL;
    file_ary_system = NULL;

    if (!searchpath || strcmp(searchpath,"") == 0 || strcmp(searchpath,"/") == 0) {
        /* The complete keystore will be listed, no path expansion */
        expanded_search_path = NULL;
    }
    else {
        r = expand_path(keystore, searchpath, &expanded_search_path);
        return_if_error(r, "Out of memory.");
    }

    /* Get the objects from system store */
    r = ifapi_asprintf(&full_search_path, "%s%s%s", keystore->systemdir, IFAPI_FILE_DELIM,
                       expanded_search_path?expanded_search_path:"");
    goto_if_error(r, "Out of memory.", cleanup);

    r = ifapi_io_dirfiles_all(full_search_path, &file_ary_system, &num_paths_system);
    goto_if_error(r, "Get all files in directory.", cleanup);
    SAFE_FREE(full_search_path);

    /* Get the objects from user store */
    r = ifapi_asprintf(&full_search_path, "%s%s%s", keystore->userdir, IFAPI_FILE_DELIM,
                       expanded_search_path?expanded_search_path:"");
    goto_if_error(r, "Out of memory.", cleanup);

    r = ifapi_io_dirfiles_all(full_search_path, &file_ary_user, &num_paths_user);

    *numresults = num_paths_system + num_paths_user;
     SAFE_FREE(full_search_path);

    if (*numresults > 0) {

        /* Move file names from list to combined array */
        file_ary = calloc(*numresults, sizeof(char *));
        goto_if_null(file_ary, "Out of memory.", TSS2_FAPI_RC_MEMORY,
                    cleanup);
        i = 0;
        for (j = 0; j < num_paths_system; j++)
            file_ary[i++] = file_ary_system[j];
        for (j = 0; j < num_paths_user; j++)
            file_ary[i++] = file_ary_user[j];

        SAFE_FREE(file_ary_system);
        SAFE_FREE(file_ary_user);
        SAFE_FREE(expanded_search_path);
        *results = file_ary;
    }

 cleanup:
    SAFE_FREE(file_ary_system);
    SAFE_FREE(file_ary_user);
    SAFE_FREE(expanded_search_path);
    SAFE_FREE(full_search_path);
    return r;
}

/** Create a list of of objects in a certain search path.
 *
 * A vector of relative paths will be computed.
 *
 * @parm[in] keystore The key directories, the default profile.
 * @parm[in] searchpath The relative search path in key store.
 * @parm[out] results The array with pointers to the relative object paths.
 * @parm[out] numresults The number of found objects.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated.
 */
TSS2_RC
ifapi_keystore_list_all(
    IFAPI_KEYSTORE *keystore,
    const char *searchpath,
    char ***results,
    size_t *numresults)
{
    TSS2_RC r;
    size_t i;

    r = keystore_list_all_abs(keystore, searchpath, results, numresults);
    return_if_error(r, "Get all keystore objects.");

    if (*numresults > 0) {
        /* Convert absolute path to relative path */
        for (i = 0; i < *numresults; i++) {
            full_path_to_fapi_path(keystore, (*results)[i]);
        }
    }
    return r;
}

/** Remove file storing a keystore object.
 *
 * @parm[in] keystore The key directories, the default profile.
 * @parm[in] path The relative name of the object be removed.
 * @retval TSS2_RC_SUCCESS On success.
 * @retval TSS2_FAPI_RC_MEMORY: If memory could not be allocated.
 * @retval TSS2_FAPI_RC_IO_ERROR If the file can't be removed.
 */
TSS2_RC
ifapi_keystore_delete(
     IFAPI_KEYSTORE *keystore,
     char *path)
{
    TSS2_RC r;
    char *abs_path = NULL;

    /* Convert relative path to abolute path in keystore */
    r = rel_path_to_abs_path(keystore, path, &abs_path);
    goto_if_error2(r, "Object %s not found.", cleanup, path);

    r = ifapi_io_remove_file(abs_path);

 cleanup:
     SAFE_FREE(abs_path);
     return r;
}

static TSS2_RC
expand_directory(IFAPI_KEYSTORE *keystore, const char *path, char **directory_name)
{
    TSS2_RC r;

    if (path && strcmp(path,"") != 0 && strcmp(path,"/") != 0) {
        size_t start_pos = 0;
        if (path[0] == IFAPI_FILE_DELIM_CHAR)
            start_pos = 1;
        if ((strncmp(&path[start_pos], "HS", 2) == 0 ||
             strncmp(&path[start_pos], "HE", 2) == 0) &&
            strlen(&path[start_pos]) <= 3) {
            /* Root directory is hierarchy */
            r = ifapi_asprintf(directory_name, "%s/", keystore->defaultprofile,
                               path[start_pos]);
            return_if_error(r, "Out of memory.");

        } else {
            /* Try to expand a key path */
            r = expand_path(keystore, path, directory_name);
            return_if_error(r, "Out of memory.");
        }
    } else {
        *directory_name = NULL;
    }
    return TSS2_RC_SUCCESS;
}

/** Remove directories in keystore.
 *
 * If the expanded directory exists in userdir and systemdir both will be deleted.
 *
 * @parm[in] keystore The key directories, the default profile.
 * @parm[in] dir_name The relative name of the directory to be removed.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_MEMORY: If memory could not be allocated.
 * @retval TSS2_FAPI_RC_IO_ERROR If directory can't be deleted.
 */
TSS2_RC
ifapi_keystore_remove_directories(IFAPI_KEYSTORE *keystore, const char *dir_name)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    char *absolute_dir_path = NULL;
    char *exp_dir_name = NULL;
    struct stat fbuffer;

    r = expand_directory(keystore, dir_name, &exp_dir_name);
    return_if_error(r, "Expand path string.");

    /* Cleanup user part of the store */
    r = ifapi_asprintf(&absolute_dir_path, "%s%s%s", keystore->userdir, IFAPI_FILE_DELIM,
                       exp_dir_name? exp_dir_name : "");
    goto_if_error(r, "Out of memory.", cleanup);

    if (stat(absolute_dir_path, &fbuffer) == 0) {
        r = ifapi_io_remove_directories(absolute_dir_path);
        goto_if_error2(r, "Could not remove: %s", cleanup, absolute_dir_path);
    }
    SAFE_FREE(absolute_dir_path);

    /* Cleanup system part of the store */
    r = ifapi_asprintf(&absolute_dir_path, "%s%s%s",  keystore->systemdir,
                       IFAPI_FILE_DELIM, exp_dir_name? exp_dir_name : "");
    goto_if_error(r, "Out of memory.", cleanup);

    if (stat(absolute_dir_path, &fbuffer) == 0) {
        r = ifapi_io_remove_directories(absolute_dir_path);
        goto_if_error2(r, "Could not remove: %s", cleanup, absolute_dir_path);
    }

cleanup:
    SAFE_FREE(absolute_dir_path);
    SAFE_FREE(exp_dir_name);
    return r;
}

/* Predicate used as function parameter for object searching in keystore */
typedef TSS2_RC (*ifapi_keystore_object_cmp) (
    IFAPI_OBJECT *object,
    void *cmp_object,
    bool *equal);

/** Search object with a certain propoerty in keystore.
 *
 * @parm[in,out] keystore The key directories, the default profile, and the
 *               state information for the asynchronous search.
 * @parm[in] io The input/output context being used for file I/O.
 * @parm[in] name The name of the searched key.
 * @param[out] found_path The relative path of the found key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND If the key was not found in keystore.
 */
static TSS2_RC
keystore_search_obj(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    void *cmp_object,
    ifapi_keystore_object_cmp cmp_function,
    char **found_path)
{
    TSS2_RC r;
    UINT32 path_idx;
    char *path;
    IFAPI_OBJECT object;
    size_t i;

    switch (keystore->key_search.state) {
    statecase(keystore->key_search.state, KSEARCH_INIT)
        r = ifapi_keystore_list_all(keystore,
                                    "/", /**< search keys and NV objects in store */
                                    &keystore->key_search.pathlist,
                                    &keystore->key_search.numPaths);
        goto_if_error2(r, "Get entities.", cleanup);

        keystore->key_search.path_idx = keystore->key_search.numPaths;
        fallthrough;

    statecase(keystore->key_search.state, KSEARCH_SEARCH_OBJECT)
        /* Use the next object in the path list */
        if (keystore->key_search.path_idx == 0) {
            goto_error(r, TSS2_FAPI_RC_PATH_NOT_FOUND, "Key not found.", cleanup);
        }
        keystore->key_search.path_idx -= 1;
        path_idx = keystore->key_search.path_idx;
        path = keystore->key_search.pathlist[path_idx];
        LOG_TRACE("Check file: %s %zu", path, keystore->key_search.path_idx);

        r = ifapi_keystore_load_async(keystore, io, path);
        return_if_error2(r, "Could not open: %s", path);

        fallthrough;

    statecase(keystore->key_search.state, KSEARCH_READ)
        r = ifapi_keystore_load_finish(keystore, io, &object);
        return_try_again(r);
        goto_if_error(r, "read_finish failed", cleanup);

        /* Check whether the key has the passed name */
        bool keys_equal;
        r = cmp_function(&object, cmp_object, &keys_equal);
        ifapi_cleanup_ifapi_object(&object);
        goto_if_error(r, "Invalid object.", cleanup);

        if (!keys_equal) {
            /* Try next key */
            keystore->key_search.state = KSEARCH_SEARCH_OBJECT;
            return TSS2_FAPI_RC_TRY_AGAIN;
        }
        /* Key found, the absolute path will be converted to relative path. */
        path_idx = keystore->key_search.path_idx;
        *found_path = strdup(keystore->key_search.pathlist[path_idx]);
        goto_if_null(*found_path, "Out of memory.",
                     TSS2_FAPI_RC_MEMORY, cleanup);
        full_path_to_fapi_path(keystore, *found_path);
        break;

    statecasedefault(keystore->key_search.state);
    }
cleanup:
    for (i = 0; i < keystore->key_search.numPaths; i++)
        free(keystore->key_search.pathlist[i]);
    free(keystore->key_search.pathlist);
    if (!*found_path) {
        LOG_ERROR("Object not found");
        r = TSS2_FAPI_RC_KEY_NOT_FOUND;
    }
    keystore->key_search.state = KSEARCH_INIT;
    return r;
}

/** Search object with a certain name in keystore.
 *
 * @parm[in,out] keystore The key directories, the default profile, and the
 *               state information for the asynchronous search.
 * @parm[in] io The input/output context being used for file I/O.
 * @parm[in] name The name of the searched object.
 * @param[out] found_path The relative path of the found key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND If the key was not found in keystore.
 */
TSS2_RC
ifapi_keystore_search_obj(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    TPM2B_NAME *name,
    char **found_path)
{
    return keystore_search_obj(keystore, io, name,
                               ifapi_object_cmp_name, found_path);
}

/** Search nv object with a certain nv_index (from nv_public) in keystore.
 *
 * @parm[in,out] keystore The key directories, the default profile, and the
 *               state information for the asynchronous search.
 * @parm[in] io The input/output context being used for file I/O.
 * @parm[in] nv_public The public data of the searched nv object.
 * @param[out] found_path The relative path of the found key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND If the key was not found in keystore.
 */
TSS2_RC
ifapi_keystore_search_nv_obj(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    TPM2B_NV_PUBLIC *nv_public,
    char **found_path)
{
    return keystore_search_obj(keystore, io, nv_public,
                               ifapi_object_cmp_nv_public, found_path);
}

 /** Check whether keystore object already exists.
  *
  * The passed relative path will be expanded for user store and system store.
 *
 *  Keys objects, NV objects, and hierarchies can be written.
 *
 * @parm[in] keystore The key directories and default profile.
 * @parm[in] io  The input/output context being used for file I/O.
 * @parm[in] path The relative path of the object. For keys the path will
 *           expanded if possible.
 * @parm[in] system Switch whether system directory will be checked. Otherwise
             the user directory will be checked.
 * @retval TSS2_RC_SUCCESS if the object does not exist.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS if the file in objects exists.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated to hold the output data.
 */
TSS2_RC
ifapi_keystore_check_overwrite(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    const char *path)
{
    TSS2_RC r;
    char *directory = NULL;
    char *file = NULL;
    (void)io; /* Used to simplifiy future extensions */

    /* Expand relative path */
    r = expand_path(keystore, path, &directory);
    goto_if_error(r, "Expand path", cleanup);

    /* Expand absolute path for user and system directory */
    r = expand_path_to_object(keystore, directory,
                              keystore->systemdir, &file);
    goto_if_error(r, "Expand path to object", cleanup);

    if (ifapi_io_path_exists(file)) {
        goto_error(r, TSS2_FAPI_RC_PATH_ALREADY_EXISTS,
                   "Object %s already exists.", cleanup, path);
    }
    SAFE_FREE(file);
    r = expand_path_to_object(keystore, directory,
                              keystore->userdir, &file);
    goto_if_error(r, "Expand path to object", cleanup);

    if (ifapi_io_path_exists(file)) {
        goto_error(r, TSS2_FAPI_RC_PATH_ALREADY_EXISTS,
                   "Object %s already exists.", cleanup, path);
    }
    r = TSS2_RC_SUCCESS;

 cleanup:
    SAFE_FREE(directory);
    SAFE_FREE(file);
    return r;
}

/** Check whether keystore object is writeable.
 *
 * The passed relative path will be expanded first for  user store, second for
 * system store if the file does not exist in system store.
 *
 *  Keys objects, NV objects, and hierarchies can be written.
 *
 * @parm[in] keystore The key directories and default profile.
 * @parm[in] io  The input/output context being used for file I/O.
 * @parm[in] path The relative path of the object. For keys the path will
 *           expanded if possible.
 * @parm[in] system Switch whether system directory will be checked. Otherwise
             the user directory will be checked.
 * @retval TSS2_RC_SUCCESS if the object does not exist.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS if the file in objects exists.
 * @retval TSS2_FAPI_RC_MEMORY: if memory could not be allocated to hold the output data.
 */
TSS2_RC
ifapi_keystore_check_writeable(
    IFAPI_KEYSTORE *keystore,
    IFAPI_IO *io,
    const char *path)
{
    TSS2_RC r;
    char *directory = NULL;
    char *file = NULL;
    (void)io; /* Used to simplifiy future extensions */

    /* Expand relative path */
    r = expand_path(keystore, path, &directory);
    goto_if_error(r, "Expand path", cleanup);

    /* Expand absolute path for user and system directory */
    r = expand_path_to_object(keystore, directory,
                              keystore->userdir, &file);
    goto_if_error(r, "Expand path to object", cleanup);

    if (ifapi_io_path_exists(file)) {
        r = ifapi_io_check_file_writeable(file);
        goto_if_error2(r, "Object %s is not writable.", cleanup, path);

        /* File can be written */
        goto cleanup;
    } else {
        SAFE_FREE(file);
        r = expand_path_to_object(keystore, directory,
                                  keystore->systemdir, &file);
        goto_if_error(r, "Expand path to object", cleanup);

        if (ifapi_io_path_exists(file)) {
             r = ifapi_io_check_file_writeable(file);
             goto_if_error2(r, "Object %s is not writable.", cleanup, path);

             /* File can be written */
             goto cleanup;
        }
    }

 cleanup:
    SAFE_FREE(directory);
    SAFE_FREE(file);
    return r;
}

static TSS2_RC
copy_uint8_ary(UINT8_ARY *dest, const UINT8_ARY * src) {
    TSS2_RC r = TSS2_RC_SUCCESS;

    /* Check the parameters if they are valid */
    if (src ==  NULL || dest == NULL) {
        return TSS2_FAPI_RC_BAD_REFERENCE;
    }

    /* Initialize the object variables for a possible error cleanup */
    dest->buffer = NULL;

    /* Create the copy */
    dest->size = src->size;
    dest->buffer = malloc(dest->size);
    goto_if_null(dest->buffer, "Out of memory.", r, error_cleanup);
    memcpy(dest->buffer, src->buffer, dest->size);

    return r;

error_cleanup:
    SAFE_FREE(dest->buffer);
    return r;
}

TSS2_RC
ifapi_copy_ifapi_key(IFAPI_KEY * dest, const IFAPI_KEY * src) {
    TSS2_RC r = TSS2_RC_SUCCESS;

    /* Check the parameters if they are valid */
    if (src == NULL || dest == NULL) {
        return TSS2_FAPI_RC_BAD_REFERENCE;
    }

    /* Initialize the object variables for a possible error cleanup */
    dest->private.buffer = NULL;
    dest->serialization.buffer = NULL;
    dest->appData.buffer = NULL;
    dest->policyInstance = NULL;
    dest->description = NULL;

    /* Create the copy */

    r = copy_uint8_ary(&dest->private, &src->private);
    goto_if_error(r, "Could not copy private", error_cleanup);
    r =copy_uint8_ary(&dest->serialization, &src->serialization);
    goto_if_error(r, "Could not copy serialization", error_cleanup);
    r =copy_uint8_ary(&dest->appData, &src->appData);
    goto_if_error(r, "Could not copy appData", error_cleanup);

    strdup_check(dest->policyInstance, src->policyInstance, r, error_cleanup);
    strdup_check(dest->description, src->description, r, error_cleanup);
    strdup_check(dest->certificate, src->certificate, r, error_cleanup);

    dest->persistent_handle = src->persistent_handle;
    dest->public = src->public;
    dest->creationData = src->creationData;
    dest->creationTicket = src->creationTicket;
    dest->signing_scheme = src->signing_scheme;
    dest->name = src->name;
    dest->with_auth = src->with_auth;

    return r;

error_cleanup:
    ifapi_cleanup_ifapi_key(dest);
    return r;
}

/** Free memory allocated during deserialization of a key object.
 *
 * The key will not be freed (might be declared on the stack).
 *
 * @param[in] key The key object to be cleaned up.
 *
 */
void ifapi_cleanup_ifapi_key(IFAPI_KEY * key) {
    if (key != NULL) {
        SAFE_FREE(key->policyInstance);
        SAFE_FREE(key->serialization.buffer);
        SAFE_FREE(key->private.buffer);
        SAFE_FREE(key->description);
        SAFE_FREE(key->certificate);
        SAFE_FREE(key->appData.buffer);
    }
}

void ifapi_cleanup_ifapi_ext_pub_key(IFAPI_EXT_PUB_KEY * key) {
    if (key != NULL) {
        SAFE_FREE(key->pem_ext_public);
        SAFE_FREE(key->certificate);
    }
}

void ifapi_cleanup_ifapi_hierarchy(IFAPI_HIERARCHY * hierarchy) {
    if (hierarchy != NULL) {
        SAFE_FREE(hierarchy->description);
    }
}

void ifapi_cleanup_ifapi_nv(IFAPI_NV * nv) {
    if (nv != NULL) {
        SAFE_FREE(nv->serialization.buffer);
        SAFE_FREE(nv->appData.buffer);
        SAFE_FREE(nv->policyInstance);
        SAFE_FREE(nv->description);
        SAFE_FREE(nv->event_log);
    }
}

void ifapi_cleanup_ifapi_duplicate(IFAPI_DUPLICATE * duplicate) {
    if(duplicate != NULL) {
        SAFE_FREE(duplicate->certificate);
    }
}

void ifapi_cleanup_ifapi_keystore(IFAPI_KEYSTORE * keystore) {
    if (keystore != NULL) {
        SAFE_FREE(keystore->systemdir);
        SAFE_FREE(keystore->userdir);
        SAFE_FREE(keystore->defaultprofile);
    }
}

TSS2_RC
ifapi_copy_ifapi_key_object(IFAPI_OBJECT * dest, const IFAPI_OBJECT * src) {
    TSS2_RC r = TSS2_RC_SUCCESS;

    /* Check the parameters if they are valid */
    if (src == NULL || dest == NULL) {
        return TSS2_FAPI_RC_BAD_REFERENCE;
    }

    if (src->objectType != IFAPI_KEY_OBJ) {
        LOG_ERROR("Bad object type");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    /* Initialize the object variables for a possible error cleanup */

    /* Create the copy */
    dest->policy_harness = ifapi_copy_policy_harness(src->policy_harness);

    ifapi_copy_ifapi_key(&dest->misc.key, &src->misc.key);
    goto_if_error(r, "Could not copy key", error_cleanup);

    dest->objectType = src->objectType;
    dest->system = src->system;
    dest->handle = src->handle;
    dest->authorization_state = src->authorization_state;

    return r;

error_cleanup:
    ifapi_cleanup_ifapi_object(dest);
    return r;
}

/** Free memory allocated during deserialization of object.
 *
 * The object will not be freed (might be declared on the stack).
 *
 * @param[in]  object The object to be cleaned up.
 *
 */
    void
ifapi_cleanup_ifapi_object(
        IFAPI_OBJECT *object)
{
    if (object != NULL) {
        if (object->objectType != IFAPI_OBJ_NONE) {
            if (object->objectType == IFAPI_KEY_OBJ) {
                ifapi_cleanup_ifapi_key(&object->misc.key);
            } else if (object->objectType == IFAPI_NV_OBJ) {
                ifapi_cleanup_ifapi_nv(&object->misc.nv);
            } else if (object->objectType == IFAPI_DUPLICATE_OBJ) {
                ifapi_cleanup_ifapi_duplicate(&object->misc.key_tree);
            } else if (object->objectType == IFAPI_EXT_PUB_KEY_OBJ) {
                ifapi_cleanup_ifapi_ext_pub_key(&object->misc.ext_pub_key);
            } else if (object->objectType == IFAPI_HIERARCHY_OBJ) {
                ifapi_cleanup_ifapi_hierarchy(&object->misc.hierarchy);
            }

            ifapi_cleanup_policy_harness(object->policy_harness);
            SAFE_FREE(object->policy_harness);
            object->objectType = IFAPI_OBJ_NONE;
        }
    }
}
