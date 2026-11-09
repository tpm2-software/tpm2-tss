/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <errno.h>       // for EEXIST, errno
#include <inttypes.h>    // for PRIu16, SCNx32, PRIi32, PRIu32
#include <json-c/json.h> // for json_object
#include <stdarg.h>      // for va_list, va_end, va_copy, va_start
#include <stdio.h>       // for sscanf, vsnprintf, vsprintf, vas...
#include <stdlib.h>      // for malloc, calloc, free
#include <string.h>      // for strcmp, strncmp, strlen, strcat
#include <strings.h>     // for strcasecmp, strncasecmp
#include <sys/stat.h>    // for mkdir, mode_t

#include "fapi_types.h"
#include "tss2_crypto.h" // for ifapi_hash_get_digest_size ...
#include "tss2_helpers.h"
#include "tss2_mu.h" // for Tss2_MU_TPMS_NV_PUBLIC_Marshal
#include "tss2_policy.h"

#define LOGMODULE fapi
#include "util/log.h" // for SAFE_FREE, goto_error, LOG_ERROR

/** Free linked list of strings.
 *
 * @param[in] node the first node of the linked list.
 */
void
free_string_list(NODE_STR_T *node) {
    NODE_STR_T *next;
    if (node == NULL)
        return;
    while (node != NULL) {
        if (node->free_string)
            free(node->str);
        next = node->next;
        free(node);
        node = next;
    }
}

/** Add a object as last element to a linked list.
 *
 * @param[in] object The object to be added.
 * @param[in,out] object_list The linked list to be extended.
 *
 * @retval TSS2_RC_SUCCESS if the object was added.
 * @retval TSS2_FAPI_RC_MEMORY If memory for the list extension cannot
 *         be allocated.
 */
TSS2_RC
append_object_to_list(void *object, NODE_OBJECT_T **object_list) {
    NODE_OBJECT_T *list;
    NODE_OBJECT_T *last = calloc(1, sizeof(NODE_OBJECT_T));
    return_if_null(last, "Out of space.", TSS2_FAPI_RC_MEMORY);
    last->object = object;
    if (!*object_list) {
        *object_list = last;
        return TSS2_RC_SUCCESS;
    }
    list = *object_list;
    while (list->next)
        list = list->next;
    list->next = last;
    return TSS2_RC_SUCCESS;
}

/** Add a object as first element to a linked list.
 *
 * @param[in] object The object to be added.
 * @param[in,out] object_list The linked list to be extended.
 *
 * @retval TSS2_RC_SUCCESS if the object was added.
 * @retval TSS2_FAPI_RC_MEMORY If memory for the list extension cannot
 *         be allocated.
 */
TSS2_RC
push_object_to_list(void *object, NODE_OBJECT_T **object_list) {
    NODE_OBJECT_T *first = calloc(1, sizeof(NODE_OBJECT_T));
    return_if_null(first, "Out of space.", TSS2_FAPI_RC_MEMORY);
    first->object = object;
    if (*object_list)
        first->next = *object_list;
    *object_list = first;
    return TSS2_RC_SUCCESS;
}

/** Print to allocated string.
 *
 * A list of parameters will be printed to an allocated string according to the
 * format description in the first parameter.
 *
 * @param[out] str The allocated output string.
 * @param[in] fmt The format string (printf formats can be used.)
 * @param[in] ... The list of objects to be printed.
 *
 * @retval TSS2_RC_SUCCESS If the printing was successful.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_asprintf(char **str, const char *fmt, ...) {
    int     size = 0;
    va_list args;
    va_start(args, fmt);
    size = vasprintf(str, fmt, args);
    va_end(args);
    if (size == -1)
        return TSS2_FAPI_RC_MEMORY;
    return TSS2_RC_SUCCESS;
}

/** Check valid keys of a json object.
 *
 * @param[in]  jso The json object.
 * @param[out] field_tab the array of strings with allowed fields.
 * @param[out] size_of_tab The number of allowed fields.
 *
 * If a unexpected field occurs a warning will be displayed.
 */
void
ifapi_check_json_object_fields(json_object *jso, char **field_tab, size_t size_of_tab) {
    enum json_type type;
    bool           found;
    size_t         i;

    type = json_object_get_type(jso);
    if (type == json_type_object) {
        /* Object with keys. */
        json_object_object_foreach(jso, key, val) {
            UNUSED(val);
            found = false;
            for (i = 0; i < size_of_tab; i++) {
                if (strcmp(key, field_tab[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                LOG_WARNING("Invalid field: %s", key);
            }
        }
    }
}

/** Compute the number on nodes in a linked list.
 *
 * @param[in] node the first node of the linked list.
 *
 * @retval the number on nodes.
 */
size_t
ifapi_path_length(NODE_STR_T *node) {
    size_t length = 0;
    if (node == NULL)
        return 0;
    while (node != NULL) {
        length += 1;
        node = node->next;
    }
    return length;
}

/** Free linked list of IFAPI objects (link nodes only).
 *
 * @param[in] node the first node of the linked list.
 */
void
ifapi_free_node_list(NODE_OBJECT_T *node) {
    NODE_OBJECT_T *next;
    if (node == NULL)
        return;
    while (node != NULL) {
        next = node->next;
        free(node);
        node = next;
    }
}

/** Compute the name of a TPM transient or persistent object.
 *
 * @param[in] publicInfo The public information of the TPM object.
 * @param[out] name The computed name.
 * @retval TPM2_RC_SUCCESS  or one of the possible errors TSS2_FAPI_RC_BAD_VALUE,
 * TSS2_FAPI_RC_MEMORY, TSS2_FAPI_RC_GENERAL_FAILURE.
 * or return codes of SAPI errors.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 */
TSS2_RC
ifapi_get_name(TPMT_PUBLIC *publicInfo, TPM2B_NAME *name) {
    BYTE                       buffer[sizeof(TPMT_PUBLIC)];
    size_t                     offset = 0;
    size_t                     len_alg_id = sizeof(TPMI_ALG_HASH);
    size_t                     size = sizeof(TPMU_NAME) - sizeof(TPMI_ALG_HASH);
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;

    if (publicInfo->nameAlg == TPM2_ALG_NULL) {
        name->size = 0;
        return TSS2_RC_SUCCESS;
    }
    TSS2_RC r;
    r = ifapi_crypto_hash_start(&cryptoContext, publicInfo->nameAlg);
    return_if_error(r, "crypto hash start");

    r = Tss2_MU_TPMT_PUBLIC_Marshal(publicInfo, &buffer[0], sizeof(TPMT_PUBLIC), &offset);
    if (r) {
        LOG_ERROR("Marshaling TPMT_PUBLIC");
        ifapi_crypto_hash_abort(&cryptoContext);
        return r;
    }

    r = ifapi_crypto_hash_update(cryptoContext, &buffer[0], offset);
    if (r) {
        LOG_ERROR("crypto hash update");
        ifapi_crypto_hash_abort(&cryptoContext);
        return r;
    }

    r = ifapi_crypto_hash_finish(&cryptoContext, &name->name[len_alg_id], &size);
    if (r) {
        LOG_ERROR("crypto hash finish");
        ifapi_crypto_hash_abort(&cryptoContext);
        return r;
    }

    offset = 0;
    r = Tss2_MU_TPMI_ALG_HASH_Marshal(publicInfo->nameAlg, &name->name[0], sizeof(TPMI_ALG_HASH),
                                      &offset);
    return_if_error(r, "Marshaling TPMI_ALG_HASH");

    name->size = size + len_alg_id;
    return TSS2_RC_SUCCESS;
}

/** Compute the name from the public data of a NV index.
 *
 * The name of a NV index is computed as follows:
 *   name = nameAlg||Hash(nameAlg,marshal(publicArea))
 * @param[in] publicInfo The public information of the NV index.
 * @param[out] name The computed name.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_MEMORY Memory can not be allocated.
 * @retval TSS2_FAPI_RC_BAD_VALUE for invalid parameters.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE for unexpected NULL pointer parameters.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE for errors of the crypto library.
 * @retval TSS2_SYS_RC_* for SAPI errors.
 */
TSS2_RC
ifapi_nv_get_name(TPMS_NV_PUBLIC *publicInfo, TPM2B_NAME *name) {
    BYTE                       buffer[sizeof(TPMS_NV_PUBLIC)];
    size_t                     offset = 0;
    size_t                     size = sizeof(TPMU_NAME) - sizeof(TPMI_ALG_HASH);
    size_t                     len_alg_id = sizeof(TPMI_ALG_HASH);
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;

    if (publicInfo->nameAlg == TPM2_ALG_NULL) {
        name->size = 0;
        return TSS2_RC_SUCCESS;
    }
    TSS2_RC r;

    /* Initialize the hash computation with the nameAlg. */
    r = ifapi_crypto_hash_start(&cryptoContext, publicInfo->nameAlg);
    return_if_error(r, "Crypto hash start");

    /* Get the marshaled data of the public area. */
    r = Tss2_MU_TPMS_NV_PUBLIC_Marshal(publicInfo, &buffer[0], sizeof(TPMS_NV_PUBLIC), &offset);
    if (r) {
        LOG_ERROR("Marshaling TPMS_NV_PUBLIC");
        ifapi_crypto_hash_abort(&cryptoContext);
        return r;
    }

    r = ifapi_crypto_hash_update(cryptoContext, &buffer[0], offset);
    if (r) {
        LOG_ERROR("crypto hash update");
        ifapi_crypto_hash_abort(&cryptoContext);
        return r;
    }

    /* The hash will be stored after the nameAlg.*/
    r = ifapi_crypto_hash_finish(&cryptoContext, &name->name[len_alg_id], &size);
    if (r) {
        LOG_ERROR("crypto hash finish");
        ifapi_crypto_hash_abort(&cryptoContext);
        return r;
    }

    offset = 0;
    /* Store the nameAlg in the result. */
    r = Tss2_MU_TPMI_ALG_HASH_Marshal(publicInfo->nameAlg, &name->name[0], sizeof(TPMI_ALG_HASH),
                                      &offset);
    return_if_error(r, "Marshaling TPMI_ALG_HASH");

    name->size = size + len_alg_id;
    return TSS2_RC_SUCCESS;
}

/**  Compute the name of a hierarchy object.
 *
 * The TPM handle will be computed from the esys handle and the name
 * will be computed from the TPM handle.
 *
 * @param[in,out] hierarchy The hierarchy object.
 */
static void
set_name_hierarchy_object(IFAPI_OBJECT *object) {
    TPM2_HANDLE handle = 0;
    size_t      offset = 0;
    switch (object->public.handle) {
    case ESYS_TR_RH_NULL:
        handle = TPM2_RH_NULL;
        break;
    case ESYS_TR_RH_OWNER:
        handle = TPM2_RH_OWNER;
        break;
    case ESYS_TR_RH_ENDORSEMENT:
        handle = TPM2_RH_ENDORSEMENT;
        break;
    case ESYS_TR_RH_LOCKOUT:
        handle = TPM2_RH_LOCKOUT;
        break;
    case ESYS_TR_RH_PLATFORM:
        handle = TPM2_RH_PLATFORM;
        break;
    case ESYS_TR_RH_PLATFORM_NV:
        handle = TPM2_RH_PLATFORM_NV;
        break;
    default:
        /* Invalid esys handle for a hierarchy */
        LOG_ERROR("This code should not be reachable");
        handle = 0xFFFFFFFF;
        break;
    }
    Tss2_MU_TPM2_HANDLE_Marshal(handle, &object->misc.hierarchy.name.name[0], sizeof(TPM2_HANDLE),
                                &offset);
    object->misc.hierarchy.name.size = offset;
}

/**  Initialize a hierarchy object read from a file.
 *
 * The esys handles will be set depending on the object path and the
 * object name will be computed.
 *
 * @param[in,out]> hierarchy The caller allocated hierarchy object.
 * @retval TSS2_RC_SUCCESS if the hierarchy could be initialized.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE For an invalid hierarchy path.
 */
TSS2_RC
ifapi_set_name_hierarchy_object(IFAPI_OBJECT *object) {
    const char *path = object->rel_path;
    size_t      pos = 0, pos2;
    if (path) {
        /* Determine esys handle from pathname. */
        if (strncmp("/", &path[0], 1) == 0)
            pos += 1;
        /* Skip profile if it does exist in path */
        if (strncmp("P_", &path[pos], 2) == 0) {
            const char *start = strchr(&path[pos], TSS2_FILE_DELIM_CHAR);
            if (start) {
                pos2 = (int)(start - &path[pos]);
                pos = pos2 + 2;
            } else {
                return_error(TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid path.");
            }
        }
        if (strcmp(&path[pos], "HS") == 0) {
            object->public.handle = ESYS_TR_RH_OWNER;
            object->misc.hierarchy.esysHandle = ESYS_TR_RH_OWNER;
        } else if (strcmp(&path[pos], "HE") == 0) {
            object->public.handle = ESYS_TR_RH_ENDORSEMENT;
            object->misc.hierarchy.esysHandle = ESYS_TR_RH_ENDORSEMENT;
        } else if (strcmp(&path[pos], "LOCKOUT") == 0) {
            object->public.handle = ESYS_TR_RH_LOCKOUT;
            object->misc.hierarchy.esysHandle = ESYS_TR_RH_LOCKOUT;
        } else if (strcmp(&path[pos], "HN") == 0) {
            object->public.handle = ESYS_TR_RH_NULL;
            object->misc.hierarchy.esysHandle = ESYS_TR_RH_NULL;
        }
    }
    set_name_hierarchy_object(object);
    return TSS2_RC_SUCCESS;
}

/** Initialize the internal representation of a FAPI hierarchy object.
 *
 * The object will be cleared and the type of the general fapi object will be
 * set to hierarchy.
 *
 * @param[in,out] hierarchy The caller allocated hierarchy object. The name of the
 *                object will be computed.
 * @param[in] esys_handle The ESAPI handle of the hierarchy which will be added to
 *            to the object.
 */
void
ifapi_init_hierarchy_object(IFAPI_OBJECT *hierarchy, ESYS_TR esys_handle) {
    memset(hierarchy, 0, sizeof(IFAPI_OBJECT));
    hierarchy->system = TPM2_YES;
    hierarchy->objectType = IFAPI_HIERARCHY_OBJ;
    hierarchy->public.handle = esys_handle;
    hierarchy->misc.hierarchy.esysHandle = esys_handle;
    set_name_hierarchy_object(hierarchy);
}
