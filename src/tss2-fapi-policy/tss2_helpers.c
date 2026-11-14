/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <errno.h>    // for EEXIST, errno
#include <inttypes.h> // for PRIu16, SCNx32, PRIi32, PRIu32
#include <stdarg.h>   // for va_list, va_end, va_copy, va_start
#include <stdio.h>    // for sscanf, vsnprintf, vsprintf, vas...
#include <stdlib.h>   // for malloc, calloc, free
#include <string.h>   // for strcmp, strncmp, strlen, strcat
#include <strings.h>  // for strcasecmp, strncasecmp
#include <sys/stat.h> // for mkdir, mode_t

#include "tss2_crypto.h" // for ifapi_hash_get_digest_size ...
#include "tss2_helpers.h"
#include "tss2_mu.h" // for Tss2_MU_TPMS_NV_PUBLIC_Marshal
#include "tss2_policy.h"
#include "tss2_types.h"

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
tss2_free_node_list(NODE_OBJECT_T *node) {
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
 * @retval TPM2_RC_SUCCESS  or one of the possible errors
 * TSS2_FAPI_RC_BAD_VALUE, TSS2_FAPI_RC_MEMORY, TSS2_FAPI_RC_GENERAL_FAILURE. or
 * return codes of SAPI errors.
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
