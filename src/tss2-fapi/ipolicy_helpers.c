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

#include "ipolicy_helpers.h"
#include "tss2_helpers.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE fapi
#include "util/log.h" // for SAFE_FREE, goto_error, LOG_ERROR

/** Compare two variables of type TPM2B_ECC_PARAMETER.
 *
 * @param[in] in1 variable to be compared with in2.
 * @param[in] in2 variable to be compared with in1.
 *
 * @retval true if the variables are equal.
 * @retval false if not.
 */
bool
ipolicy_TPM2B_ECC_PARAMETER_cmp(TPM2B_ECC_PARAMETER *in1, TPM2B_ECC_PARAMETER *in2) {

    if (in1->size != in2->size)
        return false;

    return memcmp(&in1->buffer[0], &in2->buffer[0], in1->size) == 0;
}

/** Compare two variables of type TPMS_ECC_POINT.
 *
 * @param[in] in1 variable to be compared with in2.
 * @param[in] in2 variable to be compared with in1.
 *
 * @retval true if the variables are equal.
 * @retval false if not.
 */
bool
ipolicy_TPMS_ECC_POINT_cmp(TPMS_ECC_POINT *in1, TPMS_ECC_POINT *in2) {
    LOG_TRACE("call");

    if (!ipolicy_TPM2B_ECC_PARAMETER_cmp(&in1->x, &in2->x))
        return false;

    if (!ipolicy_TPM2B_ECC_PARAMETER_cmp(&in1->y, &in2->y))
        return false;

    return true;
}

/**  Compare two variables of type TPM2B_DIGEST.
 *
 * @param[in] in1 variable to be compared with in2.
 * @param[in] in2 variable to be compared with in1.
 *
 * @retval true if the variables are equal.
 * @retval false if not.
 */
bool
ipolicy_TPM2B_DIGEST_cmp(TPM2B_DIGEST *in1, TPM2B_DIGEST *in2) {

    if (in1->size != in2->size)
        return false;

    return memcmp(&in1->buffer[0], &in2->buffer[0], in1->size) == 0;
}

/** Compare two variables of type TPM2B_PUBLIC_KEY_RSA.
 *
 * @param[in] in1 variable to be compared with in2
 * @param[in] in2 variable to be compared with in1
 *
 * @retval true if the variables are equal.
 * @retval false if not.
 */
bool
ipolicy_TPM2B_PUBLIC_KEY_RSA_cmp(TPM2B_PUBLIC_KEY_RSA *in1, TPM2B_PUBLIC_KEY_RSA *in2) {

    if (in1->size != in2->size)
        return false;

    return memcmp(&in1->buffer[0], &in2->buffer[0], in1->size) == 0;
}

/**  Compare two variables of type TPMU_PUBLIC_ID.
 *
 * @param[in] in1 variable to be compared with in2.
 * @param[in] selector1 key type of first key.
 * @param[in] in2 variable to be compared with in1.
 * @param[in] selector2 key type of second key.
 *
 * @result true if variables are equal.
 * @result false if not.
 */
bool
ipolicy_TPMU_PUBLIC_ID_cmp(TPMU_PUBLIC_ID *in1,
                           UINT32          selector1,
                           TPMU_PUBLIC_ID *in2,
                           UINT32          selector2) {

    if (selector1 != selector2)
        return false;

    switch (selector1) {
    case TPM2_ALG_KEYEDHASH:
        if (!ipolicy_TPM2B_DIGEST_cmp(&in1->keyedHash, &in2->keyedHash))
            return false;
        break;
    case TPM2_ALG_SYMCIPHER:
        if (!ipolicy_TPM2B_DIGEST_cmp(&in1->sym, &in2->sym))
            return false;
        break;
    case TPM2_ALG_RSA:
        if (!ipolicy_TPM2B_PUBLIC_KEY_RSA_cmp(&in1->rsa, &in2->rsa))
            return false;
        break;
    case TPM2_ALG_ECC:
        if (!ipolicy_TPMS_ECC_POINT_cmp(&in1->ecc, &in2->ecc))
            return false;
        break;
    default:
        return false;
    };
    return true;
}

/**
 * Compare the PUBLIC_ID stored in two  TPMT_PUBLIC structures.
 * @param[in] in1 the public data with the unique data to be compared with:
 * @param[in] in2
 *
 * @retval true if the variables are equal.
 * @retval false if not.
 */
bool
ipolicy_TPMT_PUBLIC_cmp(TPMT_PUBLIC *in1, TPMT_PUBLIC *in2) {

    if (!ipolicy_TPMU_PUBLIC_ID_cmp(&in1->unique, in1->type, &in2->unique, in2->type))
        return false;

    return true;
}
