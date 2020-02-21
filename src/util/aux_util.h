/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef AUX_UTIL_H
#define AUX_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#define SAFE_FREE(S) if((S) != NULL) {free((void*) (S)); (S)=NULL;}

#define TPM2_ERROR_FORMAT "%s%s (0x%08x)"
#define TPM2_ERROR_TEXT(r) "Error", "Code", r

#define PARAM_ERR (TPM2_RC_P | TPM2_RC_1)
#define not_expected_param_err(r) ({ \
    TSS2_RC _r = r; \
    if ((_r & PARAM_ERR) == PARAM_ERR) { \
        _r &= ~PARAM_ERR; \
    } \
    (_r != TPM2_RC_CURVE && _r != TPM2_RC_HASH && \
     _r != TPM2_RC_ASYMMETRIC && _r != TPM2_RC_KEY_SIZE); \
})

#define return_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        if (not_expected_param_err(r)) \
            LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }

#define return_state_if_error(r,s,msg)      \
    if (r != TSS2_RC_SUCCESS) { \
        if (not_expected_param_err(r)) \
            LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        esysContext->state = s; \
        return r;  \
    }

#define return_error(r,msg) \
    { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }

#define goto_state_if_error(r,s,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        if (not_expected_param_err(r)) \
            LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        esysContext->state = s; \
        goto label;  \
    }

#define goto_if_null(p,msg,ec,label) \
    if ((p) == NULL) { \
        LOG_ERROR("%s ", (msg)); \
        r = (ec); \
        goto label;  \
    }

#define goto_if_error(r,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        if (not_expected_param_err(r)) \
            LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        goto label;  \
    }

#define goto_error(r,v,msg,label, ...)              \
    { r = v;  \
      LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ## __VA_ARGS__); \
      goto label; \
    }

#define return_if_null(p,msg,ec) \
    if (p == NULL) { \
        LOG_ERROR("%s ", msg); \
        return ec; \
    }

#define return_if_notnull(p,msg,ec) \
    if (p != NULL) { \
        LOG_ERROR("%s ", msg); \
        return ec; \
    }

#define exit_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        if (not_expected_param_err(r)) \
            LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        exit(1);  \
    }

#define set_return_code(r_max, r, msg) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        r_max = r; \
    }

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AUX_UTIL_H */
