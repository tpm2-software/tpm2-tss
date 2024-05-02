/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IFAPI_CURL_H
#define IFAPI_CURL_H

#include <stddef.h>       // for size_t

#include "tss2_common.h"  // for TSS2_RC

TSS2_RC
ifapi_curl_verify_ek_cert(
    char* root_cert_pem,
    char* intermed_cert_pem,
    char* ek_cert_pem);

int
ifapi_get_curl_buffer(
    unsigned char * url,
    unsigned char ** buffer,
    size_t *cert_size);

#endif /* IFAPI_CURL_H */
