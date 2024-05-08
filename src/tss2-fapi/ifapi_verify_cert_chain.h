/* SPDX-FileCopyrightText: 2024, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IFAPI_VERIFY_CERT_CHAIN_H
#define IFAPI_VERIFY_CERT_CHAIN_H

#include <stddef.h>       // for size_t
#include <openssl/evp.h>  // for X509, ASN1_IA5STRING, X509_CRL, DIST_..
#include "tss2_common.h"  // for TSS2_RC

TSS2_RC
ifapi_verify_cert_chain(
    char* ek_pem,
    uint8_t *cert_buf,
    size_t cert_buf_size,
    char* root_cert_pem,
    char* intermed_cert_pem);

#endif /* IFAPI_VERIFY_CERT_CHAIN_H */
