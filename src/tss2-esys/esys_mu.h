/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
#ifndef ESYS_MU_H
#define ESYS_MU_H

#include "tss2_mu.h"

#include "esys_types.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#define ESYS_MAX_SIZE_METADATA 3072

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_Marshal(
    const IESYSC_RESOURCE_TYPE_CONSTANT in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_RESOURCE_TYPE_CONSTANT *out);

TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_check(
    const IESYSC_RESOURCE_TYPE_CONSTANT *in);

TSS2_RC
Tss2_MU_IESYSC_PARAM_ENCRYPT_Marshal(
    const IESYSC_PARAM_ENCRYPT in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYSC_PARAM_ENCRYPT_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_PARAM_ENCRYPT *out);

TSS2_RC
Tss2_MU_IESYSC_PARAM_ENCRYPT_check(
    const IESYSC_PARAM_ENCRYPT *in);

TSS2_RC
Tss2_MU_IESYSC_PARAM_DECRYPT_Marshal(
    const IESYSC_PARAM_DECRYPT in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYSC_PARAM_DECRYPT_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_PARAM_DECRYPT *out);

TSS2_RC
Tss2_MU_IESYSC_PARAM_DECRYPT_check(
    const IESYSC_PARAM_DECRYPT *in);

TSS2_RC
Tss2_MU_IESYSC_TYPE_POLICY_AUTH_Marshal(
    const IESYSC_TYPE_POLICY_AUTH in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYSC_TYPE_POLICY_AUTH_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_TYPE_POLICY_AUTH *out);

TSS2_RC
Tss2_MU_IESYSC_TYPE_POLICY_AUTH_check(
    const IESYSC_TYPE_POLICY_AUTH *in);

TSS2_RC
Tss2_MU_IESYS_SESSION_Marshal(
    const IESYS_SESSION *in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYS_SESSION_Unmarshal(const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_SESSION *out);


TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_Marshal(
    const IESYSC_RESOURCE_TYPE in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_RESOURCE_TYPE *out);

TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_check(
    const IESYSC_RESOURCE_TYPE *in);

TSS2_RC
Tss2_MU_IESYS_RSRC_UNION_Marshal(
    const IESYS_RSRC_UNION *in,
    UINT32 selector,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYS_RSRC_UNION_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    UINT32 selector,
    IESYS_RSRC_UNION *out);


TSS2_RC
Tss2_MU_IESYS_RESOURCE_Marshal(
    const IESYS_RESOURCE *in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYS_RESOURCE_Unmarshal(const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_RESOURCE *out);


TSS2_RC
Tss2_MU_IESYS_METADATA_Marshal(
    const IESYS_METADATA *in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYS_METADATA_Unmarshal(const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_METADATA *out);


TSS2_RC
Tss2_MU_IESYS_CONTEXT_DATA_Marshal(
    const IESYS_CONTEXT_DATA *in,
    uint8_t *buffer,
    size_t size,
    size_t *offset);

TSS2_RC
Tss2_MU_IESYS_CONTEXT_DATA_Unmarshal(const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_CONTEXT_DATA *out);


#ifdef __cplusplus
}
#endif

#endif /* ESYS_MU_H */
