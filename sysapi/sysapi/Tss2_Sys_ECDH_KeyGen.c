/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
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
 ***********************************************************************/

#include "sapi/tpm20.h"
#include "sysapi_util.h"

TPM_RC Tss2_Sys_ECDH_KeyGen_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT keyHandle)
{
    TPM_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM_CC_ECDH_KeyGen);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, SYS_CONTEXT->tpmInBuffPtr,
                                  SYS_CONTEXT->maxCommandSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 1;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TPM_RC Tss2_Sys_ECDH_KeyGen_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT *zPoint,
    TPM2B_ECC_POINT *pubPoint)
{
    TPM_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(sysContext);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_ECC_POINT_Unmarshal(SYS_CONTEXT->tpmInBuffPtr,
                                             SYS_CONTEXT->maxCommandSize,
                                             &SYS_CONTEXT->nextData,
                                             zPoint);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_ECC_POINT_Unmarshal(SYS_CONTEXT->tpmInBuffPtr,
                                             SYS_CONTEXT->maxCommandSize,
                                             &SYS_CONTEXT->nextData,
                                             pubPoint);
}

TPM_RC Tss2_Sys_ECDH_KeyGen(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT keyHandle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPM2B_ECC_POINT *zPoint,
    TPM2B_ECC_POINT *pubPoint,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    rval = Tss2_Sys_ECDH_KeyGen_Prepare(sysContext, keyHandle);
    if (rval)
        return rval;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_ECDH_KeyGen_Complete(sysContext, zPoint, pubPoint);
}
