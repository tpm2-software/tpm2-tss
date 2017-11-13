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

TSS2_RC Tss2_Sys_PP_Commands_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM auth,
    TPML_CC *setList,
    TPML_CC *clearList)
{
    TSS2_RC rval;

    if (!sysContext || !setList || !clearList)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(sysContext, TPM_CC_PP_Commands);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(auth, SYS_CONTEXT->cmdBuffer,
                                  SYS_CONTEXT->maxCmdSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_CC_Marshal(setList, SYS_CONTEXT->cmdBuffer,
                                   SYS_CONTEXT->maxCmdSize,
                                   &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_CC_Marshal(clearList, SYS_CONTEXT->cmdBuffer,
                                   SYS_CONTEXT->maxCmdSize,
                                   &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->authAllowed = 1;

    return CommonPrepareEpilogue(sysContext);
}

TSS2_RC Tss2_Sys_PP_Commands(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM auth,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TPML_CC *setList,
    TPML_CC *clearList,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if (!setList || !clearList)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PP_Commands_Prepare(sysContext, auth, setList, clearList);
    if (rval)
        return rval;

    return CommonOneCallForNoResponseCmds(sysContext, cmdAuthsArray, rspAuthsArray);
}
