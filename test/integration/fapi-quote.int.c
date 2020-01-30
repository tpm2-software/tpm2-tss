/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <json-c/json.h>
#include <json-c/json_util.h>
#include <json-c/json_tokener.h>

#include "tss2_fapi.h"

#include "test-fapi.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#define EVENT_SIZE 10

/** Test the FAPI functions for quote commands.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_CreateKey()
 *  - Fapi_Quote()
 *  - Fapi_Delete()
 *  - Fapi_List()
 *  - Fapi_VerifyQuote()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_quote(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    json_object *jso = NULL;
    char *pubkey_pem = NULL;
    uint8_t *signature = NULL;
    char *quoteInfo = NULL;
    char *pcrEventLog = NULL;
    char *certificate = NULL;
    char *export_data = NULL;
    json_object *jso_public = NULL;
    uint8_t *pcr_digest = NULL;
    char *log = NULL;
    char *pathlist = NULL;

    uint8_t data[EVENT_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    size_t signatureSize = 0;
    uint32_t pcrList[1] = { 16 };
    size_t pcr_digest_size = 0;

    r = Fapi_Provision(context, NULL, NULL, NULL);

    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_CreateKey(context, "HS/SRK/mySignKey", "sign,noDa", "", NULL);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    uint8_t qualifyingData[20] = {
        0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
        0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f
    };

    r = pcr_reset(context, 16);
    goto_if_error(r, "Error pcr_reset", error);

    r = Fapi_PcrExtend(context, 16, data, EVENT_SIZE, "{ \"test\": \"myfile\" }");
    goto_if_error(r, "Error Fapi_PcrExtend", error);

    r = Fapi_Quote(context, pcrList, 1, "HS/SRK/mySignKey",
                   "TPM-Quote",
                   qualifyingData, 20,
                   &quoteInfo,
                   &signature, &signatureSize,
                   &pcrEventLog, &certificate);
    goto_if_error(r, "Error Fapi_Quote", error);

    r = Fapi_ExportKey(context, "HS/SRK/mySignKey", NULL, &export_data);
    goto_if_error(r, "Export.", error);

    jso = json_tokener_parse(export_data);

    LOG_INFO("\nExported: %s\n", export_data);

    if (!jso || !json_object_object_get_ex(jso, "pem_ext_public",  &jso_public)) {
        LOG_ERROR("No public key eyported.");
        goto error;
    }
    pubkey_pem = strdup(json_object_get_string(jso_public));
    if (!pubkey_pem) {
        LOG_ERROR("Out of memory.");
        goto error;
    }

    r = Fapi_Import(context, "/ext/myExtPubKey", pubkey_pem);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_PcrRead(context, 16, &pcr_digest,
                     &pcr_digest_size, &log);
    goto_if_error(r, "Error Fapi_PcrRead", error);

    LOG_INFO("\nLog:\n%s\n", log);
    LOG_INFO("Quote Info:\n%s\n", quoteInfo);

    r = Fapi_VerifyQuote(context, "HS/SRK/mySignKey",
                         qualifyingData, 20,  quoteInfo,
                         signature, signatureSize, log);
    goto_if_error(r, "Error Fapi_Verfiy_Quote", error);

    r = Fapi_Delete(context, "/HS/SRK");
    goto_if_error(r, "Error Fapi_Delete", error);

    r = Fapi_List(context, "/", &pathlist);
    goto_if_error(r, "Pathlist", error);

    json_object_put(jso);
    SAFE_FREE(pubkey_pem);
    SAFE_FREE(signature);
    SAFE_FREE(quoteInfo);
    SAFE_FREE(pcrEventLog);
    SAFE_FREE(certificate);
    SAFE_FREE(export_data);
    SAFE_FREE(pcr_digest);
    SAFE_FREE(log);
    SAFE_FREE(pathlist);
    return EXIT_SUCCESS;

error:
    if (jso)
        json_object_put(jso);
    SAFE_FREE(pubkey_pem);
    SAFE_FREE(signature);
    SAFE_FREE(quoteInfo);
    SAFE_FREE(pcrEventLog);
    SAFE_FREE(certificate);
    SAFE_FREE(export_data);
    SAFE_FREE(pcr_digest);
    SAFE_FREE(log);
    SAFE_FREE(pathlist);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_quote(fapi_context);
}
