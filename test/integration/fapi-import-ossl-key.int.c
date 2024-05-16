/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <json.h>         // for json_object_put, json_object_get_string
#include <stdio.h>        // for NULL
#include <stdlib.h>       // for EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>       // for strcmp, strdup, strlen, strncmp

#include "test-fapi.h"    // for ASSERT, ASSERT_SIZE, test_invoke_fapi
#include "tss2_common.h"  // for TSS2_RC
#include "tss2_fapi.h"    // for Fapi_Delete, Fapi_ExportKey, Fapi_Import

#define LOGMODULE test
#include "util/log.h"     // for LOG_ERROR, SAFE_FREE, goto_if_error, LOG_INFO

#define SIZE 2000

/** Test the FAPI functions for key duplication.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_Import()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

const char *priv_rsa_pem =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAwBgOktII9d+oYJQLUhQYPk8Ad6dW54ak8XWLdMtNx7161kgQ\n"
    "sohndq3WUZ10mR/lf/GVPYNHj5+vR28BQ3In0GZgYGNSiE+6drSq6h+VyaYzDRQG\n"
    "b2CUKqNSMhl5FAqhCs6kM8GeXI6FZhnur3gNv4S+hcra9is9mwzucLnt1Maqu5/D\n"
    "7HgXJrWmn5JTg8OlZMiYnqD91LD+nx9ZYWxCQzwUBDVaEXQtndvF5neTALOXro1B\n"
    "awMMqjlMug0IFA46MOo2mvOWaRWm4JgVS50lj+cye7nobQbw6gkF/kb1VbiEvi/L\n"
    "/vbnQCtDlvjx9a97QKuphp2sGtOM/K8c9yuXMwIDAQABAoIBADPYSlamCXUS4Ebw\n"
    "rf2BHunyOJYSvAnQ9UOWDgV/uYZnRXgAC0GkPwhw8p8keAu76B0X/seTXwUMfCoz\n"
    "c4vYi5Zbizd4lxXjLthK+rYlwC+kg7LL7NCyqEq5ub170onuNHjOPNMbNrqUXLyp\n"
    "0xnYtR0znphNn7tBAGeQneoexGngnPnImUh4+wwJReUaDO6Kozu4ETd/1TWa1xLY\n"
    "VzMWWLuU+adUmjY+AvEOHXva7P2c4B1d+FS16JHSxGN0i/cPyZBMx3DEAGP3JIN8\n"
    "zpMmMlUmG3yuX3w0atWXkvA/lPYajIiRASdzBFri8dLt4euR/I88DUYAT0gelvl7\n"
    "IoPnOUECgYEA5lqTe7NNnLJNFqWd96Xu2ga44711oIOuTBLgiuHjTnDwUicBRjMY\n"
    "rzPx7Ya3kJds9SLatyswWAvlr3oBidRg/HH/IMejinySGLgbaJOB2srAXMuHD4/k\n"
    "pMrHC7CSGglgvXkNFH+4FIny5n1CHcsRA8cHFfUGbW5FYRaNnuJyvgcCgYEA1XsE\n"
    "09gbBy0jaTZHdn0Km82+7uTb+9zgtG8TeTskR7zLC3Daq2O896dhPYqVnrZ6MSj1\n"
    "9cZGTEzhtT5LaipvDkXU27yvUhcDfZAYYBIAlQ40mpkDxzorHGPEdZ3opxzg1E8D\n"
    "UHEs0kdsoVQS7FgugEHTZ2zOZc2VtenOL3of0nUCgYEApnQbEI8PbUSWWeARVwur\n"
    "nhavcbnNDtE4mLYnVZRHCb6omeSfkheIJcpWbnojmTMiw7yM6UEnLOhj77os9Gjo\n"
    "MGM7pXc9YOwFMiGPhLDaa7yI5kUX8pHa+Y2h6XuNB41xP1kCr6Ze4VCRmiY3KYo8\n"
    "YEtofmBRZbACKFcAvSgLG+8CgYEAublk4cjI+t1SSV5nnbX7XMEKs1t35w6qj09z\n"
    "aa0CS0b8ft+X3jPPWsXL23aN5J5sgAhas4/j6M2aL8waYCq6o3gtT15ASPKsnriV\n"
    "/D6tMwBA0577ooAAsZo6ePkARyLgltSG1Z0gmXB6GYDDVcsB6aNbAEew6PCKptDa\n"
    "CIP+22ECgYBWe2OzDxPVj04WDCcyaQIURFtjYjL+Z7FQD9iQX9ux4a+qBdNkEdEs\n"
    "CRawbM1vO4VgjLzqg5QSl+OM8CAr7jiSAxqUCCe/25VrxZi+QqDMZ2a0wzz00dSZ\n"
    "N1DbUyfqzTzv0jCTEPNbtSjDc/SMuLPWB1G9wvz6LRZxOgeGgaQQGQ==\n"
    "-----END RSA PRIVATE KEY-----\n";

const char *priv_ecc_pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIJ+3y/OoXGdVUvht0DxYtOhI69dNqe0KqyWFmIleIjMqoAoGCCqGSM49\n"
    "AwEHoUQDQgAEKGzvYBs1yaZO5t0unKAtXSl/theSgmdGpkFKc5BAzXp+AeNgmuu1\n"
    "wpkzNe7Pl4hneV/W4ddBvJMI5ux2ftaCBQ==\n"
    "-----END EC PRIVATE KEY-----\n";

const char *pub_rsa_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwBgOktII9d+oYJQLUhQY\n"
    "Pk8Ad6dW54ak8XWLdMtNx7161kgQsohndq3WUZ10mR/lf/GVPYNHj5+vR28BQ3In\n"
    "0GZgYGNSiE+6drSq6h+VyaYzDRQGb2CUKqNSMhl5FAqhCs6kM8GeXI6FZhnur3gN\n"
    "v4S+hcra9is9mwzucLnt1Maqu5/D7HgXJrWmn5JTg8OlZMiYnqD91LD+nx9ZYWxC\n"
    "QzwUBDVaEXQtndvF5neTALOXro1BawMMqjlMug0IFA46MOo2mvOWaRWm4JgVS50l\n"
    "j+cye7nobQbw6gkF/kb1VbiEvi/L/vbnQCtDlvjx9a97QKuphp2sGtOM/K8c9yuX\n"
    "MwIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

const char *pub_ecc_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKGzvYBs1yaZO5t0unKAtXSl/theS\n"
    "gmdGpkFKc5BAzXp+AeNgmuu1wpkzNe7Pl4hneV/W4ddBvJMI5ux2ftaCBQ==\n"
    "-----END PUBLIC KEY-----\n";

int
test_fapi_import_ossl(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    const char *priv_pem;
    char *json_string_pubkey = NULL;
    json_object *jso = NULL;
    json_object *jso_public = NULL;
    char *pubkey_pem = NULL;
    const char *pubkey_test = NULL;


    if (strncmp(FAPI_PROFILE, "P_RSA", 5) == 0) {
        priv_pem = priv_rsa_pem;
        pubkey_test = pub_rsa_pem;
    } else {
        priv_pem = priv_ecc_pem;
        pubkey_test =pub_ecc_pem;
    }

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_Import(context, "/SRK/my_osslkey", priv_pem);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_ExportKey(context, "/SRK/my_osslkey", NULL, &json_string_pubkey);
    goto_if_error(r, "Error Fapi_CreateKey", error);
    ASSERT(json_string_pubkey != NULL);
    ASSERT(strlen(json_string_pubkey) > ASSERT_SIZE);

    jso = json_tokener_parse(json_string_pubkey);
    LOG_INFO("\nExported: %s\n", json_string_pubkey);

    if (!jso || !json_object_object_get_ex(jso, "pem_ext_public",  &jso_public)) {
        LOG_ERROR("No public key eyported.");
        goto error;
    }
    pubkey_pem = strdup(json_object_get_string(jso_public));
    if (!pubkey_pem) {
        LOG_ERROR("Out of memory.");
        goto error;
    }

    if (strcmp(pubkey_pem, pubkey_test) != 0) {
        LOG_ERROR("Pub keys not equal.");
        LOG_ERROR("%s", pubkey_test);
        LOG_ERROR("%s", pubkey_pem);
        goto error;
    }

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error2);

    SAFE_FREE(json_string_pubkey);
    json_object_put(jso);
    SAFE_FREE(pubkey_pem);
      return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
 error2:
    if (jso)
        json_object_put(jso);
    SAFE_FREE(pubkey_pem);
    SAFE_FREE(json_string_pubkey);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_import_ossl(fapi_context);
}
