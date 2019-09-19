/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "tss2_esys.h"
#include "util/tss2_endian.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

/** This test is intended to test the function Esys_LoadExternal
 *
 * Mainly, the padding of ECC parameters shall be tested. Those parameters
 * are the x and y coordinates of the public key as well as the scalar of the
 * private key.
 *
 * Tested ESAPI commands:
 *  - Esys_ActivateCredential() (M)
 *  - Esys_Create() (M)
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_Load() (M)
 *  - Esys_LoadExternal() (M)
 *  - Esys_MakeCredential() (M)
 *  - Esys_ReadPublic() (M)
 *  - Esys_StartAuthSession() (M)
 *
 * Used compiler defines: TEST_SESSION
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

/*
 * Load an unpadded private ECC key (prime256v1)
 */
int
test_esys_loadexternal_unpadded_private(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_NODA),
            .authPolicy = {
                .size = 0,
             },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {
                        .anySig.hashAlg = TPM2_ALG_NULL
                    }
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                }
             },
            .unique.ecc = {
                .x = {
                    .size = 32,
                    .buffer = {
                        0xc9, 0x24, 0x6f, 0xc9, 0x04, 0x74, 0x0e, 0xad,
                        0x60, 0x6b, 0x8d, 0x2b, 0xe7, 0xbf, 0xde, 0xde,
                        0xed, 0x5c, 0x9a, 0x83, 0xa8, 0x17, 0xac, 0x49,
                        0x9b, 0x39, 0x32, 0x29, 0x90, 0xc9, 0x57, 0x71
                    }
                },
                .y = {
                    .size = 32,
                    .buffer = {
                        0xc8, 0x56, 0x07, 0x68, 0x68, 0x08, 0xed, 0x90,
                        0x59, 0x15, 0xd0, 0xfd, 0x2c, 0x6a, 0x3e, 0x80,
                        0x83, 0xa3, 0x86, 0x18, 0xf3, 0x98, 0x93, 0xe9,
                        0x75, 0x9e, 0xdc, 0x8f, 0x33, 0xb0, 0x74, 0xf3
                    }
                }
            }
        }
    };

    TPM2B_AUTH authValue = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5},
    };

    TPM2B_SENSITIVE inSensitiveECC = {
        .size = 0,
        .sensitiveArea = {
            .sensitiveType = TPM2_ALG_ECC,
            .authValue = authValue,
            .seedValue = {
                .size = 0,
                .buffer = {}
            },
            .sensitive.ecc = {
                .size = 31,
                .buffer = {
                          0x61, 0xe9, 0x6d, 0x0c, 0xd4, 0x4b, 0xb9,
                    0xea, 0x47, 0xe3, 0x42, 0x30, 0x62, 0x9d, 0x41,
                    0x4d, 0xd6, 0x6b, 0xa2, 0x47, 0x4c, 0x5e, 0xdd,
                    0x6a, 0x9b, 0x8a, 0x82, 0x61, 0xd0, 0x99, 0x30
                }
            }
        }
    };

     r = Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          &inSensitiveECC,
                          &inPublicECC,
                          TPM2_RH_NULL,
                          &loadedKeyHandle);
    goto_if_error(r, "Error Esys_LoadExternal", error);

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_DIGEST digest = {
        .size = 32,
        .buffer = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        }
    };
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details = {
            .ecdsa = {
                .hashAlg = TPM2_ALG_SHA256,
            }
        }
    };
    TPMT_TK_HASHCHECK hashcheck = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {}
    };
    TPMT_SIGNATURE *signature;
    r = Esys_Sign(esys_context,
                  loadedKeyHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &digest,
                  &inScheme,
                  &hashcheck,
                  &signature);
    goto_if_error(r, "Error Esys_Sign", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    return EXIT_SUCCESS;

 error:
    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup loadedKeyHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

/*
 * Load an public key with unpadded x coordinate with private part (secp384r1),
 * Use the private portion to sign, flush the key, load the public part only
 * again and verify the signature
 */
int
test_esys_loadexternal_unpadded_x(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_NODA),
            .authPolicy = {
                .size = 0,
             },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {
                        .anySig.hashAlg = TPM2_ALG_NULL
                    }
                },
                .curveID = TPM2_ECC_NIST_P384,
                .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                }
             },
            .unique.ecc = {
                .x = {
                    .size = 47,
                    .buffer = {
                              0x02, 0xa5, 0x88, 0x19, 0xea, 0x72, 0x51,
                        0xa7, 0xcc, 0x6a, 0xae, 0x3e, 0x81, 0x68, 0xe8,
                        0x5e, 0x13, 0x36, 0xb5, 0x9b, 0x99, 0x9b, 0xd7,
                        0xdc, 0x1e, 0xfd, 0xbe, 0x25, 0xa5, 0xb2, 0xa1,
                        0x23, 0xcb, 0x2c, 0xbe, 0x72, 0x52, 0xf5, 0xda,
                        0xd4, 0xc5, 0x21, 0xdd, 0x39, 0x9e, 0x87, 0x4d,
                    }
                },
                .y = {
                    .size = 48,
                    .buffer = {
                        0xf5, 0x5e, 0xdf, 0xcb, 0x05, 0x54, 0xda, 0x17,
                        0x45, 0x07, 0x09, 0x44, 0x57, 0xd9, 0x52, 0x8f,
                        0xea, 0x2a, 0xe8, 0xcb, 0x17, 0xab, 0x04, 0x32,
                        0x9b, 0x42, 0xe3, 0x21, 0x23, 0x60, 0x49, 0xd3,
                        0xed, 0x49, 0xce, 0x06, 0x70, 0xe3, 0x5b, 0x98,
                        0x07, 0xb3, 0x75, 0x5a, 0xfb, 0x69, 0x24, 0x1a
                    }
                }
            }
        }
    };

    TPM2B_AUTH authValue = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5},
    };

    TPM2B_SENSITIVE inSensitiveECC = {
        .size = 0,
        .sensitiveArea = {
            .sensitiveType = TPM2_ALG_ECC,
            .authValue = authValue,
            .seedValue = {
                .size = 0,
                .buffer = {}
            },
            .sensitive.ecc = {
                .size = 48,
                .buffer = {
                    0xb7, 0xd0, 0xd4, 0x08, 0x1a, 0x53, 0x35, 0x4a,
                    0x4f, 0xa1, 0xbf, 0x04, 0x08, 0xde, 0x2d, 0xe9,
                    0x26, 0x0c, 0x71, 0x51, 0xc4, 0x94, 0x13, 0xba,
                    0x1f, 0xb0, 0x2f, 0x86, 0x8c, 0xac, 0x20, 0x4e,
                    0x12, 0x8d, 0x26, 0xdb, 0xae, 0x67, 0xfd, 0x0c,
                    0xf3, 0x32, 0x57, 0x02, 0xcd, 0x54, 0xac, 0x30
                }
            }
        }
     };

    r = Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          &inSensitiveECC,
                          &inPublicECC,
                          TPM2_RH_NULL,
                          &loadedKeyHandle);
    goto_if_error(r, "Error Esys_LoadExternal", error);

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_DIGEST digest = {
        .size = 32,
        .buffer = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        }
    };
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details = {
            .ecdsa = {
                .hashAlg = TPM2_ALG_SHA256,
            }
        }
    };
    TPMT_TK_HASHCHECK hashcheck = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {}
    };
    TPMT_SIGNATURE *signature;
    r = Esys_Sign(esys_context,
                  loadedKeyHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &digest,
                  &inScheme,
                  &hashcheck,
                  &signature);
    goto_if_error(r, "Error Esys_Sign", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    /* The key (public + private) is flushed, load the public key only and verify */
    r = Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          NULL,
                          &inPublicECC,
                          TPM2_RH_NULL,
                          &loadedKeyHandle);
    goto_if_error(r, "Error Esys_LoadExternal", error);

    TPMT_TK_VERIFIED *validation;
    r = Esys_VerifySignature(esys_context,
                             loadedKeyHandle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &digest,
                             signature,
                             &validation);
    goto_if_error(r, "Error Esys_VerifySignature", error);

    if (validation->tag != TPM2_ST_VERIFIED) {
        LOG_ERROR("Verification failed: %04x", validation->tag);
	    goto error;
    }

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    return EXIT_SUCCESS;

 error:
    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup loadedKeyHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

/*
 * Load an public key with unpadded y coordinate with private part (prime256v1),
 * Use the private portion to sign, flush the key, load the public part only
 * again and verify the signature
 */
int
test_esys_loadexternal_unpadded_y(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_NODA),
            .authPolicy = {
                .size = 0,
             },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {
                        .anySig.hashAlg = TPM2_ALG_NULL
                    }
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                }
             },
            .unique.ecc = {
                .x = {
                    .size = 32,
                    .buffer = {
                        0xf9, 0x01, 0x15, 0x32, 0x8c, 0x3c, 0x15, 0x97,
                        0x0e, 0x0a, 0x09, 0xf9, 0xb1, 0x74, 0x9c, 0x7d,
                        0x8f, 0x27, 0xfe, 0xa3, 0xed, 0x0c, 0xb7, 0xa9,
                        0xb4, 0xe0, 0x6f, 0x3b, 0xab, 0x9e, 0x99, 0xc7
                    }
                },
                .y = {
                    .size = 30,
                    .buffer = {
                                    0xcb, 0xf1, 0xd0, 0x59, 0x14, 0x8c,
                        0xcd, 0xf4, 0x54, 0xf1, 0xbd, 0x05, 0xb0, 0x0b,
                        0x43, 0x69, 0x03, 0xa1, 0x08, 0x0a, 0x75, 0x79,
                        0x64, 0x91, 0x81, 0x47, 0xdd, 0x80, 0x43, 0x36
                    }
                }
            }
        }
    };

    TPM2B_AUTH authValue = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5},
    };

    TPM2B_SENSITIVE inSensitiveECC = {
        .size = 0,
        .sensitiveArea = {
            .sensitiveType = TPM2_ALG_ECC,
            .authValue = authValue,
            .seedValue = {
                .size = 0,
                .buffer = {}
            },
            .sensitive.ecc = {
                .size = 32,
                .buffer = {
                    0xb1, 0x07, 0x87, 0x76, 0x1f, 0x42, 0xda, 0x24,
                    0xe7, 0xbb, 0x92, 0xb3, 0x7b, 0x1e, 0x59, 0x20,
                    0x19, 0x47, 0xc6, 0xfc, 0xcb, 0xf1, 0x94, 0x07,
                    0xb9, 0x78, 0xa1, 0x7d, 0x83, 0x30, 0xf2, 0x0c
                }
            }
        }
     };

    r = Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          &inSensitiveECC,
                          &inPublicECC,
                          TPM2_RH_NULL,
                          &loadedKeyHandle);
    goto_if_error(r, "Error Esys_LoadExternal", error);

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_DIGEST digest = {
        .size = 32,
        .buffer = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        }
    };
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details = {
            .ecdsa = {
                .hashAlg = TPM2_ALG_SHA256,
            }
        }
    };
    TPMT_TK_HASHCHECK hashcheck = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {}
    };
    TPMT_SIGNATURE *signature;
    r = Esys_Sign(esys_context,
                  loadedKeyHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &digest,
                  &inScheme,
                  &hashcheck,
                  &signature);
    goto_if_error(r, "Error Esys_Sign", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    /* The key (public + private) is flushed, load the public key only and verify */
    r = Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          NULL,
                          &inPublicECC,
                          TPM2_RH_NULL,
                          &loadedKeyHandle);
    goto_if_error(r, "Error Esys_LoadExternal", error);

    TPMT_TK_VERIFIED *validation;
    r = Esys_VerifySignature(esys_context,
                             loadedKeyHandle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &digest,
                             signature,
                             &validation);
    goto_if_error(r, "Error Esys_VerifySignature", error);

    if (validation->tag != TPM2_ST_VERIFIED) {
        LOG_ERROR("Verification failed: %04x", validation->tag);
	    goto error;
    }

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    return EXIT_SUCCESS;

 error:
    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup loadedKeyHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

int
test_ecc_get_keysize(void) {
    TPM2_RC rc;
    size_t keysize;

    rc = ecc_get_keysize(TPM2_ECC_NIST_P192, &keysize);
    if (rc != TPM2_RC_SUCCESS || keysize != 192 / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_NIST_P224, &keysize);
    if (rc != TPM2_RC_SUCCESS || keysize != 224 / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_NIST_P256, &keysize);
    if (rc != TPM2_RC_SUCCESS || keysize != 256 / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_NIST_P384, &keysize);
    if (rc != TPM2_RC_SUCCESS || keysize != 384 / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_NIST_P521, &keysize);
    /* here we have to round up */
    if (rc != TPM2_RC_SUCCESS || keysize != (521 + 7) / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_BN_P256, &keysize);
    if (rc != TPM2_RC_SUCCESS || keysize != 256 / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_BN_P638, &keysize);
    /* here we have to round up */
    if (rc != TPM2_RC_SUCCESS || keysize != (638 + 7) / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(TPM2_ECC_SM2_P256, &keysize);
    if (rc != TPM2_RC_SUCCESS || keysize != 256 / 8)
        return EXIT_FAILURE;

    rc = ecc_get_keysize(0, &keysize);
    if (rc != TSS2_ESYS_RC_BAD_VALUE || keysize != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int
test_esys_loadexternal(ESYS_CONTEXT * esys_context) {
    int r;
    TPM2_RC rc;

    r = test_esys_loadexternal_unpadded_private(esys_context);
    if (r != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    int p384_supported = 0;
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data = NULL;
    do {
        rc = Esys_GetCapability(esys_context,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                TPM2_CAP_ECC_CURVES,
                                TPM2_ECC_NIST_P192,
                                TPM2_MAX_ECC_CURVES,
                                &more_data,
                                &capability_data);
        if (rc != TPM2_RC_SUCCESS) {
            return EXIT_FAILURE;
        }
        for (uint32_t i = 0; i < capability_data->data.eccCurves.count; i++) {
            if (capability_data->data.eccCurves.eccCurves[i] == TPM2_ECC_NIST_P384) {
                p384_supported = 1;
            }
        }
    } while (more_data);

    if (p384_supported) {
        r = test_esys_loadexternal_unpadded_x(esys_context);
        if (r != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
    }

    r = test_esys_loadexternal_unpadded_y(esys_context);
    if (r != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    r = test_ecc_get_keysize();
    if (r != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    return test_esys_loadexternal(esys_context);
}
