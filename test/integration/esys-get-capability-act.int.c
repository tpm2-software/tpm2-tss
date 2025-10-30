/* SPDX-FileCopyrightText: 2021, Jesper Brynolf */
/* SPDX-FileCopyrightText: 2021, Fraunhofer SIT sponsored by Infineon */
/* SPDX-FileCopyrightText: 2022, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for EXIT_FAILURE, EXIT_SUCCESS

#include "test-esys.h"        // for EXIT_SKIP, test_invoke_esys
#include "tss2_common.h"      // for UINT32, TSS2_RC
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_GetCapability, ESYS_...
#include "tss2_tpm2_types.h"  // for TPM2_CAP, TPM2_CAP_ACT, TPM2_RC_N_MASK

#define LOGMODULE test
#include "util/log.h"         // for SAFE_FREE, goto_if_error

/** This test is intended to test to get ACT
 *  capabilities using the get capability command.
 *
 *
 * Tested ESYS commands:
 *  - Esys_GetCapability() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_get_capability_act(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    TPM2_CAP                       capability = TPM2_CAP_ACT;
    UINT32                         property = TPM2_RH_ACT_0;
    UINT32                         propertyCount = 1;
    TPMS_CAPABILITY_DATA           *capabilityData;
    TPMI_YES_NO                    moreData;

    r = Esys_GetCapability(esys_context,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           capability, property, propertyCount,
                           &moreData, &capabilityData);

    /* Check whether capability is available. */
    if ((r & ~TPM2_RC_N_MASK) == (TPM2_RC_P | TPM2_RC_VALUE)) {
        SAFE_FREE(capabilityData);
        return EXIT_SKIP;
    }

    goto_if_error(r, "Error esys get capability", error);

    SAFE_FREE(capabilityData);

    return EXIT_SUCCESS;

 error:
    SAFE_FREE(capabilityData);

    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_get_capability_act(esys_context);
}
