/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2024, Infineon Technologies AG
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"                       // for TCTI_LIBTPMS, TCTI_MSSIM
#endif

#include <inttypes.h>                     // for PRIx64
#ifdef TCTI_LIBTPMS
#include <libtpms/tpm_library.h>          // for TPMLIB_STATE_PERMANENT, TPM...
#endif /* TCTI_LIBTPMS */
#include <stdbool.h>                      // for true, false, bool
#include <stdlib.h>                       // for free, EXIT_SUCCESS
#include <string.h>                       // for memset, memcpy

#include "test-common-tcti.h"
#include "test/fuzz/tcti/tcti-fuzzing.h"  // for TCTI_FUZZING_MAGIC
#include "tss2-tcti/tcti-cmd.h"           // for TCTI_CMD_MAGIC
#include "tss2-tcti/tcti-device.h"        // for TCTI_DEVICE_MAGIC
#include "tss2-tcti/tcti-i2c-helper.h"    // for TCTI_I2C_HELPER_MAGIC
#ifdef TCTI_LIBTPMS
#include "tss2-tcti/tcti-libtpms.h"       // for TSS2_TCTI_LIBTPMS_CONTEXT
#endif /* TCTI_LIBTPMS */
#include "tss2-tcti/tcti-mssim.h"         // for TCTI_MSSIM_MAGIC
#include "tss2-tcti/tcti-pcap.h"          // for TCTI_PCAP_MAGIC, TSS2_TCTI_...
#include "tss2-tcti/tcti-spi-helper.h"    // for TCTI_SPI_HELPER_MAGIC
#include "tss2-tcti/tcti-start-sim.h"     // for TCTI_START_SIM_MAGIC, TSS2_...
#include "tss2-tcti/tcti-swtpm.h"         // for TCTI_SWTPM_MAGIC
#include "tss2-tcti/tcti-tbs.h"           // for TCTI_TBS_MAGIC
#include "tss2-tcti/tctildr.h"            // for TCTILDR_MAGIC, TSS2_TCTILDR...
#include "tss2_common.h"                  // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_tcti_libtpms.h"            // for Tss2_Tcti_Libtpms_Reset
#include "tss2_tcti_mssim.h"              // for tcti_platform_command, MS_S...
#include "tss2_tcti_swtpm.h"              // for Tss2_Tcti_Swtpm_Reset
#include "util/aux_util.h"                // for ARRAY_LEN

#define LOGMODULE test
#include "util/log.h"                     // for LOG_ERROR, LOG_DEBUG, LOG_T...

/* Also defined in test-common.h, but we cannot have cyclic dependencies */
#define EXIT_SKIP 77
#define EXIT_ERROR 99


/** Define a proxy tcti that returns yielded on every second invocation
 * thus the corresponding handling code in ESYS can be tested.
 * The first invocation will be Tss2_Sys_StartUp.
 */
#ifdef TEST_ESYS

TSS2_RC
(*transmit_hook) (const uint8_t *command_buffer, size_t command_size) = NULL;

#define TCTI_PROXY_MAGIC 0x5250584f0a000000ULL /* 'PROXY\0\0\0' */
#define TCTI_PROXY_VERSION 0x1


TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx)
{
    TSS2_TCTI_CONTEXT_PROXY *ctxi = (TSS2_TCTI_CONTEXT_PROXY*)ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_PROXY_MAGIC) {
        LOG_ERROR("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}

TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        return TSS2_RC_SUCCESS;
    }

    if (transmit_hook != NULL) {
        rval = transmit_hook(command_buffer, command_size);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_ERROR("transmit hook requested error");
            return rval;
        }
    }

    rval = Tss2_Tcti_Transmit(tcti_proxy->tctiInner, command_size,
        command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

uint8_t yielded_response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08  /* TPM_RC_YIELDED */
};

TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        *response_size = sizeof(yielded_response);

        if (response_buffer != NULL) {
            memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));
            tcti_proxy->state = forwarding;
        }
        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Receive(tcti_proxy->tctiInner, response_size,
                             response_buffer, timeout);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    /* First read with response buffer == NULL is to get the size of the
     * response. The subsequent read needs to be forwarded also */
    if (response_buffer != NULL)
        tcti_proxy->state = intercepting;

    return rval;
}

void
tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
}

TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    TSS2_TCTI_CONTEXT *tctiInner)
{
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy =
        (TSS2_TCTI_CONTEXT_PROXY*) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_proxy);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_proxy, 0, sizeof(*tcti_proxy));
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_PROXY_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_PROXY_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_proxy_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_proxy_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_proxy_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = NULL;
    tcti_proxy->tctiInner = tctiInner;
    tcti_proxy->state = forwarding;

    return TSS2_RC_SUCCESS;
}
#endif /* TEST_ESYS */

static TSS2_TCTI_CONTEXT *tcti_unwrap_max_depth(TSS2_TCTI_CONTEXT *tcti, int max_depth) {
    uint64_t magic;

    for (int i = 0; max_depth < 0 || i < max_depth; i++) {
        magic = TSS2_TCTI_MAGIC(tcti);

        switch (magic) {
            case TCTILDR_MAGIC:
                LOG_TRACE("TCTI is tctildr (0x%" PRIx64 "). Unwrapping...", magic);
                tcti = ((TSS2_TCTILDR_CONTEXT *) tcti)->tcti;
                break;
            case TCTI_PCAP_MAGIC:
                LOG_TRACE("TCTI is tcti-pcap (0x%" PRIx64 "). Unwrapping...", magic);
                tcti = ((TSS2_TCTI_PCAP_CONTEXT *) tcti)->tcti_child;
                break;
            case TCTI_START_SIM_MAGIC:
                LOG_TRACE("TCTI is tcti-start-sim (0x%" PRIx64 "). Unwrapping...", magic);
                tcti = ((TSS2_TCTI_START_SIM_CONTEXT *) tcti)->tcti_child;
                break;
            case TCTI_PROXY_MAGIC:
                LOG_TRACE("TCTI is tcti-proxy (0x%" PRIx64 "). Unwrapping...", magic);
                tcti = ((TSS2_TCTI_CONTEXT_PROXY *) tcti)->tctiInner;
                break;
            default:
                return tcti;
        }
    }

    return tcti;
}

TSS2_TCTI_CONTEXT *tcti_unwrap(TSS2_TCTI_CONTEXT *tcti) {
    return tcti_unwrap_max_depth(tcti, -1);
}

typedef struct {
    const char *name;
    uint64_t magic;
} tcti_type;

/* grep -rhPo '(?<=#define) TCTI_.*_MAGIC.*' | sort | uniq */
tcti_type tcti_types[] = {
   {.name = "ldr", .magic = TCTILDR_MAGIC },
   {.name = "cmd", .magic = TCTI_CMD_MAGIC },
   {.name = "device", .magic = TCTI_DEVICE_MAGIC },
   {.name = "fuzzing", .magic = TCTI_FUZZING_MAGIC },
   {.name = "libtpms", .magic = TCTI_LIBTPMS_MAGIC },
   {.name = "mssim", .magic = TCTI_MSSIM_MAGIC },
   {.name = "pcap", .magic = TCTI_PCAP_MAGIC },
   {.name = "proxy", .magic = TCTI_PROXY_MAGIC },
   {.name = "spi-helper", .magic = TCTI_SPI_HELPER_MAGIC },
   {.name = "i2c-helper", .magic = TCTI_I2C_HELPER_MAGIC },
   {.name = "start-sim", .magic = TCTI_START_SIM_MAGIC },
   {.name = "swtpm", .magic = TCTI_SWTPM_MAGIC },
   {.name = "tbs", .magic = TCTI_TBS_MAGIC },
   {.name = "fake", .magic = 0x46414b4500000000ULL },
   {.name = "tpmerror", .magic = 0x5441455252000000ULL },
   {.name = "tryagainerror", .magic = 0x5441455252000000ULL },
   {.name = "yielder", .magic = 0x5949454c44455200ULL },

   /* from https://github.com/tpm2-software/tpm2-abrmd */
   {.name = "tabrmd", .magic = 0x1c8e03ff00db0f92 },
};

void tcti_print(TSS2_TCTI_CONTEXT *tcti) {
    uint64_t magic = TSS2_TCTI_MAGIC(tcti);
    bool found = false;

    for (size_t i = 0; i < ARRAY_LEN(tcti_types); i++) {
        if (magic == tcti_types[i].magic) {
            LOG_DEBUG("TCTI dump: %s", tcti_types[i].name);
            found = true;
        }
    }

    if (!found) {
        LOG_DEBUG("TCTI dump: UNKNOWN (0x%" PRIx64 ")", magic);
    }
}

void tcti_dump(TSS2_TCTI_CONTEXT *tcti) {
    TSS2_TCTI_CONTEXT *tcti_next;

    while (true) {
        tcti_print(tcti);

        tcti_next = tcti_unwrap_max_depth(tcti, 1);
        if (tcti_next == tcti) {
            /* tcti unwrap could not get a child tcti */
            return;
        }
        tcti = tcti_next;
    }
}

/* Return true if the TCTI (considering its children) loses its state after finalize */
int
tcti_is_volatile (TSS2_TCTI_CONTEXT *tcti) {
    uint64_t magic;
    TSS2_TCTI_CONTEXT *tcti_next;

    while (true) {
        magic = TSS2_TCTI_MAGIC(tcti);
        if (magic == TCTI_START_SIM_MAGIC || magic == TCTI_LIBTPMS_MAGIC) {
            return true;
        }

        tcti_next = tcti_unwrap_max_depth(tcti, 1);
        if (tcti_next == tcti) {
            /* tcti unwrap could not get a child tcti */
            break;
        }
        tcti = tcti_next;
    }

    return false;
}

/* Return true if the TCTI state can be backed up */
int
tcti_state_backup_supported (TSS2_TCTI_CONTEXT *tcti) {
    uint64_t magic;

    tcti = tcti_unwrap(tcti);
    magic = TSS2_TCTI_MAGIC(tcti);

    if (!tcti_is_volatile(tcti)) {
        return false;
    }

    return magic == TCTI_LIBTPMS_MAGIC;
}

/* Backup TCTI state and return alloced buffer. */
int
tcti_state_backup(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state) {
#ifdef TCTI_LIBTPMS
    TSS2_RC rc;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms;

    LOG_DEBUG("TCTI state backup called.");

    tcti = tcti_unwrap(tcti);

    if (! tcti_state_backup_supported(tcti)) {
        LOG_ERROR("TCTI state backup: state not supported");
        return EXIT_ERROR;
    }

    if (TSS2_TCTI_MAGIC(tcti) != TCTI_LIBTPMS_MAGIC) {
        LOG_ERROR("TCTI state backup: only implemented for tcti-libtpms so far");
        return EXIT_ERROR;
    }

    tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT*) tcti;

    /* get states */
    rc = tcti_libtpms->TPMLIB_GetState(TPMLIB_STATE_PERMANENT, &state->permanent_buf, &state->permanent_buf_len);
    if (rc != 0) {
        LOG_ERROR("TCTI state backup: TPMLIB_GetState(TPMLIB_STATE_PERMANENT) failed");
        return EXIT_ERROR;
    }
    tcti_libtpms->TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &state->volatile_buf, &state->volatile_buf_len);
    if (rc != 0) {
        LOG_ERROR("TCTI state backup: TPMLIB_GetState(TPMLIB_STATE_VOLATILE) failed");
        free(state->permanent_buf);
        return EXIT_ERROR;
    }

    return EXIT_SUCCESS;
#else
    UNUSED(tcti);
    UNUSED(state);
    return EXIT_ERROR;
#endif /* TCTI_LIBTPMS */
}

/* Restore TCTI state and free the buffer. */
int tcti_state_restore(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state) {
#ifdef TCTI_LIBTPMS
    TSS2_RC rc;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms;

    LOG_DEBUG("TCTI state restore called.");

    tcti = tcti_unwrap(tcti);

    if (! tcti_state_backup_supported(tcti)) {
        LOG_ERROR("TCTI state restore: not supported");
        return EXIT_SKIP;
    }

    if (TSS2_TCTI_MAGIC(tcti) != TCTI_LIBTPMS_MAGIC) {
        LOG_ERROR("TCTI state restore: only implemented for tcti-libtpms so far");
        return EXIT_ERROR;
    }

    tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT*) tcti;

    tcti_libtpms->TPMLIB_Terminate();

    /* set states */
    rc = tcti_libtpms->TPMLIB_SetState(TPMLIB_STATE_PERMANENT, state->permanent_buf, state->permanent_buf_len);
    if (rc != 0) {
        LOG_ERROR("TCTI state restore: TPMLIB_SetState(TPMLIB_STATE_PERMANENT) failed");
        return EXIT_ERROR;
    }
    rc = tcti_libtpms->TPMLIB_SetState(TPMLIB_STATE_VOLATILE, state->volatile_buf, state->volatile_buf_len);
    if (rc != 0) {
        LOG_ERROR("TCTI state restore: TPMLIB_SetState(TPMLIB_STATE_VOLATILE) failed");
        return EXIT_ERROR;
    }

    rc = tcti_libtpms->TPMLIB_MainInit();
    if (rc != 0) {
        LOG_ERROR("TCTI state restore: TPMLIB_MainInit() failed");
        return EXIT_ERROR;
    }

    free(state->permanent_buf);
    free(state->volatile_buf);

    return EXIT_SUCCESS;
#else
    UNUSED(tcti);
    UNUSED(state);
    return EXIT_ERROR;
#endif /* TCTI_LIBTPMS */
}

/* Backup TCTI state and return alloced buffer. Does nothing if tcti is not volatile and returns skip if backup is necessary but not supported */
int tcti_state_backup_if_necessary(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state) {
    tcti = tcti_unwrap(tcti);

    if (!tcti_is_volatile(tcti)) {
        LOG_TRACE("TCTI state backup: is not necessary, TCTI is not volatile");
        return EXIT_SUCCESS;
    }

    if (!tcti_state_backup_supported(tcti)) {
        LOG_WARNING("TCTI state backup: is necessary but not supported");
        return EXIT_SKIP;
    }

    return tcti_state_backup(tcti, state);
}

/* Restore TCTI state and free the buffer. Does nothing if tcti is not volatile and returns skip if backup is necessary but not supported */
int tcti_state_restore_if_necessary(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state) {
    tcti = tcti_unwrap(tcti);

    if (!tcti_is_volatile(tcti)) {
        LOG_TRACE("TCTI state restore: is not necessary, TCTI is not volatile");
        return EXIT_SUCCESS;
    }

    if (!tcti_state_backup_supported(tcti)) {
        LOG_WARNING("TCTI state restore: is necessary but not supported");
        return EXIT_SKIP;
    }

    return tcti_state_restore(tcti, state);
}

TSS2_RC tcti_reset_tpm(TSS2_TCTI_CONTEXT *tcti) {
    TSS2_RC rval = TSS2_RC_SUCCESS;
    uint64_t magic;

    tcti = tcti_unwrap(tcti);
    magic = TSS2_TCTI_MAGIC(tcti);

    switch (magic) {
#ifdef TCTI_LIBTPMS
        case TCTI_LIBTPMS_MAGIC:
            LOG_DEBUG("Calling Tss2_Tcti_Libtpms_Reset()");
            rval = Tss2_Tcti_Libtpms_Reset(tcti);
            break;
#endif /* TCTI_LIBTPMS */

#ifdef TCTI_SWTPM
        case TCTI_SWTPM_MAGIC:
            LOG_DEBUG("Calling Tss2_Tcti_Swtpm_Reset()");
            rval = Tss2_Tcti_Swtpm_Reset(tcti);
            break;
#endif /* TCTI_SWTPM */

#ifdef TCTI_MSSIM
        case TCTI_MSSIM_MAGIC:
            LOG_DEBUG("Calling tcti_platform_command()");
            rval = (TSS2_RC)tcti_platform_command( tcti, MS_SIM_POWER_OFF );
            if (rval == TSS2_RC_SUCCESS) {
                rval = (TSS2_RC)tcti_platform_command( tcti, MS_SIM_POWER_ON );
            }
            break;
#endif /* TCTI_MSSIM */

        default:
            LOG_WARNING("TPM reset failed. TCTI unknown. Got TCTI magic: 0x%" PRIx64 ". Enabled TCTIs with reset support: "
#ifdef TCTI_LIBTPMS
                        "libtpms (" xstr(TCTI_LIBTPMS_MAGIC) "), "
#endif /* TCTI_LIBTPMS */
#ifdef TCTI_SWTPM
                        "swtpm (" xstr(TCTI_SWTPM_MAGIC) "), "
#endif /* TCTI_SWTPM */
#ifdef TCTI_MSSIM
                        "mssim (" xstr(TCTI_MSSIM_MAGIC) "), "
#endif /* TCTI_MSSIM */
                        "", magic);
            return EXIT_SKIP;
    }

    if (rval != TSS2_RC_SUCCESS) {
        LOG_WARNING("TPM reset failed: 0x%08x", rval);
    }

    return rval;
}
