/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_EVENTLOG_H
#define IFAPI_EVENTLOG_H

#include <json-c/json.h>

#include "tss2_tpm2_types.h"
#include "ifapi_io.h"

/** Type of event
 */
typedef UINT32 IFAPI_EVENT_TYPE;
#define IFAPI_IMA_EVENT_TAG            1    /**< Tag for key resource */
#define IFAPI_TSS_EVENT_TAG            2    /**< Tag for key resource */

/** TSS event information
 */
typedef struct {
    TPM2B_EVENT                                    data;    /**< The event data */
    char                                         *event;    /**< TSS event information */
} IFAPI_TSS_EVENT;

/** IMA event information
 */
typedef struct {
    TPM2B_DIGEST                              eventData;    /**< The ima event digest */
    char                                     *eventName;    /**< IMA event information */
} IFAPI_IMA_EVENT;

/** Type for representing sub types of FAPI events
 */
typedef union {
    IFAPI_TSS_EVENT                           tss_event;    /**< TSS event information */
    IFAPI_IMA_EVENT                           ima_event;    /**< IMA event information */
} IFAPI_EVENT_UNION;

/** Type for representing a FAPI event
 */
typedef struct IFAPI_EVENT {
    UINT32                                       recnum;    /**< Number of event */
    TPM2_HANDLE                                     pcr;    /**< PCR register */
    TPML_DIGEST_VALUES                          digests;    /**< The digest list of the event */
    IFAPI_EVENT_TYPE                               type;    /**< Selector for object type */
    IFAPI_EVENT_UNION                         sub_event;    /**< Additional event information */
} IFAPI_EVENT;

enum IFAPI_EVENTLOG_STATE {
    IFAPI_EVENTLOG_STATE_INIT = 0,
    IFAPI_EVENTLOG_STATE_READING,
    IFAPI_EVENTLOG_STATE_APPENDING,
    IFAPI_EVENTLOG_STATE_WRITING
};

typedef struct IFAPI_EVENTLOG {
    enum IFAPI_EVENTLOG_STATE state;
    char *log_dir;
    struct IFAPI_EVENT event;
    TPM2_HANDLE pcrList[TPM2_MAX_PCRS];
    size_t pcrListSize;
    size_t pcrListIdx;
    json_object *log;
} IFAPI_EVENTLOG;

TSS2_RC
ifapi_eventlog_initialize(
    IFAPI_EVENTLOG *eventlog,
    const char *log_dir);

TSS2_RC
ifapi_eventlog_get_async(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io,
    const TPM2_HANDLE *pcrList,
    size_t pcrListSize);

TSS2_RC
ifapi_eventlog_get_finish(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io,
    char **log);

TSS2_RC
ifapi_eventlog_append_check(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io);

TSS2_RC
ifapi_eventlog_append_finish(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io,
    const IFAPI_EVENT *event);

void
ifapi_cleanup_event(
    IFAPI_EVENT * event);

#endif /* IFAPI_EVENTLOG_H */
