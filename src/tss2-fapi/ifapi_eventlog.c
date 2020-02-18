/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "ifapi_helpers.h"
#include "ifapi_eventlog.h"
#include "ifapi_json_serialize.h"

#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"
#include "ifapi_macros.h"

/** Initialize the eventlog module of FAPI.
 *
 * @param[in,out] eventlog The context area for the eventlog.
 * @param[in] log_dir The directory where to put the eventlog data.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR if creation of log_dir failed or log_dir is not writable.
 * @retval TSS2_FAPI_RC_MEMORY if memory allocation failed.
 */
TSS2_RC
ifapi_eventlog_initialize(
    IFAPI_EVENTLOG *eventlog,
    const char *log_dir)
{
    check_not_null(eventlog);
    check_not_null(log_dir);

    TSS2_RC r;

    r = ifapi_io_check_create_dir(log_dir);
    return_if_error2(r, "Directory check/creation failed for %s", log_dir);

    eventlog->log_dir = strdup(log_dir);
    return_if_null(eventlog->log_dir, "Out of memory.", TSS2_FAPI_RC_MEMORY);

    return TSS2_RC_SUCCESS;
}

/** Retrieve the eventlog for a given list of pcrs using asynchronous io.
 *
 * Call ifapi_eventlog_get_finish to retrieve the results.
 *
 * @param[in,out] eventlog The context area for the eventlog.
 * @param[in,out] io The context area for the asynchronous io module.
 * @param[in] pcrList The list of PCR indices to retrieve the log for.
 * @param[in] pcrListSize The size of pcrList.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR if creation of log_dir failed or log_dir is not writable.
 * @retval TSS2_FAPI_RC_MEMORY if memory allocation failed.
 */
TSS2_RC
ifapi_eventlog_get_async(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io,
    const TPM2_HANDLE *pcrList,
    size_t pcrListSize)
{
    check_not_null(eventlog);
    check_not_null(io);
    check_not_null(pcrList);

    if (pcrListSize > TPM2_MAX_PCRS) {
        LOG_ERROR("pcrList too long %zi > %i", pcrListSize, TPM2_MAX_PCRS);
        return TSS2_FAPI_RC_BAD_VALUE;
    }

    LOG_TRACE("called for pcrListSize=%zi", pcrListSize);

    memcpy(&eventlog->pcrList, pcrList, pcrListSize * sizeof(TPM2_HANDLE));
    eventlog->pcrListSize = pcrListSize;
    eventlog->pcrListIdx = 0;

    eventlog->log = json_object_new_array();
    return_if_null(eventlog->log, "Out of memory", TSS2_FAPI_RC_MEMORY);

    return TSS2_RC_SUCCESS;
}

/** Retrieve the eventlog for a given list of pcrs using asynchronous io.
 *
 * Call after ifapi_eventlog_get_async.
 *
 * @param[in,out] eventlog The context area for the eventlog.
 * @param[in,out] io The context area for the asynchronous io module.
 * @param[out] log The event log for the requested PCRs in JSON format
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR if creation of log_dir failed or log_dir is not writable.
 * @retval TSS2_FAPI_RC_MEMORY if memory allocation failed.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if the I/O operation is not finished yet and this function needs
 *         to be called again.
 */
TSS2_RC
ifapi_eventlog_get_finish(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io,
    char **log)
{
    /* eventlog parameter currently not used */
    check_not_null(eventlog);
    check_not_null(io);
    check_not_null(log);

    TSS2_RC r;
    char *event_log_file, *logstr;
    json_object *logpart, *event;

    LOG_TRACE("called");

loop:
    /* If we're dune with adding all eventlogs to the json array, we can serialize it and return
       it to the caller. */
    if (eventlog->pcrListIdx >= eventlog->pcrListSize) {
        LOG_TRACE("Done reading pcrLog");
        *log = strdup(json_object_to_json_string_ext(eventlog->log, JSON_C_TO_STRING_PRETTY));
        check_oom(*log);
        json_object_put(eventlog->log);
        eventlog->log = NULL;
        eventlog->state = IFAPI_EVENTLOG_STATE_INIT;
        return TSS2_RC_SUCCESS;
    }

    switch (eventlog->state) {
    statecase(eventlog->state, IFAPI_EVENTLOG_STATE_INIT)
        /* Construct the filename for the eventlog file */
        r = ifapi_asprintf(&event_log_file, "%s/%s%i",
                           eventlog->log_dir, IFAPI_PCR_LOG_FILE,
                           eventlog->pcrList[eventlog->pcrListIdx]);
        return_if_error(r, "Out of memory.");

        if (!ifapi_io_path_exists(event_log_file)) {
            LOG_DEBUG("No event log for pcr %i", eventlog->pcrList[eventlog->pcrListIdx]);
            SAFE_FREE(event_log_file);
            eventlog->pcrListIdx += 1;
            goto loop;
        }

        /* Initiate the reading of the eventlog file */
        r = ifapi_io_read_async(io, event_log_file);
        free(event_log_file);
        if (r) {
            LOG_DEBUG("No event log for pcr %i", eventlog->pcrList[eventlog->pcrListIdx]);
            eventlog->pcrListIdx += 1;
            goto loop;
        }
        fallthrough;

    statecase(eventlog->state, IFAPI_EVENTLOG_STATE_READING)
        /* Finish the reading of the eventlog file and return it directly to the output parameter */
        r = ifapi_io_read_finish(io, (uint8_t **)&logstr, NULL);
        return_try_again(r);
        return_if_error(r, "read_finish failed");

        logpart = json_tokener_parse(logstr);
        SAFE_FREE(logstr);
        return_if_null(log, "JSON parsing error", TSS2_FAPI_RC_BAD_VALUE);

        /* Append the log-entry from logpart to the eventlog */
        json_type jso_type = json_object_get_type(logpart);
        if (jso_type != json_type_array) {
            /* libjson-c does not deliver an array if array has only one element */
            json_object_array_add(eventlog->log, logpart);
        } else {
            /* Iterate through the array of logpart and add each item to the eventlog */
            /* The return type of json_object_array_length() was changed, thus the case */
            for (int i = 0; i < (int)json_object_array_length(logpart); i++) {
                event = json_object_array_get_idx(logpart, i);
                /* Increment the refcount of event so it does not get freed on put(logpart) below */
                json_object_get(event);
                json_object_array_add(eventlog->log, event);
            }
            json_object_put(logpart);
        }

        eventlog->pcrListIdx += 1;
        eventlog->state = IFAPI_EVENTLOG_STATE_INIT;
        goto loop;

    statecasedefault(eventlog->state);
    }
    return TSS2_RC_SUCCESS;
}

/** Append an event to the existing event log.
 *
 * Call ifapi_eventlog_append_finish to finalize this operation.
 *
 * @param[in,out] eventlog The context area for the eventlog.
 * @param[in,out] io The context area for the asynchronous io module.
 * @param[in] event The event to be appended to the eventlog.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR if creation of log_dir failed or log_dir is not writable.
 * @retval TSS2_FAPI_RC_MEMORY if memory allocation failed.
 */
TSS2_RC
ifapi_eventlog_append_async(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io,
    const IFAPI_EVENT *event)
{
    check_not_null(eventlog);
    check_not_null(io);
    check_not_null(event);

    TSS2_RC r;
    char *event_log_file;

    if (eventlog->state != IFAPI_EVENTLOG_STATE_INIT) {
        LOG_ERROR("Wrong state: %i", eventlog->state);
        return TSS2_FAPI_RC_BAD_SEQUENCE;
    }

    eventlog->event = *event;

    /* Construct the filename for the eventlog file */
    r = ifapi_asprintf(&event_log_file, "%s/%s%i",
                       eventlog->log_dir, IFAPI_PCR_LOG_FILE, event->pcr);
    return_if_error(r, "Out of memory.");

    /* Initiate the reading of the eventlog file */
    r = ifapi_io_read_async(io, event_log_file);
    if (r) {
        LOG_DEBUG("Eventlog file %s could not be opened, creating...", event_log_file);
        free(event_log_file);
        eventlog->state = IFAPI_EVENTLOG_STATE_APPENDING;
        return TSS2_RC_SUCCESS;
    }
    free(event_log_file);

    eventlog->state = IFAPI_EVENTLOG_STATE_READING;
    return TSS2_RC_SUCCESS;
}

/** Append an event to the existing event log.
 *
 * Call after ifapi_eventlog_get_async.
 *
 * @param[in,out] eventlog The context area for the eventlog.
 * @param[in,out] io The context area for the asynchronous io module.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR if creation of log_dir failed or log_dir is not writable.
 * @retval TSS2_FAPI_RC_MEMORY if memory allocation failed.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if the I/O operation is not finished yet and this function needs
 *         to be called again.
 */
TSS2_RC
ifapi_eventlog_append_finish(
    IFAPI_EVENTLOG *eventlog,
    IFAPI_IO *io)
{
    check_not_null(eventlog);
    check_not_null(io);

    TSS2_RC r;
    char *logstr = NULL, *event_log_file;
    const char *logstr2 = NULL;
    json_object *log, *event = NULL;

    switch (eventlog->state) {
    statecase(eventlog->state, IFAPI_EVENTLOG_STATE_READING)
        /* Finish the reading of the eventlog file and return it directly to the output parameter */
        r = ifapi_io_read_finish(io, (uint8_t **)&logstr, NULL);
        return_try_again(r);
        return_if_error(r, "read_finish failed");
        fallthrough;

    statecase(eventlog->state, IFAPI_EVENTLOG_STATE_APPENDING)
        /* If a log was read, we deserialize it to JSON. Otherwise we start a new log. */
        if (logstr) {
            log = json_tokener_parse(logstr);
            SAFE_FREE(logstr);
            return_if_null(log, "JSON parsing error", TSS2_FAPI_RC_BAD_VALUE);

             /* libjson-c does not deliver an array if array has only one element */
            json_type jso_type = json_object_get_type(log);
            if (jso_type != json_type_array) {
                json_object *json_array = json_object_new_array();
                json_object_array_add(json_array, log);
                log = json_array;
            }
        } else {
            log = json_object_new_array();
            return_if_null(log, "Out of memory", TSS2_FAPI_RC_MEMORY);
        }

        /* Extend the eventlog with the data */
        eventlog->event.recnum = json_object_array_length(log) + 1;

        r = ifapi_json_IFAPI_EVENT_serialize(&eventlog->event, &event);
        if (r) {
            json_object_put(log);
            LOG_ERROR("Error serializing event data");
            return TSS2_FAPI_RC_GENERAL_FAILURE;
        }

        json_object_array_add(log, event);
        logstr2 = json_object_to_json_string_ext(log, JSON_C_TO_STRING_PRETTY);

        /* Construct the filename for the eventlog file */
        r = ifapi_asprintf(&event_log_file, "%s/%s%i",
                           eventlog->log_dir, IFAPI_PCR_LOG_FILE, eventlog->event.pcr);
        return_if_error(r, "Out of memory.");

        /* Start writing the eventlog back to disk */
        r = ifapi_io_write_async(io, event_log_file, (uint8_t *) logstr2, strlen(logstr2));
        free(event_log_file);
        json_object_put(log); /* this also frees logstr2 */
        return_if_error(r, "write_async failed");
        fallthrough;

    statecase(eventlog->state, IFAPI_EVENTLOG_STATE_WRITING)
        /* Finish writing the eventlog */
        r = ifapi_io_write_finish(io);
        return_try_again(r);
        return_if_error(r, "read_finish failed");

        eventlog->state = IFAPI_EVENTLOG_STATE_INIT;
        break;

    statecasedefault(eventlog->state);
    }

    return TSS2_RC_SUCCESS;
}


/** Free allocated memory for an ifapi event.
 *
 * @param[in,out] event The structure to be cleaned up.
 */
void
ifapi_cleanup_event(IFAPI_EVENT * event) {
    if (event != NULL) {
        if (event->type == IFAPI_IMA_EVENT_TAG) {
            SAFE_FREE(event->sub_event.ima_event.eventName);
        } else if (event->type == IFAPI_TSS_EVENT_TAG) {
            SAFE_FREE(event->sub_event.tss_event.event);
        }
    }
}
