/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2019, Fraunhofer SIT, Infineon Technologies AG, Intel Corporation
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <dlfcn.h>             // for dlerror, dlsym, dlclose, dlopen, RTLD...
#include <errno.h>             // for errno
#include <fcntl.h>             // for open, posix_fallocate, O_CREAT, O_RDWR
#include <inttypes.h>          // for uint32_t, PRIx32, PRIu32, PRIxPTR
#include <libtpms/tpm_error.h> // for TPM_SUCCESS, TPM_FAIL, TPM_RETRY
#include <libtpms/tpm_nvfilename.h> // for TPM_PERMANENT_ALL_NAME, TPM_SAVESTATE_NAME, TPM_VOLATILESTATE_NAME
#include <netinet/in.h>             // for htonl, ntohl
#include <stdio.h>                  // for NULL, ssize_t
#include <stdlib.h>                 // for free
#include <string.h>                 // for memcpy, strerror, memset, strdup, strlen
#include <unistd.h>                 // for close, lseek, truncate

#include "tcti-common.h" // for TSS2_TCTI_COMMON_CONTEXT, tpm_header_t
#include "tcti-libtpms.h"
#include "tss2_common.h"       // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_TCTI_R...
#include "tss2_tcti.h"         // for TSS2_TCTI_CONTEXT, TSS2_TCTI_INFO
#include "tss2_tcti_libtpms.h" // for Tss2_Tcti_Libtpms_Init, Tss2_Tcti_Lib...
#include "tss2_tpm2_types.h"   // for TPM2_RC_SUCCESS
#include "util/aux_util.h"     // for MAYBE_UNUSED, ARRAY_LEN

#define LOGMODULE tcti
#include "util/log.h" // for LOG_ERROR, LOG_TRACE, LOG_DEBUG, LOGB...

#if defined(__FreeBSD__)
#define mremap(a, b, c, d) ((void *)(-1))
#endif

/*
 * libtpms API calls need to be wrapped. We set the current active TCTI module
 * for this thread. This is needed because libtpms may call callbacks and these
 * need to know which TCTI context they have to operate on.
 *
 * This macro assumes that int ret is declared. Jumps to fail_label on error. In
 * this case, rc contains the respective error code.
 */
#define LIBTPMS_API_CALL(fail_label, tcti_libtpms, function, ...)                                  \
    current_tcti_libtpms = tcti_libtpms;                                                           \
    ret = tcti_libtpms->function(__VA_ARGS__);                                                     \
    if (ret != TPM_SUCCESS) {                                                                      \
        LOG_ERROR("libtpms function " #function "() failed with return code 0x%" PRIx32, ret);     \
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;                                                         \
        goto fail_label;                                                                           \
    }                                                                                              \
    current_tcti_libtpms = NULL;

static __thread TSS2_TCTI_LIBTPMS_CONTEXT *current_tcti_libtpms = NULL;

/*
 * If the mapped memory for the state file does not suffice, reallocate. This
 * may move tcti_libtpms->state_mmap to a new memory location.
 */
static TSS2_RC
tcti_libtpms_ensure_state_len(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms, size_t state_len) {
    int            ret;
    unsigned char *new_state_mmap;
    size_t         new_state_mmap_len;
    int            state_fd;

    if (state_len > tcti_libtpms->state_mmap_len) {
        new_state_mmap_len = (state_len / STATE_MMAP_CHUNK_LEN + 1) * STATE_MMAP_CHUNK_LEN;
        LOG_DEBUG("Mapped memory region is too small: %zu > %zu. Reallocating to %zu...", state_len,
                  tcti_libtpms->state_mmap_len, new_state_mmap_len);
        new_state_mmap = mremap(tcti_libtpms->state_mmap, tcti_libtpms->state_mmap_len,
                                new_state_mmap_len, MREMAP_MAYMOVE);
        if (new_state_mmap == MAP_FAILED) {
            LOG_ERROR("mremap failed on file %s: %s", tcti_libtpms->state_path, strerror(errno));
            return TSS2_TCTI_RC_IO_ERROR;
        }
        tcti_libtpms->state_mmap = new_state_mmap;
        tcti_libtpms->state_mmap_len = new_state_mmap_len;

        LOG_DEBUG("Successfully mapped state file to %zu bytes.", tcti_libtpms->state_mmap_len);

        /* allocate more disk space */
        if (tcti_libtpms->state_path) {
            state_fd = open(tcti_libtpms->state_path, O_RDWR | O_CREAT, 0644);
            if (state_fd == -1) {
                LOG_ERROR("open failed on file %s: %s", tcti_libtpms->state_path, strerror(errno));
                return TSS2_TCTI_RC_IO_ERROR;
            }

            ret = posix_fallocate(state_fd, 0, (off_t)tcti_libtpms->state_mmap_len);
            if (ret != 0) {
                LOG_ERROR("fallocate failed on file %s: %d", tcti_libtpms->state_path, ret);
                close(state_fd);
                return TSS2_TCTI_RC_IO_ERROR;
            }

            close(state_fd);
        }
    }

    return TSS2_RC_SUCCESS;
}

/*
 * Map the state file for this context into memory and allocate disk space. The
 * file descriptor is closed again. Once this context reaches the end of its
 * lifetime, the memory must be unmapped and the file must be truncated to its
 * real size (rather than the allocated size).
 */
static TSS2_RC
tcti_libtpms_map_state_file(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms) {
    TSS2_RC rc;
    int     ret;
    int     state_fd = -1;
    ssize_t file_len = 0;
    int     flags = MAP_PRIVATE | MAP_ANONYMOUS;

    LOG_DEBUG("Mapping state file: %s", tcti_libtpms->state_path);

    tcti_libtpms->state_mmap_len = STATE_MMAP_CHUNK_LEN;

    /* if state path was given, prepare file */
    if (tcti_libtpms->state_path != NULL) {
        /* open file */
        state_fd = open(tcti_libtpms->state_path, O_RDWR | O_CREAT, 0644);
        if (state_fd == -1) {
            LOG_ERROR("open failed on file %s: %s", tcti_libtpms->state_path, strerror(errno));
            return TSS2_TCTI_RC_IO_ERROR;
        }

        /* get file size (to detect if state does already exist). */
        file_len = lseek(state_fd, 0L, SEEK_END);
        if (file_len < 0) {
            LOG_ERROR("lseek failed on file %s: %s", tcti_libtpms->state_path, strerror(errno));
            rc = TSS2_TCTI_RC_IO_ERROR;
            goto cleanup_fd;
        }
        tcti_libtpms->state_mmap_len = (file_len / STATE_MMAP_CHUNK_LEN + 1) * STATE_MMAP_CHUNK_LEN;

        /* allocate disk space */
        ret = posix_fallocate(state_fd, 0, (off_t)tcti_libtpms->state_mmap_len);
        if (ret != 0) {
            LOG_ERROR("fallocate failed on file %s: %d", tcti_libtpms->state_path, ret);
            rc = TSS2_TCTI_RC_IO_ERROR;
            goto cleanup_fd;
        }

        flags = MAP_SHARED;
    }

    /* map memory (either backed by file or not) */
    tcti_libtpms->state_mmap
        = mmap(NULL, tcti_libtpms->state_mmap_len, PROT_READ | PROT_WRITE, flags, state_fd, 0);
    /* for non-file-backed memory, contents are zeroized by mmap */
    if (tcti_libtpms->state_mmap == MAP_FAILED) {
        tcti_libtpms->state_mmap_len = 0;
        LOG_ERROR("mmap failed on file %s: %s", tcti_libtpms->state_path, strerror(errno));
        rc = TSS2_TCTI_RC_IO_ERROR;
        goto cleanup_fd;
    }

    /* Current state length is file_len (which is 0 for non-file-backed memory).
     */
    tcti_libtpms->state_len = file_len;

    rc = TPM2_RC_SUCCESS;

cleanup_fd:
    if (state_fd != -1) {
        /* file can always be closed, this does not unmap the region */
        close(state_fd);
    }

    return rc;
}

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the mssim TCTI context. If passed a NULL context the function
 * returns a NULL ptr. The function doesn't check magic number anymore
 * It should checked by the appropriate tcti_common_checks.
 */
static TSS2_TCTI_LIBTPMS_CONTEXT *
tcti_libtpms_context_cast(TSS2_TCTI_CONTEXT *tcti_ctx) {
    if (tcti_ctx == NULL)
        return NULL;

    return (TSS2_TCTI_LIBTPMS_CONTEXT *)tcti_ctx;
}

/*
 * This function down-casts the libtpms TCTI context to the common context
 * defined in the tcti-common module.
 */
static TSS2_TCTI_COMMON_CONTEXT *
tcti_libtpms_down_cast(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms) {
    if (tcti_libtpms == NULL) {
        return NULL;
    }
    return &tcti_libtpms->common;
}

TSS2_RC
Tss2_Tcti_Libtpms_Reset(TSS2_TCTI_CONTEXT *tcti_ctx) {
    TSS2_RC                    rc;
    int                        ret;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast(tcti_ctx);

    if (TSS2_TCTI_MAGIC(tcti_libtpms) != TCTI_LIBTPMS_MAGIC) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    LOG_DEBUG("Resetting libtpms TPM...");

    /* TPM power off */
    tcti_libtpms->TPMLIB_Terminate();

    /* Power on (internally reloads state) */
    LIBTPMS_API_CALL(cleanup, tcti_libtpms, TPMLIB_MainInit);

    rc = TSS2_RC_SUCCESS;

cleanup:
    return rc;
}

/*
 * Transmits and gets the response. The response buffer was allocated by
 * libtpms, is referenced by the libtpms TCTI context and needs to be freed once
 * it is not needed anymore (i.e. at the end of tcti_libtpms_receive()).
 */
TSS2_RC
tcti_libtpms_transmit(TSS2_TCTI_CONTEXT *tcti_ctx, size_t size, const uint8_t *cmd_buf) {
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast(tcti_ctx);
    TSS2_TCTI_COMMON_CONTEXT  *tcti_common = tcti_libtpms_down_cast(tcti_libtpms);
    tpm_header_t               header;
    TSS2_RC                    rc;
    TPM_RESULT                 ret;
    uint32_t                   resp_size;
    uint32_t                   respbufsize;

    rc = tcti_common_transmit_checks(tcti_common, cmd_buf, TCTI_LIBTPMS_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    rc = header_unmarshal(cmd_buf, &header);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    if (header.size != size) {
        LOG_ERROR("Buffer size parameter: %zu, and TPM2 command header size "
                  "field: %" PRIu32 " disagree.",
                  size, header.size);
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    LOGBLOB_DEBUG(cmd_buf, size, "Sending command with TPM_CC 0x%" PRIx32, header.code);
    resp_size = (uint32_t)tcti_libtpms->response_len;
    respbufsize = (uint32_t)tcti_libtpms->response_buffer_len;
    LIBTPMS_API_CALL(fail, tcti_libtpms, TPMLIB_Process, &tcti_libtpms->response_buffer,
                     (uint32_t *)&resp_size, (uint32_t *)&respbufsize, (uint8_t *)cmd_buf, size);
    tcti_libtpms->response_len = resp_size;
    tcti_libtpms->response_buffer_len = respbufsize;

    tcti_common->state = TCTI_STATE_RECEIVE;

    return TSS2_RC_SUCCESS;

fail:
    return TSS2_TCTI_RC_IO_ERROR;
}

TSS2_RC
tcti_libtpms_cancel(TSS2_TCTI_CONTEXT *tctiContext) {
    (void)(tctiContext);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_libtpms_set_locality(TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality) {
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast(tctiContext);
    TSS2_TCTI_COMMON_CONTEXT  *tcti_common = tcti_libtpms_down_cast(tcti_libtpms);
    TSS2_RC                    rc;

    rc = tcti_common_set_locality_checks(tcti_common, TCTI_LIBTPMS_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->locality = locality;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_libtpms_get_poll_handles(TSS2_TCTI_CONTEXT     *tctiContext,
                              TSS2_TCTI_POLL_HANDLE *handles,
                              size_t                *num_handles) {
    (void)(tctiContext);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

void
tcti_libtpms_finalize(TSS2_TCTI_CONTEXT *tctiContext) {
    int                        ret;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast(tctiContext);

    if (tcti_libtpms == NULL) {
        return;
    }

    tcti_libtpms->TPMLIB_Terminate();

    /* close libtpms library handle */
    dlclose(tcti_libtpms->libtpms);

    if (tcti_libtpms->state_mmap != NULL) {
        /* unmap memory (may be backed by a state file) */
        munmap(tcti_libtpms->state_mmap, tcti_libtpms->state_mmap_len);
    }

    if (tcti_libtpms->state_path != NULL) {
        /* truncate state file to its real size */
        ret = truncate(tcti_libtpms->state_path, (off_t)tcti_libtpms->state_len);
        if (ret != 0) {
            LOG_WARNING("truncate failed on file %s: %s", tcti_libtpms->state_path,
                        strerror(errno));
        }
    }

    free(tcti_libtpms->state_path);
    free(tcti_libtpms->response_buffer);
}

TSS2_RC
tcti_libtpms_receive(TSS2_TCTI_CONTEXT *tctiContext,
                     size_t            *response_size,
                     unsigned char     *response_buffer,
                     int32_t            timeout) {
#ifdef TEST_FAPI_ASYNC
    /* Used for simulating a timeout. */
    static int wait = 0;
#endif

    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast(tctiContext);
    TSS2_TCTI_COMMON_CONTEXT  *tcti_common = tcti_libtpms_down_cast(tcti_libtpms);
    TSS2_RC                    rc;

    rc = tcti_common_receive_checks(tcti_common, response_size, TCTI_LIBTPMS_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    if (timeout != TSS2_TCTI_TIMEOUT_BLOCK) {
        LOG_TRACE("Asynchronous I/O not actually implemented.");
#ifdef TEST_FAPI_ASYNC
        if (wait < 1) {
            LOG_TRACE("Simulating Async by requesting another invocation.");
            wait += 1;
            return TSS2_TCTI_RC_TRY_AGAIN;
        } else {
            LOG_TRACE("Sending the actual result.");
            wait = 0;
        }
#endif /* TEST_FAPI_ASYNC */
    }

    if (response_buffer == NULL) {
        *response_size = tcti_libtpms->response_len;
        return TSS2_RC_SUCCESS;
    }

    if (*response_size < tcti_libtpms->response_len) {
        *response_size = tcti_libtpms->response_len;
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    *response_size = tcti_libtpms->response_len;

    memcpy(response_buffer, tcti_libtpms->response_buffer, tcti_libtpms->response_len);

    LOGBLOB_DEBUG(response_buffer, *response_size, "Response received:");

    free(tcti_libtpms->response_buffer);
    tcti_libtpms->response_buffer = NULL;
    tcti_libtpms->response_buffer_len = 0;
    tcti_libtpms->response_len = 0;

    tcti_common->state = TCTI_STATE_TRANSMIT;

    return TSS2_RC_SUCCESS;
}

static void
tcti_libtpms_init_context_data(TSS2_TCTI_COMMON_CONTEXT *tcti_common) {
    TSS2_TCTI_MAGIC(tcti_common) = TCTI_LIBTPMS_MAGIC;
    TSS2_TCTI_VERSION(tcti_common) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT(tcti_common) = tcti_libtpms_transmit;
    TSS2_TCTI_RECEIVE(tcti_common) = tcti_libtpms_receive;
    TSS2_TCTI_FINALIZE(tcti_common) = tcti_libtpms_finalize;
    TSS2_TCTI_CANCEL(tcti_common) = tcti_libtpms_cancel;
    TSS2_TCTI_GET_POLL_HANDLES(tcti_common) = tcti_libtpms_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY(tcti_common) = tcti_libtpms_set_locality;
    TSS2_TCTI_MAKE_STICKY(tcti_common) = tcti_make_sticky_not_implemented;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    memset(&tcti_common->header, 0, sizeof(tcti_common->header));
}

TSS2_RC
tcti_libtpms_dl(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms) {
    const char *names[] = { "libtpms.so", "libtpms.so.0" };

    for (size_t i = 0; i < ARRAY_LEN(names); i++) {
        tcti_libtpms->libtpms = dlopen(names[i], RTLD_LAZY | RTLD_LOCAL);
        if (tcti_libtpms->libtpms != NULL) {
            break;
        }
    }
    if (tcti_libtpms->libtpms == NULL) {
        LOG_ERROR("Could not load libtpms library: %s", dlerror());
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }

    tcti_libtpms->TPMLIB_ChooseTPMVersion = dlsym(tcti_libtpms->libtpms, "TPMLIB_ChooseTPMVersion");
    if (tcti_libtpms->TPMLIB_ChooseTPMVersion == NULL) {
        LOG_ERROR("Could not resolve libtpms symbol TPMLIB_ChooseTPMVersion(): %s", dlerror());
        goto cleanup_dl;
    }

    tcti_libtpms->TPMLIB_RegisterCallbacks
        = dlsym(tcti_libtpms->libtpms, "TPMLIB_RegisterCallbacks");
    if (tcti_libtpms->TPMLIB_RegisterCallbacks == NULL) {
        LOG_ERROR("Could not resolve libtpms symbol TPMLIB_RegisterCallbacks(): %s", dlerror());
        goto cleanup_dl;
    }

    tcti_libtpms->TPMLIB_MainInit = dlsym(tcti_libtpms->libtpms, "TPMLIB_MainInit");
    if (tcti_libtpms->TPMLIB_MainInit == NULL) {
        LOG_ERROR("Could not resolve libtpms symbol TPMLIB_MainInit(): %s", dlerror());
        goto cleanup_dl;
    }

    tcti_libtpms->TPMLIB_Process = dlsym(tcti_libtpms->libtpms, "TPMLIB_Process");
    if (tcti_libtpms->TPMLIB_Process == NULL) {
        LOG_ERROR("Could not resolve libtpms symbol TPMLIB_Process(): %s", dlerror());
        goto cleanup_dl;
    }

    tcti_libtpms->TPMLIB_Terminate = dlsym(tcti_libtpms->libtpms, "TPMLIB_Terminate");
    if (tcti_libtpms->TPMLIB_Terminate == NULL) {
        LOG_ERROR("Could not resolve libtpms symbol TPMLIB_Terminate(): %s", dlerror());
        goto cleanup_dl;
    }

    return TPM2_RC_SUCCESS;

cleanup_dl:
    dlclose(tcti_libtpms->libtpms);
    return TSS2_TCTI_RC_GENERAL_FAILURE;
}

/****************** libtpms callbacks ******************
 * Override the libtpms callbacks. This is needed to implement localities and to
 * prevent the NVChip file from being created. The other callbacks are
 * implemented as per advice from the libtpms man pages and/or as a placeholder
 * for future features.
 *
 * Using tcti_libtpms_get_current_tcti(), one can retrieve the currently active
 * libtpms TCTI instance.
 */

TPM_RESULT
tcti_libtpms_cb_nvram_init(void) {
    LOG_TRACE("tcti-libtpms callback nvram_init() called.");

    /* Nothing to do here, the map file is initialized as part of the
     * initialization of tcti-libtpms.
     */

    return TPM_SUCCESS;
}

/**
 * @brief Parse the libtpms states from the mapped memory.
 *
 * WARNING: This function assumes initialized state memory. Do not call before
 * the state was stored at least once!
 *
 * This function extracts the permanent and volatile state buffers from the
 * memory-mapped state file. It updates the provided pointers with the buffer
 * addresses and their lengths.
 *
 * @param tcti_libtpms The libtpms TCTI context containing the mapped state
 * memory.
 * @param permanent_buf_len_ptr To return the address of the permanent buffer
 * length. Due to alignment issues: do not dereference directly.
 * @param permanent_buf_len To return the length of the permanent buffer.
 * @param permanent_buf To return the address of the permanent buffer.
 * @param volatile_buf_len_ptr To return the address of the volatile buffer
 * length. Due to alignment issues: do not dereference directly.
 * @param volatile_buf_len To return the length of the volatile buffer.
 * @param volatile_buf To return the address of the volatile buffer.
 */
static void
parse_state(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms,
            unsigned char            **permanent_buf_len_ptr,
            uint32_t                  *permanent_buf_len,
            unsigned char            **permanent_buf,
            unsigned char            **volatile_buf_len_ptr,
            uint32_t                  *volatile_buf_len,
            unsigned char            **volatile_buf) {

    /* layout statefile:
     * - permanent_buf_len (4 bytes, big endian)
     * - permanent_buf (permanent_buf_len bytes)
     * - volatile_buf_len (4 bytes, big endian)
     * - volatile_buf (volatile_buf_len bytes)
     *
     * To avoid unaligned 32-bit accesses on architectures that forbid them,
     * read the 4-byte length fields via memcpy into a local uint32_t and
     * convert with ntohl(). Also perform simple bounds checks against the
     * mapped state length.
     */
    uint32_t tmp_be;

    /* permanent buffer length */
    *permanent_buf_len_ptr = tcti_libtpms->state_mmap;
    memcpy(&tmp_be, tcti_libtpms->state_mmap, sizeof(tmp_be));
    *permanent_buf_len = ntohl(tmp_be);
    *permanent_buf = (unsigned char *)tcti_libtpms->state_mmap + sizeof(uint32_t);

    /* volatile buffer length pointer is after the permanent buffer */
    *volatile_buf_len_ptr = (*permanent_buf + *permanent_buf_len);
    memcpy(&tmp_be, (unsigned char *)*volatile_buf_len_ptr, sizeof(tmp_be));
    *volatile_buf_len = ntohl(tmp_be);
    *volatile_buf = (unsigned char *)*volatile_buf_len_ptr + sizeof(uint32_t);
}

/**
 * @brief Load TPM state from persistent storage.
 *
 * This function is called when the TPM needs to retrieve state data from
 * persistent storage. The implementing function must allocate a buffer and
 * return it along with its length.
 *
 * [UNDOCUMENTED] If the state is empty, the function should leave the
 * parameters untouched and return TPM_RETRY.
 *
 * @param tcti_libtpms The libtpms TCTI context containing the mapped state memory.
 * @param tpm_number Always 0; can be ignored.
 * @param name       Type of state to load. Must be one of: - TPM_SAVESTATE_NAME
 *                   - TPM_VOLATILESTATE_NAME - TPM_PERMANENT_ALL_NAME
 * @param data       Pointer to receive allocated buffer containing the loaded
 *                   state data. The caller is responsible for freeing this
 *                   buffer.
 * @param length     Pointer to receive the length of the allocated buffer in
 * bytes.
 *
 * @return TPM_RETRY on empty state; TPM_SUCCESS on success; appropriate failure
 * code otherwise.
 */
TPM_RESULT
tcti_libtpms_load(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms,
                  unsigned char            **data,
                  uint32_t                  *length,
                  uint32_t tpm_number        MAYBE_UNUSED,
                  const char                *name) {
    unsigned char *permanent_buf_len_ptr;
    uint32_t       permanent_buf_len;
    unsigned char *permanent_buf;
    unsigned char *volatile_buf_len_ptr;
    uint32_t       volatile_buf_len;
    unsigned char *volatile_buf;
    unsigned char *state_buf;
    uint32_t       state_buf_len;

    LOG_TRACE("tcti-libtpms callback nvram_loaddata() called: "
              "data=0x%" PRIxPTR ", "
              "length=0x%" PRIxPTR ", "
              "tpm_number=%" PRIu32 ", "
              "name=%s",
              (uintptr_t)data, (uintptr_t)length, tpm_number, name);

    /* undocumented requirement: if state is empty, this function must return TPM_RETRY. */
    if (tcti_libtpms->state_len == 0) {
        LOG_DEBUG("States are empty. Return TPM_RETRY.");
        return TPM_RETRY;
    }

    /* layout statefile:
     * - permanent_buf_len (4 bytes, big endian)
     * - permanent_buf (permanent_buf_len bytes)
     * - volatile_buf_len (4 bytes, big endian)
     * - volatile_buf (volatile_buf_len bytes)
     */
    parse_state(tcti_libtpms, &permanent_buf_len_ptr, &permanent_buf_len, &permanent_buf,
                &volatile_buf_len_ptr, &volatile_buf_len, &volatile_buf);

    LOG_TRACE("Loading state from %s: permanent[%" PRIu32 "]=%p, volatile[%" PRIu32 "]=%p",
              tcti_libtpms->state_path, permanent_buf_len, permanent_buf, volatile_buf_len,
              volatile_buf);

    if (strcmp(name, TPM_SAVESTATE_NAME) == 0) {
        LOG_ERROR("Loading state is not supported yet.");
        return TPM_FAIL;
    } else if (strcmp(name, TPM_PERMANENT_ALL_NAME) == 0) {
        state_buf = permanent_buf;
        state_buf_len = permanent_buf_len;
    } else if (strcmp(name, TPM_VOLATILESTATE_NAME) == 0) {
        state_buf = volatile_buf;
        state_buf_len = volatile_buf_len;
    } else {
        LOG_ERROR("Unknown name parameter: %s", name);
        return TPM_FAIL;
    }

    /* undocumented requirement: if state is empty, this function must return TPM_RETRY. */
    if (state_buf_len == 0) {
        LOG_DEBUG("State %s is empty. Return TPM_RETRY.", name);
        return TPM_RETRY;
    }

    *data = malloc(state_buf_len);
    if (*data == NULL) {
        LOG_ERROR("Failed to allocate memory for libtpms state.");
        return TPM_FAIL;
    }
    memcpy(*data, state_buf, state_buf_len);
    *length = state_buf_len;

    return TPM_SUCCESS;
}

TPM_RESULT
tcti_libtpms_cb_nvram_loaddata(unsigned char **data,
                               uint32_t       *length,
                               uint32_t        tpm_number,
                               const char     *name) {
    if (current_tcti_libtpms == NULL) {
        LOG_ERROR("No TCTI registered as currently active before loading state.");
        return TPM_FAIL;
    }

    return tcti_libtpms_load(current_tcti_libtpms, data, length, tpm_number, name);
}

/**
 * @brief Store TPM state data to persistent storage.
 *
 * This function is called when the TPM wants to store state to persistent storage. The data and
 * length parameters provide the data to be stored and the number of bytes. The implementing
 * function must not free the data buffer.
 *
 * @param tcti_libtpms The libtpms TCTI context containing the mapped state memory.
 * @param tpm_number Always 0; can be ignored.
 * @param name       Type of state to store. Must be one of:
 *                   - TPM_SAVESTATE_NAME
 *                   - TPM_VOLATILESTATE_NAME
 *                   - TPM_PERMANENT_ALL_NAME
 * @param data Pointer to the data buffer to be stored; must not be freed by this function
 * @param length The number of bytes in the data buffer
 *
 * @return TPM_SUCCESS on success; a failure code otherwise
 */
TPM_RESULT
tcti_libtpms_store(TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms,
                   const unsigned char       *data,
                   uint32_t                   length,
                   uint32_t tpm_number        MAYBE_UNUSED,
                   const char                *name) {
    unsigned char *permanent_buf_len_ptr;
    uint32_t       permanent_buf_len;
    unsigned char *permanent_buf;
    unsigned char *volatile_buf_len_ptr;
    uint32_t       volatile_buf_len;
    unsigned char *volatile_buf;
    uint32_t       permanent_buf_len_be, volatile_buf_len_be;
    size_t         new_size = 0;
    TPM2_RC        rc;

    LOG_TRACE("tcti-libtpms callback nvram_storedata() called: "
              "data=0x%" PRIxPTR ", "
              "length=%" PRIu32 ", "
              "tpm_number=%" PRIu32 ", "
              "name=%s",
              (uintptr_t)data, length, tpm_number, name);

    /* If state is empty, initialize the state with 8 bytes of zeros. This
     * represents an empty state.
     */
    if (tcti_libtpms->state_len == 0) {
        new_size = sizeof(uint32_t) + sizeof(uint32_t);

        rc = tcti_libtpms_ensure_state_len(tcti_libtpms, new_size);
        if (rc != TSS2_RC_SUCCESS) {
            return TSS2_TCTI_RC_MEMORY;
        }

        memset(tcti_libtpms->state_mmap, 0, new_size);
        tcti_libtpms->state_len = new_size;
    }

    /* layout statefile:
     * - permanent_buf_len (4 bytes, big endian)
     * - permanent_buf (permanent_buf_len bytes)
     * - volatile_buf_len (4 bytes, big endian)
     * - volatile_buf (volatile_buf_len bytes)
     */
    parse_state(tcti_libtpms, &permanent_buf_len_ptr, &permanent_buf_len, &permanent_buf,
                &volatile_buf_len_ptr, &volatile_buf_len, &volatile_buf);

    if (strcmp(name, TPM_SAVESTATE_NAME) == 0) {
        LOG_ERROR("Saving state is not supported yet.");
        return TPM_FAIL;

    } else if (strcmp(name, TPM_VOLATILESTATE_NAME) == 0) {
        /* check if enough memory is allocated first */
        new_size = sizeof(uint32_t) + permanent_buf_len + sizeof(uint32_t) + length;
        rc = tcti_libtpms_ensure_state_len(tcti_libtpms, new_size);
        if (rc != TSS2_RC_SUCCESS) {
            return TPM_FAIL;
        }

        /* memory might have moved, refresh pointers */
        parse_state(tcti_libtpms, &permanent_buf_len_ptr, &permanent_buf_len, &permanent_buf,
                    &volatile_buf_len_ptr, &volatile_buf_len, &volatile_buf);

        /* move everything which is behind volatile state, here nothing */

        /* write volatile buffer length (big endian) */
        volatile_buf_len_be = htonl(length);
        memcpy(volatile_buf_len_ptr, &volatile_buf_len_be, sizeof(volatile_buf_len_be));

        /* write volatile buffer */
        memcpy(volatile_buf, data, length);

    } else if (strcmp(name, TPM_PERMANENT_ALL_NAME) == 0) {
        /* check if enough memory is allocated first */
        new_size = sizeof(uint32_t) + length + sizeof(uint32_t) + volatile_buf_len;
        rc = tcti_libtpms_ensure_state_len(tcti_libtpms, new_size);
        if (rc != TSS2_RC_SUCCESS) {
            return TPM_FAIL;
        }

        /* memory might have moved, refresh pointers */
        parse_state(tcti_libtpms, &permanent_buf_len_ptr, &permanent_buf_len, &permanent_buf,
                    &volatile_buf_len_ptr, &volatile_buf_len, &volatile_buf);

        /* move everything which is behind permanent state, i.e.
         * - volatile_buf_len
         * - volatile_buf
         */
        memmove(tcti_libtpms->state_mmap + sizeof(uint32_t) + length,
                tcti_libtpms->state_mmap + sizeof(uint32_t) + permanent_buf_len,
                sizeof(uint32_t) + volatile_buf_len);

        /* write permanent buffer length (big endian) */
        permanent_buf_len_be = htonl(length);
        memcpy(permanent_buf_len_ptr, &permanent_buf_len_be, sizeof(permanent_buf_len_be));

        /* write permanent buffer */
        memcpy(permanent_buf, data, length);
    } else {
        LOG_ERROR("Unknown name parameter: %s", name);
        return TPM_FAIL;
    }

    /* state changed, refresh a last time for the logging call */
    parse_state(tcti_libtpms, &permanent_buf_len_ptr, &permanent_buf_len, &permanent_buf,
                &volatile_buf_len_ptr, &volatile_buf_len, &volatile_buf);

    LOG_TRACE("Stored state to %s: permanent[%" PRIu32 "]=%p, volatile[%" PRIu32 "]=%p",
              tcti_libtpms->state_path, permanent_buf_len, permanent_buf, volatile_buf_len,
              volatile_buf);

    tcti_libtpms->state_len = new_size;

    return TPM_SUCCESS;
}

TPM_RESULT
tcti_libtpms_cb_nvram_storedata(const unsigned char *data,
                                uint32_t             length,
                                uint32_t             tpm_number,
                                const char          *name) {
    if (current_tcti_libtpms == NULL) {
        LOG_ERROR("No TCTI registered as currently active before loading state.");
        return TPM_FAIL;
    }

    return tcti_libtpms_store(current_tcti_libtpms, data, length, tpm_number, name);
}

TPM_RESULT
tcti_libtpms_cb_nvram_deletename(uint32_t tpm_number MAYBE_UNUSED,
                                 const char *name    MAYBE_UNUSED,
                                 TPM_BOOL must_exist MAYBE_UNUSED) {
    LOG_TRACE("tcti-libtpms callback nvram_deletename() called: "
              "tpm_number=%" PRIu32 ", "
              "name=%s, "
              "must_exist=%d",
              tpm_number, name, must_exist);

    LOG_ERROR("Not implemented");

    return TPM_FAIL;
}

TPM_RESULT
tcti_libtpms_cb_io_init(void) {
    LOG_TRACE("tcti-libtpms callback io_init() called.");

    return TPM_SUCCESS;
}

TPM_RESULT
tcti_libtpms_cb_io_getlocality(TPM_MODIFIER_INDICATOR *locality_modifer,
                               uint32_t tpm_number     MAYBE_UNUSED) {
    TSS2_TCTI_COMMON_CONTEXT *tcti_common;

    LOG_TRACE("tcti-libtpms callback io_getlocality() called: "
              "locality_modifer=0x%" PRIxPTR ", "
              "tpm_number=%" PRIu32,
              (uintptr_t)locality_modifer, tpm_number);

    if (locality_modifer == NULL) {
        return TPM_FAIL;
    }

    if (current_tcti_libtpms == NULL) {
        LOG_ERROR("No TCTI registered as currently active before libtpms API call.");
        return TPM_FAIL;
    }
    tcti_common = tcti_libtpms_down_cast(current_tcti_libtpms);
    *locality_modifer = tcti_common->locality;

    return TPM_SUCCESS;
}

TPM_RESULT
tcti_libtpms_cb_io_getphysicalpresence(TPM_BOOL *physical_presence MAYBE_UNUSED,
                                       uint32_t tpm_number         MAYBE_UNUSED) {
    LOG_TRACE("tcti-libtpms callback io_getphysicalpresence() called: "
              "physical_presence=0x%" PRIxPTR ", "
              "tpm_number=%" PRIu32,
              (uintptr_t)physical_presence, tpm_number);

    LOG_ERROR("Not implemented");

    return TPM_FAIL;
}
/*************** end: libtpms callbacks ****************/

TSS2_RC
Tss2_Tcti_Libtpms_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size, const char *conf) {
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT  *tcti_common = tcti_libtpms_down_cast(tcti_libtpms);
    TSS2_RC                    rc;
    TPM_RESULT                 ret;
    (void)(conf);

    LOG_TRACE("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s", (uintptr_t)tctiContext,
              (uintptr_t)size, conf);
    if (size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (tctiContext == NULL) {
        *size = sizeof(TSS2_TCTI_LIBTPMS_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    tcti_libtpms_init_context_data(tcti_common);

    rc = tcti_libtpms_set_locality(tctiContext, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_WARNING("Could not set locality: 0x%" PRIx32, rc);
        return rc;
    }

    rc = tcti_libtpms_dl(tcti_libtpms);
    if (rc != TPM2_RC_SUCCESS) {
        return rc;
    }
    LOG_TRACE("Successfully loaded libtpms and resolved symbols.");

    /* copy state path given in conf */
    if (conf == NULL || strlen(conf) == 0) {
        tcti_libtpms->state_path = NULL;
    } else {
#ifdef __FreeBSD__
        // mremap() on FreeBSD is a stub returning -1/ENOMEM
        // this could be fixed with a munmap()/mmap() workaround
        LOG_ERROR("Libtpms state files are not supported on FreeBSD. Try an empty conf string.");
        return TSS2_TCTI_RC_BAD_VALUE;
#else
        tcti_libtpms->state_path = strdup(conf);
        if (tcti_libtpms->state_path == NULL) {
            LOG_ERROR("Out of memory.");
            rc = TSS2_TCTI_RC_MEMORY;
            goto cleanup_dl;
        }
#endif
    }

    rc = tcti_libtpms_map_state_file(tcti_libtpms);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Could not create and map state file.");
        goto cleanup_state_path;
    }
    LOG_TRACE("Successfully opened memory-mapped libtpms state file: %s", tcti_libtpms->state_path);

    struct libtpms_callbacks callbacks
        = { .sizeOfStruct = sizeof(struct libtpms_callbacks),
            .tpm_nvram_init = tcti_libtpms_cb_nvram_init,
            .tpm_nvram_loaddata = tcti_libtpms_cb_nvram_loaddata,
            .tpm_nvram_storedata = tcti_libtpms_cb_nvram_storedata,
            .tpm_nvram_deletename = tcti_libtpms_cb_nvram_deletename,
            .tpm_io_init = tcti_libtpms_cb_io_init,
            .tpm_io_getlocality = tcti_libtpms_cb_io_getlocality,
            .tpm_io_getphysicalpresence = tcti_libtpms_cb_io_getphysicalpresence };
    LIBTPMS_API_CALL(cleanup_state_mmap, tcti_libtpms, TPMLIB_ChooseTPMVersion,
                     TPMLIB_TPM_VERSION_2);
    LIBTPMS_API_CALL(cleanup_state_mmap, tcti_libtpms, TPMLIB_RegisterCallbacks, &callbacks);
    LIBTPMS_API_CALL(cleanup_state_mmap, tcti_libtpms, TPMLIB_MainInit);

    tcti_libtpms->response_buffer = NULL;
    tcti_libtpms->response_buffer_len = 0;
    tcti_libtpms->response_len = 0;

    return TSS2_RC_SUCCESS;

cleanup_state_mmap:
    munmap(tcti_libtpms->state_mmap, tcti_libtpms->state_mmap_len);

cleanup_state_path:
    free(tcti_libtpms->state_path);

cleanup_dl:
    dlclose(tcti_libtpms->libtpms);

    return rc;
}

/* public info structure */
static const TSS2_TCTI_INFO tss2_tcti_libtpms_info = {
    .version = TCTI_VERSION,
    .name = "tcti-libtpms",
    .description = "TCTI module for communication with the libtpms library.",
    .config_help = "Path to the state file. NULL for no state file.",
    .init = Tss2_Tcti_Libtpms_Init,
};

const TSS2_TCTI_INFO *
Tss2_Tcti_Info(void) {
    return &tss2_tcti_libtpms_info;
}
