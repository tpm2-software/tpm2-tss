/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <dlfcn.h>               // for RTLD_LAZY, RTLD_LOCAL
#include <errno.h>               // for errno, ENOENT
#include <fcntl.h>               // for O_CREAT, O_RDWR, SEEK_END, mode_t
#include <inttypes.h>            // for uint32_t
#include <libtpms/tpm_error.h>   // for TPM_SUCCESS
#include <libtpms/tpm_library.h> // for libtpms_callbacks, TPMLIB_STATE_...
#include <libtpms/tpm_nvfilename.h> // for TPM_PERMANENT_ALL_NAME, TPM_SAVESTATE_NAME, TPM_VOLATILESTATE_NAME
#include <libtpms/tpm_tis.h>   // for TPM_IO_TpmEstablished_Reset
#include <libtpms/tpm_types.h> // for TPM_RESULT
#include <stdio.h>             // for NULL, fprintf, size_t, stderr
#include <stdlib.h>            // for free, calloc, malloc
#include <string.h>            // for memcpy, strerror, strlen, strncmp
#include <sys/mman.h>          // for MAP_FAILED, MREMAP_MAYMOVE, MAP_...
#include <unistd.h>            // for unlink

#include "../helper/cmocka_all.h"   // for will_return, expect_value, asser...
#include "tss2-tcti/tcti-common.h"  // for TSS2_TCTI_COMMON_CONTEXT, tcti_c...
#include "tss2-tcti/tcti-libtpms.h" // for TSS2_TCTI_LIBTPMS_CONTEXT, STATE...
#include "tss2_common.h"            // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_T...
#include "tss2_tcti.h"              // for TSS2_TCTI_CONTEXT, Tss2_Tcti_Tra...
#include "tss2_tcti_libtpms.h"      // for Tss2_Tcti_Libtpms_Init
#include "tss2_tpm2_types.h"        // for TPM2_RC_SUCCESS
#include "util/aux_util.h"          // for ARRAY_LEN

#define LOGMODULE test
#include "util/log.h" // for LOG_TRACE, LOG_ERROR, LOG_WARNING

#define EXIT_SKIP 77

/* function signature modified for ease of life */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
TPM_RESULT
tcti_libtpms_store(void       *tcti_libtpms,
                   const char *data,
                   uint32_t    length,
                   uint32_t    tpm_number,
                   const char *name);

TPM_RESULT
tcti_libtpms_load(void       *tcti_libtpms,
                  char      **data,
                  uint32_t   *length,
                  uint32_t    tpm_number,
                  const char *name);
#pragma GCC diagnostic pop

#define LIBTPMS_DL_HANDLE    0x12345678
#define STATEFILE_PATH       "statefile.bin"
#define STATEFILE_FD         0xAABB
#define STATEFILE_MMAP       mmap_buf
#define STATEFILE_MMAP_NEW   mmap_buf_new
#define STATEFILE_PATH_REAL0 "statefile0.bin"
#define STATEFILE_PATH_REAL1 "statefile1.bin"

#define LEN(x)               (sizeof(x) - 1)

/* loaded state */
#define S1_STATE     "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B
#define S1_STATE_LEN LEN(S1_STATE)

/* some literals */
#define LITERAL_A_3B      "aaa"
#define LITERAL_A_3B_LEN  LEN(LITERAL_A_3B)
#define LITERAL_B_5B      "bbbbb"
#define LITERAL_B_5B_LEN  LEN(LITERAL_B_5B)
#define LITERAL_C_20B     "cccccccccccccccccccc"
#define LITERAL_C_20B_LEN LEN(LITERAL_C_20B)
#define LITERAL_D_0B      ""
#define LITERAL_D_0B_LEN  LEN(LITERAL_D_0B)
#define LITERAL_E_2392B                                                                            \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#define LITERAL_E_2392B_LEN LEN(LITERAL_E_2392B)

#define LITERAL_F_4140B                                                                            \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define LITERAL_F_4140B_LEN LEN(LITERAL_F_4140B)

char mmap_buf[STATE_MMAP_CHUNK_LEN] = { 0 };
char mmap_buf_new[STATE_MMAP_CHUNK_LEN * 3] = { 0 };

struct libtpms_callbacks global_callbacks;

/* mock libtpms API */
TPM_RESULT
TPMLIB_ChooseTPMVersion(TPMLIB_TPMVersion ver) {
    check_expected(ver);
    return mock_type(int);
}
TPM_RESULT
TPMLIB_RegisterCallbacks(struct libtpms_callbacks *callbacks) {
    global_callbacks.sizeOfStruct = callbacks->sizeOfStruct;
    global_callbacks.tpm_nvram_init = callbacks->tpm_nvram_init;
    global_callbacks.tpm_nvram_loaddata = callbacks->tpm_nvram_loaddata;
    global_callbacks.tpm_nvram_storedata = callbacks->tpm_nvram_storedata;
    global_callbacks.tpm_nvram_deletename = callbacks->tpm_nvram_deletename;
    global_callbacks.tpm_io_init = callbacks->tpm_io_init;
    global_callbacks.tpm_io_getlocality = callbacks->tpm_io_getlocality;
    global_callbacks.tpm_io_getphysicalpresence = callbacks->tpm_io_getphysicalpresence;
    return mock_type(int);
}
TPM_RESULT
TPMLIB_MainInit(void) {
    uint32_t ret;
    ret = global_callbacks.tpm_nvram_init();
    assert_int_equal(ret, 0);
    ret = global_callbacks.tpm_io_init();
    assert_int_equal(ret, 0);
    return mock_type(int);
}
TPM_RESULT
TPMLIB_Process(unsigned char **resp_buf,
               uint32_t       *resp_len,
               uint32_t       *resp_buf_len,
               unsigned char  *cmd,
               uint32_t        cmd_len) {
    uint32_t locality;
    uint32_t ret;
    check_expected_ptr(cmd);
    check_expected(cmd_len);
    ret = global_callbacks.tpm_io_getlocality(&locality, 0);
    assert_int_equal(ret, 0);
    check_expected(locality);

    unsigned char *buf_out = mock_type(unsigned char *);
    *resp_buf_len = *resp_len = mock_type(uint32_t);
    *resp_buf = malloc(*resp_len);
    assert_non_null(*resp_buf);
    memcpy(*resp_buf, buf_out, *resp_len);
    return mock_type(int);
}
void
TPMLIB_Terminate(void) {}

void *
__wrap_dlopen(const char *filename, int flags) {
    LOG_TRACE("Called with filename %s and flags %x", filename, flags);
    check_expected_ptr(filename);
    check_expected(flags);
    return mock_type(void *);
}
int
__wrap_dlclose(void *handle) {
    LOG_TRACE("Called with handle %p", handle);
    check_expected_ptr(handle);
    return mock_type(int);
}
void *
__wrap_dlsym(void *handle, const char *symbol) {
    LOG_TRACE("Called with handle %p and symbol %s", handle, symbol);
    check_expected_ptr(handle);
    check_expected_ptr(symbol);
    return mock_type(void *);
}
void *__real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void *
__wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    int wrap = mock_type(int);
    if (wrap) {
        check_expected_ptr(addr);
        check_expected(len);
        check_expected(prot);
        check_expected(flags);
        check_expected(fd);
        check_expected(offset);
        return mock_type(void *);
    } else {
        return __real_mmap(addr, len, prot, flags, fd, offset);
    }
}
void *
__wrap_mremap(void *old_address, size_t old_size, size_t new_size, int flags) {
    void *new_address;
    check_expected_ptr(old_address);
    check_expected(old_size);
    check_expected(new_size);
    check_expected(flags);
    new_address = mock_type(void *);
    if (new_address != MAP_FAILED) {
        memcpy(new_address, old_address, old_size);
    }
    return new_address;
}
int __real_munmap(void *addr, size_t len);
int
__wrap_munmap(void *addr, size_t len) {
    int wrap = mock_type(int);
    if (wrap) {
        check_expected_ptr(addr);
        check_expected(len);
        return mock_type(int);
    } else {
        return __real_munmap(addr, len);
    }
}
int __real_open(const char *pathname, int flags, ...);
int
__wrap_open(const char *pathname, int flags, mode_t mode) {
    if (strncmp(pathname, STATEFILE_PATH, strlen(STATEFILE_PATH)) == 0) {
        check_expected_ptr(pathname);
        check_expected(flags);
        check_expected(mode);
        return mock_type(int);
    } else if (strncmp(pathname, STATEFILE_PATH_REAL0, strlen(STATEFILE_PATH_REAL0)) == 0
               || strncmp(pathname, STATEFILE_PATH_REAL1, strlen(STATEFILE_PATH_REAL1)) == 0) {
        check_expected_ptr(pathname);
        check_expected(flags);
        check_expected(mode);
        return __real_open(pathname, flags, mode);
    } else {
        /* only mock opening of state files as the open() syscall is needed
           for code coverage reports as well */
        return __real_open(pathname, flags, mode);
    }
}
off_t __real_lseek(int fd, off_t offset, int whence);
off_t
__wrap_lseek(int fd, off_t offset, int whence) {
    int wrap = mock_type(int);
    if (wrap) {
        check_expected(fd);
        check_expected(offset);
        check_expected(whence);
        return mock_type(off_t);
    } else {
        return __real_lseek(fd, offset, whence);
    }
}
int __real_posix_fallocate(int fd, off_t offset, off_t len);
int
__wrap_posix_fallocate(int fd, off_t offset, off_t len) {
    int wrap = mock_type(int);
    if (wrap) {
        check_expected(fd);
        check_expected(offset);
        check_expected(len);
        return mock_type(int);
    } else {
        return __real_posix_fallocate(fd, offset, len);
    }
}
int __real_truncate(const char *path, off_t length);
int
__wrap_truncate(const char *path, off_t length) {
    int wrap = mock_type(int);
    if (wrap) {
        check_expected_ptr(path);
        check_expected(length);
        return mock_type(int);
    } else {
        return __real_truncate(path, length);
    }
}
int __real_close(int fd);
int
__wrap_close(int fd) {
    int wrap = mock_type(int);
    if (wrap) {
        check_expected(fd);
        return mock_type(int);
    } else {
        return __real_close(fd);
    }
}

/* When passed all NULL values, we expect TSS2_TCTI_RC_BAD_VALUE. */
static void
tcti_libtpms_init_all_null_test(void **state) {
    TSS2_RC rc;

    rc = Tss2_Tcti_Libtpms_Init(NULL, NULL, NULL);
    assert_int_equal(rc, TSS2_TCTI_RC_BAD_VALUE);
}

/* When dlopen fails for library names we expect TSS2_TCTI_RC_GENERAL_FAILURE. */
static void
tcti_libtpms_init_dlopen_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, NULL);
    expect_string(__wrap_dlopen, filename, "libtpms.so.0");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, NULL);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, NULL);
    assert_int_equal(ret, TSS2_TCTI_RC_GENERAL_FAILURE);

    free(ctx);
}

static int   dummy;
static void *dummy_ptr = &dummy;
/* When dlsym fails for any libtpms symbol, we expect TSS2_TCTI_RC_GENERAL_FAILURE. */
static void
tcti_libtpms_init_dlsym_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    const char *syms[] = {
        "TPMLIB_ChooseTPMVersion", "TPMLIB_RegisterCallbacks", "TPMLIB_MainInit",
        "TPMLIB_Process",          "TPMLIB_Terminate",
    };

    /* test for every symbol syms[i] */
    for (size_t i = 0; i < ARRAY_LEN(syms); i++) {
        ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
        assert_true(ret == TSS2_RC_SUCCESS);
        ctx = calloc(1, tcti_size);
        assert_non_null(ctx);

        expect_string(__wrap_dlopen, filename, "libtpms.so");
        expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
        will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

        /* successfully load all symbols up to (excluding) index i */
        for (size_t j = 0; j < i; j++) {
            expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
            expect_string(__wrap_dlsym, symbol, syms[j]);
            will_return(__wrap_dlsym, dummy_ptr);
        }

        /* fail to load sym at index i */
        expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
        expect_string(__wrap_dlsym, symbol, syms[i]);
        will_return(__wrap_dlsym, NULL);

        /* cleanup */
        expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
        will_return(__wrap_dlclose, 0);

        ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, NULL);
        assert_int_equal(ret, TSS2_TCTI_RC_GENERAL_FAILURE);

        free(ctx);
    }
}

/* When open fails to open the state file, we expect TSS2_TCTI_RC_IO_ERROR. */
static void
tcti_libtpms_init_state_open_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

#ifdef __FreeBSD__
    // Currently, state files are not supported on FreeBSD
    skip();
#endif

    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_ChooseTPMVersion");
    will_return(__wrap_dlsym, &TPMLIB_ChooseTPMVersion);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_RegisterCallbacks");
    will_return(__wrap_dlsym, &TPMLIB_RegisterCallbacks);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_MainInit");
    will_return(__wrap_dlsym, &TPMLIB_MainInit);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Process");
    will_return(__wrap_dlsym, &TPMLIB_Process);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Terminate");
    will_return(__wrap_dlsym, &TPMLIB_Terminate);

    /* fail open */
    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, -1);

    /* cleanup */
    expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
    will_return(__wrap_dlclose, 0);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, STATEFILE_PATH);
    assert_int_equal(ret, TSS2_TCTI_RC_IO_ERROR);

    free(ctx);
}

/* When lseek fails on the state file, we expect TSS2_TCTI_RC_IO_ERROR. */
static void
tcti_libtpms_init_state_lseek_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

#ifdef __FreeBSD__
    // Currently, state files are not supported on FreeBSD
    skip();
#endif

    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_ChooseTPMVersion");
    will_return(__wrap_dlsym, &TPMLIB_ChooseTPMVersion);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_RegisterCallbacks");
    will_return(__wrap_dlsym, &TPMLIB_RegisterCallbacks);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_MainInit");
    will_return(__wrap_dlsym, &TPMLIB_MainInit);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Process");
    will_return(__wrap_dlsym, &TPMLIB_Process);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Terminate");
    will_return(__wrap_dlsym, &TPMLIB_Terminate);

    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, STATEFILE_FD);

    /* fail to lseek */
    expect_value(__wrap_lseek, fd, STATEFILE_FD);
    expect_value(__wrap_lseek, offset, 0L);
    expect_value(__wrap_lseek, whence, SEEK_END);
    will_return(__wrap_lseek, 1); /* wrap = true */
    will_return(__wrap_lseek, -1);

    /* cleanup */
    expect_value(__wrap_close, fd, STATEFILE_FD);
    will_return(__wrap_close, 1); /* wrap = true */
    will_return(__wrap_close, 0);

    expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
    will_return(__wrap_dlclose, 0);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, STATEFILE_PATH);
    assert_int_equal(ret, TSS2_TCTI_RC_IO_ERROR);

    free(ctx);
}

/* When posix_fallocate fails on the state file, we expect TSS2_TCTI_RC_IO_ERROR. */
static void
tcti_libtpms_init_state_posix_fallocate_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

#ifdef __FreeBSD__
    // Currently, state files are not supported on FreeBSD
    skip();
#endif

    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_ChooseTPMVersion");
    will_return(__wrap_dlsym, &TPMLIB_ChooseTPMVersion);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_RegisterCallbacks");
    will_return(__wrap_dlsym, &TPMLIB_RegisterCallbacks);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_MainInit");
    will_return(__wrap_dlsym, &TPMLIB_MainInit);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Process");
    will_return(__wrap_dlsym, &TPMLIB_Process);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Terminate");
    will_return(__wrap_dlsym, &TPMLIB_Terminate);

    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, STATEFILE_FD);

    expect_value(__wrap_lseek, fd, STATEFILE_FD);
    expect_value(__wrap_lseek, offset, 0L);
    expect_value(__wrap_lseek, whence, SEEK_END);
    will_return(__wrap_lseek, 1); /* wrap = true */
    will_return(__wrap_lseek, S1_STATE_LEN);

    /* fail to posix_fallocate */
    expect_value(__wrap_posix_fallocate, fd, STATEFILE_FD);
    expect_value(__wrap_posix_fallocate, offset, 0);
    expect_value(__wrap_posix_fallocate, len, STATE_MMAP_CHUNK_LEN);
    will_return(__wrap_posix_fallocate, 1); /* wrap = true */
    will_return(__wrap_posix_fallocate, -1);

    /* cleanup */
    expect_value(__wrap_close, fd, STATEFILE_FD);
    will_return(__wrap_close, 1); /* wrap = true */
    will_return(__wrap_close, 0);

    expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
    will_return(__wrap_dlclose, 0);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, STATEFILE_PATH);
    assert_int_equal(ret, TSS2_TCTI_RC_IO_ERROR);

    free(ctx);
}

/* When mmap fails on the state file, we expect TSS2_TCTI_RC_IO_ERROR. */
static void
tcti_libtpms_init_state_mmap_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

#ifdef __FreeBSD__
    // Currently, state files are not supported on FreeBSD
    skip();
#endif

    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_ChooseTPMVersion");
    will_return(__wrap_dlsym, &TPMLIB_ChooseTPMVersion);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_RegisterCallbacks");
    will_return(__wrap_dlsym, &TPMLIB_RegisterCallbacks);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_MainInit");
    will_return(__wrap_dlsym, &TPMLIB_MainInit);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Process");
    will_return(__wrap_dlsym, &TPMLIB_Process);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Terminate");
    will_return(__wrap_dlsym, &TPMLIB_Terminate);

    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, STATEFILE_FD);

    expect_value(__wrap_lseek, fd, STATEFILE_FD);
    expect_value(__wrap_lseek, offset, 0L);
    expect_value(__wrap_lseek, whence, SEEK_END);
    will_return(__wrap_lseek, 1); /* wrap = true */
    will_return(__wrap_lseek, S1_STATE_LEN);

    expect_value(__wrap_posix_fallocate, fd, STATEFILE_FD);
    expect_value(__wrap_posix_fallocate, offset, 0);
    expect_value(__wrap_posix_fallocate, len, STATE_MMAP_CHUNK_LEN);
    will_return(__wrap_posix_fallocate, 1); /* wrap = true */
    will_return(__wrap_posix_fallocate, 0);

    /* fail to mmap */
    expect_value(__wrap_mmap, addr, NULL);
    expect_value(__wrap_mmap, len, STATE_MMAP_CHUNK_LEN);
    expect_value(__wrap_mmap, prot, PROT_READ | PROT_WRITE);
    expect_value(__wrap_mmap, flags, MAP_SHARED);
    expect_value(__wrap_mmap, fd, STATEFILE_FD);
    expect_value(__wrap_mmap, offset, 0);
    will_return(__wrap_mmap, 1); /* wrap = true */
    will_return(__wrap_mmap, MAP_FAILED);

    /* cleanup */
    expect_value(__wrap_close, fd, STATEFILE_FD);
    will_return(__wrap_close, 1); /* wrap = true */
    will_return(__wrap_close, 0);

    expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
    will_return(__wrap_dlclose, 0);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, STATEFILE_PATH);
    assert_int_equal(ret, TSS2_TCTI_RC_IO_ERROR);

    free(ctx);
}

/* Currently, state files are not supported on FreeBSD. */
static void
tcti_libtpms_init_state_freebsd_fail_test(void **state) {
    size_t             tcti_size = 0;
    TSS2_RC            ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    // FreeBSD-only test
#ifndef __FreeBSD__
    skip();
#endif

    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    // successfull dlopen
    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_ChooseTPMVersion");
    will_return(__wrap_dlsym, &TPMLIB_ChooseTPMVersion);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_RegisterCallbacks");
    will_return(__wrap_dlsym, &TPMLIB_RegisterCallbacks);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_MainInit");
    will_return(__wrap_dlsym, &TPMLIB_MainInit);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Process");
    will_return(__wrap_dlsym, &TPMLIB_Process);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Terminate");
    will_return(__wrap_dlsym, &TPMLIB_Terminate);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, STATEFILE_PATH);
    assert_int_equal(ret, TSS2_TCTI_RC_BAD_VALUE);

    free(ctx);
}
/*
 * This is a utility function used by other tests to setup a TCTI context. It
 * effectively wraps the init / allocate / init pattern as well as priming the
 * mock functions necessary for a the successful call to
 * 'Tss2_Tcti_Libtpms_Init'.
 */
static TSS2_TCTI_CONTEXT *
tcti_libtpms_init_from_conf(const char *conf) {
    size_t                     tcti_size = 0;
    TSS2_RC                    ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT         *ctx = NULL;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms;

    memcpy(mmap_buf, S1_STATE, S1_STATE_LEN);

    fprintf(stderr, "%s: before first init\n", __func__);
    ret = Tss2_Tcti_Libtpms_Init(NULL, &tcti_size, NULL);
    assert_true(ret == TSS2_RC_SUCCESS);
    ctx = calloc(1, tcti_size);
    assert_non_null(ctx);

    fprintf(stderr, "%s: before second_init\n", __func__);
    expect_string(__wrap_dlopen, filename, "libtpms.so");
    expect_value(__wrap_dlopen, flags, RTLD_LAZY | RTLD_LOCAL);
    will_return(__wrap_dlopen, LIBTPMS_DL_HANDLE);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_ChooseTPMVersion");
    will_return(__wrap_dlsym, &TPMLIB_ChooseTPMVersion);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_RegisterCallbacks");
    will_return(__wrap_dlsym, &TPMLIB_RegisterCallbacks);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_MainInit");
    will_return(__wrap_dlsym, &TPMLIB_MainInit);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Process");
    will_return(__wrap_dlsym, &TPMLIB_Process);

    expect_value(__wrap_dlsym, handle, LIBTPMS_DL_HANDLE);
    expect_string(__wrap_dlsym, symbol, "TPMLIB_Terminate");
    will_return(__wrap_dlsym, &TPMLIB_Terminate);

    if (conf != NULL) {
        expect_string(__wrap_open, pathname, STATEFILE_PATH);
        expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
        expect_value(__wrap_open, mode, 0644);
        will_return(__wrap_open, STATEFILE_FD);

        expect_value(__wrap_lseek, fd, STATEFILE_FD);
        expect_value(__wrap_lseek, offset, 0L);
        expect_value(__wrap_lseek, whence, SEEK_END);
        will_return(__wrap_lseek, 1); /* wrap = true */
        will_return(__wrap_lseek, S1_STATE_LEN);

        expect_value(__wrap_posix_fallocate, fd, STATEFILE_FD);
        expect_value(__wrap_posix_fallocate, offset, 0);
        expect_value(__wrap_posix_fallocate, len, STATE_MMAP_CHUNK_LEN);
        will_return(__wrap_posix_fallocate, 1); /* wrap = true */
        will_return(__wrap_posix_fallocate, 0);

        expect_value(__wrap_mmap, addr, NULL);
        expect_value(__wrap_mmap, len, STATE_MMAP_CHUNK_LEN);
        expect_value(__wrap_mmap, prot, PROT_READ | PROT_WRITE);
        expect_value(__wrap_mmap, flags, MAP_SHARED);
        expect_value(__wrap_mmap, fd, STATEFILE_FD);
        expect_value(__wrap_mmap, offset, 0);
        will_return(__wrap_mmap, 1); /* wrap = true */
        will_return(__wrap_mmap, STATEFILE_MMAP);

        expect_value(__wrap_close, fd, STATEFILE_FD);
        will_return(__wrap_close, 1); /* wrap = true */
        will_return(__wrap_close, 0);
    } else {
        expect_value(__wrap_mmap, addr, NULL);
        expect_value(__wrap_mmap, len, STATE_MMAP_CHUNK_LEN);
        expect_value(__wrap_mmap, prot, PROT_READ | PROT_WRITE);
        expect_value(__wrap_mmap, flags, MAP_PRIVATE | MAP_ANONYMOUS);
        expect_value(__wrap_mmap, fd, -1);
        expect_value(__wrap_mmap, offset, 0);
        will_return(__wrap_mmap, 1); /* wrap = true */
        will_return(__wrap_mmap, STATEFILE_MMAP);
    }

    expect_value(TPMLIB_ChooseTPMVersion, ver, TPMLIB_TPM_VERSION_2);
    will_return(TPMLIB_ChooseTPMVersion, 0);
    will_return(TPMLIB_RegisterCallbacks, 0);
    will_return(TPMLIB_MainInit, 0);

    ret = Tss2_Tcti_Libtpms_Init(ctx, &tcti_size, conf);
    fprintf(stderr, "%s: after second init\n", __func__);
    assert_int_equal(ret, TSS2_RC_SUCCESS);

    tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    if (conf != NULL) {
        assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
        assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
        assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
        assert_int_equal(tcti_libtpms->state_len, S1_STATE_LEN);
        assert_memory_equal(tcti_libtpms->state_mmap, S1_STATE, S1_STATE_LEN);
    } else {
        assert_ptr_equal(tcti_libtpms->state_path, NULL);
        assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
        assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
        assert_int_equal(tcti_libtpms->state_len, 0);
    }

    return ctx;
}

/* Test the store routine without any state file */
static void
tcti_libtpms_no_statefile_store_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_ptr_equal(tcti_libtpms->state_path, NULL);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 0);

    /* permanent state only */
    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_A_3B, LITERAL_A_3B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_ptr_equal(tcti_libtpms->state_path, NULL);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4);
    assert_memory_equal(tcti_libtpms->state_mmap, "\0\0\0\x03" LITERAL_A_3B "\0\0\0\0",
                        4 + LITERAL_A_3B_LEN + 4);

    /* reset state */
    memset(tcti_libtpms->state_mmap, 0, tcti_libtpms->state_len);
    tcti_libtpms->state_len = 0;

    /* volatile state only */
    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_A_3B, LITERAL_A_3B_LEN, 0,
                             TPM_VOLATILESTATE_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_ptr_equal(tcti_libtpms->state_path, NULL);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + 4 + LITERAL_A_3B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\0"
                        "\0\0\0\x03" LITERAL_A_3B,
                        4 + 4 + LITERAL_A_3B_LEN);

    /* reset state */
    memset(tcti_libtpms->state_mmap, 0, tcti_libtpms->state_len);
    tcti_libtpms->state_len = 0;

    /* permanent and volatile state */
    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_A_3B, LITERAL_A_3B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_B_5B, LITERAL_B_5B_LEN, 0,
                             TPM_VOLATILESTATE_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_ptr_equal(tcti_libtpms->state_path, NULL);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    /* reset state */
    memset(tcti_libtpms->state_mmap, 0, tcti_libtpms->state_len);
    tcti_libtpms->state_len = 0;

    /* other way round: volatile and permanent state */
    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_B_5B, LITERAL_B_5B_LEN, 0,
                             TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_A_3B, LITERAL_A_3B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_ptr_equal(tcti_libtpms->state_path, NULL);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
}

/* Test the load routine without any state file */
static void
tcti_libtpms_no_statefile_load_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    char                      *data = NULL;
    uint32_t                   data_len = 0;
    TPM_RESULT                 ret;

    assert_ptr_equal(tcti_libtpms->state_path, NULL);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 0);

    /* empty state */
    data = NULL;
    data_len = 0;
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_RETRY);
    assert_int_equal(data_len, 0);
    assert_ptr_equal(data, NULL);

    /* permanent state only */
    memcpy(tcti_libtpms->state_mmap, "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x00",
           4 + LITERAL_A_3B_LEN + 4);
    tcti_libtpms->state_len = 4 + LITERAL_A_3B_LEN + 4;

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_A_3B_LEN);
    assert_memory_equal(data, LITERAL_A_3B, LITERAL_A_3B_LEN);
    free(data);

    data = NULL;
    data_len = 0;
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_RETRY);
    assert_int_equal(data_len, 0);
    assert_ptr_equal(data, NULL);

    /* volatile state only */
    memcpy(tcti_libtpms->state_mmap,
           "\0\0\0\x00"
           "\0\0\0\x05" LITERAL_B_5B,
           4 + 4 + LITERAL_B_5B_LEN);
    tcti_libtpms->state_len = 4 + 4 + LITERAL_B_5B_LEN;

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_B_5B_LEN);
    assert_memory_equal(data, LITERAL_B_5B, LITERAL_B_5B_LEN);
    free(data);

    data = NULL;
    data_len = 0;
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_RETRY);
    assert_int_equal(data_len, 0);
    assert_ptr_equal(data, NULL);

    /* both states */
    memcpy(tcti_libtpms->state_mmap, "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
           4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    tcti_libtpms->state_len = 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN;

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_A_3B_LEN);
    assert_memory_equal(data, LITERAL_A_3B, LITERAL_A_3B_LEN);
    free(data);

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_B_5B_LEN);
    assert_memory_equal(data, LITERAL_B_5B, LITERAL_B_5B_LEN);
    free(data);
}

/* Test the store routine with a state file */
static void
tcti_libtpms_store_persistent_smaller_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_D_0B, LITERAL_D_0B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x00"
                        ""
                        "\0\0\0\x05" LITERAL_B_5B,
                        4 + 4 + LITERAL_B_5B_LEN);
}

/* Test the store routine with a state file */
static void
tcti_libtpms_store_persistent_bigger_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_C_20B, LITERAL_C_20B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_C_20B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x14" LITERAL_C_20B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_C_20B_LEN + 4 + LITERAL_B_5B_LEN);
}

/* Test the store routine with a state file, forcing remap */
static void
tcti_libtpms_store_persistent_huge_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    /* expect remap */
    expect_value(__wrap_mremap, old_address, STATEFILE_MMAP);
    expect_value(__wrap_mremap, old_size, STATE_MMAP_CHUNK_LEN);
    expect_value(__wrap_mremap, new_size, STATE_MMAP_CHUNK_LEN * 2);
    expect_value(__wrap_mremap, flags, MREMAP_MAYMOVE);
    will_return(__wrap_mremap, STATEFILE_MMAP_NEW);

    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, STATEFILE_FD);

    expect_value(__wrap_posix_fallocate, fd, STATEFILE_FD);
    expect_value(__wrap_posix_fallocate, offset, 0);
    expect_value(__wrap_posix_fallocate, len, STATE_MMAP_CHUNK_LEN * 2);
    will_return(__wrap_posix_fallocate, 1); /* wrap = true */
    will_return(__wrap_posix_fallocate, 0);

    expect_value(__wrap_close, fd, STATEFILE_FD);
    will_return(__wrap_close, 1); /* wrap = true */
    will_return(__wrap_close, 0);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_E_2392B, LITERAL_E_2392B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP_NEW);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN * 2);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_E_2392B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\x09\x58" LITERAL_E_2392B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_E_2392B_LEN + 4 + LITERAL_B_5B_LEN);
}

/* Test the store routine with a state file, forcing remap of two chunks */
static void
tcti_libtpms_store_persistent_ridiculously_huge_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    /* expect double remap */
    expect_value(__wrap_mremap, old_address, STATEFILE_MMAP);
    expect_value(__wrap_mremap, old_size, STATE_MMAP_CHUNK_LEN);
    expect_value(__wrap_mremap, new_size, STATE_MMAP_CHUNK_LEN * 3);
    expect_value(__wrap_mremap, flags, MREMAP_MAYMOVE);
    will_return(__wrap_mremap, STATEFILE_MMAP_NEW);

    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, STATEFILE_FD);

    expect_value(__wrap_posix_fallocate, fd, STATEFILE_FD);
    expect_value(__wrap_posix_fallocate, offset, 0);
    expect_value(__wrap_posix_fallocate, len, STATE_MMAP_CHUNK_LEN * 3);
    will_return(__wrap_posix_fallocate, 1); /* wrap = true */
    will_return(__wrap_posix_fallocate, 0);

    expect_value(__wrap_close, fd, STATEFILE_FD);
    will_return(__wrap_close, 1); /* wrap = true */
    will_return(__wrap_close, 0);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_F_4140B, LITERAL_F_4140B_LEN, 0,
                             TPM_PERMANENT_ALL_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP_NEW);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN * 3);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_F_4140B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\x10\x2c" LITERAL_F_4140B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_F_4140B_LEN + 4 + LITERAL_B_5B_LEN);
}

/* Test the store routine with a state file */
static void
tcti_libtpms_store_volatile_smaller_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_D_0B, LITERAL_D_0B_LEN, 0,
                             TPM_VOLATILESTATE_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4);
    assert_memory_equal(tcti_libtpms->state_mmap, "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x00",
                        4 + LITERAL_A_3B_LEN + 4);
}

/* Test the store routine with a state file */
static void
tcti_libtpms_store_volatile_bigger_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_C_20B, LITERAL_C_20B_LEN, 0,
                             TPM_VOLATILESTATE_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_C_20B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x14" LITERAL_C_20B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_C_20B_LEN);
}

/* Test the store routine with a state file */
static void
tcti_libtpms_store_volatile_huge_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x05" LITERAL_B_5B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    /* expect remap */
    expect_value(__wrap_mremap, old_address, STATEFILE_MMAP);
    expect_value(__wrap_mremap, old_size, STATE_MMAP_CHUNK_LEN);
    expect_value(__wrap_mremap, new_size, STATE_MMAP_CHUNK_LEN * 2);
    expect_value(__wrap_mremap, flags, MREMAP_MAYMOVE);
    will_return(__wrap_mremap, STATEFILE_MMAP_NEW);

    expect_string(__wrap_open, pathname, STATEFILE_PATH);
    expect_value(__wrap_open, flags, O_RDWR | O_CREAT);
    expect_value(__wrap_open, mode, 0644);
    will_return(__wrap_open, STATEFILE_FD);

    expect_value(__wrap_posix_fallocate, fd, STATEFILE_FD);
    expect_value(__wrap_posix_fallocate, offset, 0);
    expect_value(__wrap_posix_fallocate, len, STATE_MMAP_CHUNK_LEN * 2);
    will_return(__wrap_posix_fallocate, 1); /* wrap = true */
    will_return(__wrap_posix_fallocate, 0);

    expect_value(__wrap_close, fd, STATEFILE_FD);
    will_return(__wrap_close, 1); /* wrap = true */
    will_return(__wrap_close, 0);

    ret = tcti_libtpms_store(tcti_libtpms, LITERAL_E_2392B, LITERAL_E_2392B_LEN, 0,
                             TPM_VOLATILESTATE_NAME);

    assert_int_equal(ret, TPM_SUCCESS);
    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP_NEW);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN * 2);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_E_2392B_LEN);
    assert_memory_equal(tcti_libtpms->state_mmap,
                        "\0\0\0\x03" LITERAL_A_3B "\0\0\x09\x58" LITERAL_E_2392B,
                        4 + LITERAL_A_3B_LEN + 4 + LITERAL_E_2392B_LEN);
}

/* Test the load routine with a state file */
static void
tcti_libtpms_load_test(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;
    char                      *data = NULL;
    uint32_t                   data_len = 0;
    TPM_RESULT                 ret;

    assert_string_equal(tcti_libtpms->state_path, STATEFILE_PATH);
    assert_ptr_equal(tcti_libtpms->state_mmap, STATEFILE_MMAP);
    assert_int_equal(tcti_libtpms->state_mmap_len, STATE_MMAP_CHUNK_LEN);
    assert_int_equal(tcti_libtpms->state_len, 4 + LITERAL_A_3B_LEN + 4 + LITERAL_B_5B_LEN);

    /* both states */
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_A_3B_LEN);
    assert_memory_equal(data, LITERAL_A_3B, LITERAL_A_3B_LEN);
    free(data);

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_B_5B_LEN);
    assert_memory_equal(data, LITERAL_B_5B, LITERAL_B_5B_LEN);
    free(data);

    /* permanent state only */
    memcpy(tcti_libtpms->state_mmap, "\0\0\0\x03" LITERAL_A_3B "\0\0\0\x00",
           4 + LITERAL_A_3B_LEN + 4);
    tcti_libtpms->state_len = 4 + LITERAL_A_3B_LEN + 4;

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_A_3B_LEN);
    assert_memory_equal(data, LITERAL_A_3B, LITERAL_A_3B_LEN);
    free(data);

    data = NULL;
    data_len = 0;
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_RETRY);
    assert_int_equal(data_len, 0);
    assert_ptr_equal(data, NULL);

    /* volatile state only */
    memcpy(tcti_libtpms->state_mmap,
           "\0\0\0\x00"
           "\0\0\0\x05" LITERAL_B_5B,
           4 + 4 + LITERAL_B_5B_LEN);
    tcti_libtpms->state_len = 4 + 4 + LITERAL_B_5B_LEN;

    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_VOLATILESTATE_NAME);
    assert_int_equal(ret, TPM_SUCCESS);
    assert_int_equal(data_len, LITERAL_B_5B_LEN);
    assert_memory_equal(data, LITERAL_B_5B, LITERAL_B_5B_LEN);
    free(data);

    data = NULL;
    data_len = 0;
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_RETRY);
    assert_int_equal(data_len, 0);
    assert_ptr_equal(data, NULL);

    /* empty state */
    tcti_libtpms->state_len = 0;

    data = NULL;
    data_len = 0;
    ret = tcti_libtpms_load(tcti_libtpms, &data, &data_len, 0, TPM_PERMANENT_ALL_NAME);
    assert_int_equal(ret, TPM_RETRY);
    assert_int_equal(data_len, 0);
    assert_ptr_equal(data, NULL);
}

/*
 * This is a utility function to setup the "default" TCTI context.
 */
static int
tcti_libtpms_setup(void **state) {
#ifdef __FreeBSD__
    // Currently, state files are not supported on FreeBSD
    return 0;
#endif

    fprintf(stderr, "%s: before tcti_libtpms_init_from_conf\n", __func__);
    *state = tcti_libtpms_init_from_conf(STATEFILE_PATH);
    fprintf(stderr, "%s: done\n", __func__);
    return 0;
}
/*
 * This is a utility function to setup the "default" TCTI context.
 */
static int
tcti_libtpms_setup_no_statefile(void **state) {
    fprintf(stderr, "%s: before tcti_libtpms_init_from_conf\n", __func__);
    *state = tcti_libtpms_init_from_conf(NULL);
    fprintf(stderr, "%s: done\n", __func__);
    return 0;
}
/*
 * This is a utility function to teardown a TCTI context allocated by the
 * tcti_libtpms_setup function. Will expect no state file.
 */
static int
tcti_libtpms_teardown_no_statefile(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;

    expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
    will_return(__wrap_dlclose, 0);

    expect_value(__wrap_munmap, addr, tcti_libtpms->state_mmap);
    expect_value(__wrap_munmap, len, tcti_libtpms->state_mmap_len);
    will_return(__wrap_munmap, 1); /* wrap = true */
    will_return(__wrap_munmap, 0);

    Tss2_Tcti_Finalize(ctx);
    free(ctx);
    return 0;
}
/*
 * This is a utility function to teardown a TCTI context allocated by the
 * tcti_libtpms_setup function. Will expect libtpms state 1.
 */
static int
tcti_libtpms_teardown_any(void **state) {
    TSS2_TCTI_CONTEXT         *ctx = (TSS2_TCTI_CONTEXT *)*state;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = (TSS2_TCTI_LIBTPMS_CONTEXT *)ctx;

#ifdef __FreeBSD__
    // Currently, state files are not supported on FreeBSD
    return 0;
#endif

    expect_value(__wrap_dlclose, handle, LIBTPMS_DL_HANDLE);
    will_return(__wrap_dlclose, 0);

    if (tcti_libtpms->state_mmap != NULL) {
        expect_value(__wrap_munmap, addr, tcti_libtpms->state_mmap);
        expect_value(__wrap_munmap, len, tcti_libtpms->state_mmap_len);
        will_return(__wrap_munmap, 1); /* wrap = true */
        will_return(__wrap_munmap, 0);
    }

    expect_string(__wrap_truncate, path, tcti_libtpms->state_path);
    expect_value(__wrap_truncate, length, tcti_libtpms->state_len);
    will_return(__wrap_truncate, 1); /* wrap = true */
    will_return(__wrap_truncate, 0);

    Tss2_Tcti_Finalize(ctx);
    free(ctx);
    return 0;
}

int
main(int argc, char *argv[]) {
#if _FILE_OFFSET_BITS == 64
    // Would produce cmocka error
    LOG_WARNING("_FILE_OFFSET == 64 would produce cmocka errors.");
    return EXIT_SKIP;
#endif

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tcti_libtpms_init_all_null_test),
        cmocka_unit_test(tcti_libtpms_init_dlopen_fail_test),
        cmocka_unit_test(tcti_libtpms_init_dlsym_fail_test),
        cmocka_unit_test(tcti_libtpms_init_state_open_fail_test),
        cmocka_unit_test(tcti_libtpms_init_state_lseek_fail_test),
        cmocka_unit_test(tcti_libtpms_init_state_posix_fallocate_fail_test),
        cmocka_unit_test(tcti_libtpms_init_state_mmap_fail_test),
        cmocka_unit_test(tcti_libtpms_init_state_freebsd_fail_test),
        cmocka_unit_test_setup_teardown(tcti_libtpms_no_statefile_store_test,
                                        tcti_libtpms_setup_no_statefile,
                                        tcti_libtpms_teardown_no_statefile),
        cmocka_unit_test_setup_teardown(tcti_libtpms_no_statefile_load_test,
                                        tcti_libtpms_setup_no_statefile,
                                        tcti_libtpms_teardown_no_statefile),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_persistent_smaller_test,
                                        tcti_libtpms_setup, tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_persistent_bigger_test,
                                        tcti_libtpms_setup, tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_persistent_huge_test, tcti_libtpms_setup,
                                        tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_persistent_ridiculously_huge_test,
                                        tcti_libtpms_setup, tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_volatile_smaller_test,
                                        tcti_libtpms_setup, tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_volatile_bigger_test, tcti_libtpms_setup,
                                        tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_store_volatile_huge_test, tcti_libtpms_setup,
                                        tcti_libtpms_teardown_any),
        cmocka_unit_test_setup_teardown(tcti_libtpms_load_test, tcti_libtpms_setup,
                                        tcti_libtpms_teardown_any),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
