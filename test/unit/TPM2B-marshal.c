/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "tss2_mu.h"
#include "util/tss2_endian.h"

/*
 * Success case
 */
static void
tpm2b_marshal_success(void **state) {
    TPM2B_DIGEST dgst = {4, {0}};
    TPM2B_ECC_POINT point = {sizeof(TPMS_ECC_POINT), {0}};
    uint8_t buffer[sizeof(dgst) + sizeof(point)] = {0};
    size_t  buffer_size = sizeof(buffer);
    uint16_t *size_ptr = (uint16_t *) buffer;
    uint32_t *ptr = (uint32_t *) (buffer + 2);
    uint32_t value = 0xdeadbeef;
    uint64_t value2 = 0xdeadbeefdeadbeefULL;
    uint64_t *ptr2;
    TSS2_RC rc;

    memcpy(dgst.buffer, &value, sizeof(value));
    memcpy(point.point.x.buffer, &value, sizeof(value));
    point.point.x.size = sizeof(value);
    memcpy(point.point.y.buffer, &value2, sizeof(value2));
    point.point.y.size = sizeof(value2);

    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, buffer, buffer_size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (*size_ptr, HOST_TO_BE_16(4));
    assert_int_equal (*ptr, value);

    size_ptr = (uint16_t *) buffer;
    ptr = (uint32_t *) (buffer + 4);
    rc = Tss2_MU_TPM2B_ECC_POINT_Marshal(&point, buffer, buffer_size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    /*
     * size_ptr points to the size of the whole TPMS_ECC_POINT:
     * sizeof(unit16) + sizeof(value) + sizeof(unit16) + sizeof(value2)
     */
    assert_int_equal (*size_ptr, HOST_TO_BE_16(2 + 4 + 2 + 8));
    /* check point.x: */
    assert_int_equal (*(size_ptr + 1), HOST_TO_BE_16(4));
    assert_int_equal (*ptr, value);
    size_ptr = (uint16_t *) (buffer + 2 + 2 + 4);
    ptr2 = (uint64_t *) (buffer + 2 + 2 + 2 + 4);
    /* check point.y: */
    assert_int_equal (*size_ptr, HOST_TO_BE_16(8));
    assert_int_equal (*ptr2, value2);
}

/*
 * Success case with a valid offset
 */
static void
tpm2b_marshal_success_offset(void **state) {
    TPM2B_DIGEST dgst = {4, {0}};
    TPM2B_ECC_POINT point = {sizeof(TPMS_ECC_POINT), {0}};
    size_t offset = 10;
    uint8_t buffer[sizeof(dgst) + sizeof(point) + 10] = {0};
    size_t  buffer_size = sizeof(buffer);
    uint16_t *size_ptr = (uint16_t *) (buffer + 10);
    uint32_t *ptr = (uint32_t *) (buffer + 2 + 10);
    uint32_t value = 0xdeadbeef;
    uint64_t value2 = 0xdeadbeefdeadbeefULL;
    uint64_t *ptr2;
    TSS2_RC rc;

    memcpy(dgst.buffer, &value, sizeof(value));
    memcpy(point.point.x.buffer, &value, sizeof(value));
    point.point.x.size = sizeof(value);
    memcpy(point.point.y.buffer, &value2, sizeof(value2));
    point.point.y.size = sizeof(value2);

    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, buffer, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (*size_ptr, HOST_TO_BE_16(4));
    assert_int_equal (*ptr, value);
    /* check the offset */
    assert_int_equal (offset, 10 + 2 + 4);

    size_ptr = (uint16_t *) (buffer + offset);
    ptr = (uint32_t *) (buffer + offset + 4);
    rc = Tss2_MU_TPM2B_ECC_POINT_Marshal(&point, buffer, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    /*
     * size_ptr points to the size of the whole TPMS_ECC_POINT:
     * sizeof(unit16) + sizeof(value) + sizeof(unit16) + sizeof(value2)
     */
    assert_int_equal (*size_ptr, HOST_TO_BE_16(2 + 4 + 2 + 8));
    /* check point.x: */
    assert_int_equal (*(size_ptr + 1), HOST_TO_BE_16(4));
    assert_int_equal (*ptr, value);
    size_ptr = (uint16_t *) (buffer + 10 + 2 + 4 + 2 + 2 + 4);
    ptr2 = (uint64_t *) (buffer + 10 + 2 + 4 + 2 + 2 + 4 + 2);

    /* check point.y: */
    assert_int_equal (*size_ptr, HOST_TO_BE_16(8));
    assert_int_equal (*ptr2, value2);
    /* check the offset */
    assert_int_equal (offset, 10 + 2 + 4 + 2 + 2 + 4 + 2 + 8);
}

/*
 * Success case with a null buffer
 */
static void
tpm2b_marshal_buffer_null_with_offset(void **state)
{
    TPM2B_DIGEST dgst = {4, {0}};
    TPM2B_ECC_POINT point = {sizeof(TPMS_ECC_POINT), {0}};
    size_t offset = 10;
    size_t  buffer_size = sizeof(dgst) + sizeof(point) + 10;
    uint32_t value = 0xdeadbeef;
    uint64_t value2 = 0xdeadbeefdeadbeefULL;

    TSS2_RC rc;

    memcpy(dgst.buffer, &value, sizeof(value));
    memcpy(point.point.x.buffer, &value, sizeof(value));
    point.point.x.size = sizeof(value);
    memcpy(point.point.y.buffer, &value2, sizeof(value2));
    point.point.y.size = sizeof(value2);

    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, NULL, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 10 + 2 + 4);

    offset = 10;
    rc = Tss2_MU_TPM2B_ECC_POINT_Marshal(&point, NULL, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 10 + 2 + 2 + sizeof(value) + 2 + sizeof(value2));
    offset = 0;
    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, NULL, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    /*
     * TSS MU spec states:
     * If the 'buffer' parameter is NULL the implementation shall not write
     * any marshaled data but the 'offset' parameter shall be updated as
     * though it had.
     * The offset of call with NULL and not NULL buffer will be compared.
     */
    uint8_t buffer[offset];

    size_t offset1 = 0;
    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, NULL, buffer_size, &offset1);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    size_t offset2 = 0;
    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, buffer, buffer_size, &offset2);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset1, offset2);

}

/*
 * Invalid case with a null buffer and a null offset
 */
static void
tpm2b_marshal_buffer_null_offset_null(void **state)
{
    TPM2B_DIGEST dgst = {4, {0}};
    TPM2B_ECC_POINT point = {sizeof(TPMS_ECC_POINT), {0}};
    size_t buffer_size = 1024;
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, NULL, buffer_size, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_ECC_POINT_Marshal(&point, NULL, buffer_size, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);
}

/*
 * Invalid case with not big enough buffer
 */
static void
tpm2b_marshal_buffer_size_lt_data_nad_lt_offset(void **state) {
    TPM2B_DIGEST dgst = {4, {0}};
    TPM2B_ECC_POINT point = {sizeof(TPMS_ECC_POINT), {0}};
    size_t offset = 10;
    uint8_t buffer[sizeof(dgst) + sizeof(point)] = {0};
    size_t  buffer_size = sizeof(buffer);
    uint32_t value = 0xdeadbeef;
    uint64_t value2 = 0xdeadbeefdeadbeefULL;
    TSS2_RC rc;

    memcpy(dgst.buffer, &value, sizeof(value));
    memcpy(point.point.x.buffer, &value, sizeof(value));
    point.point.x.size = sizeof(value);
    memcpy(point.point.y.buffer, &value2, sizeof(value2));
    point.point.y.size = sizeof(value2);

    rc = Tss2_MU_TPM2B_DIGEST_Marshal(&dgst, buffer, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);

    rc = Tss2_MU_TPM2B_ECC_POINT_Marshal(&point, buffer, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}

/*
 * Unmarshal success case
 */
static void
tpm2b_unmarshal_success(void **state)
{
    TPM2B_DIGEST dgst = {0};
    TPM2B_ECC_POINT point = {0};
    size_t offset = 0;
    uint8_t buffer[] = { 0x00, 0x04, 0xef, 0xbe, 0xad, 0xde, /* digest of 4 bytes */
                         0x00, 0x0c, /* size of TPM2B_ECC_POINT */
                         0x00, 0x04, 0xef, 0xbe, 0xad, 0xde,   /* ECC_POINT.x - 4 bytes */
                         0x00, 0x04, 0x44, 0x33, 0x22, 0x11 }; /* ECC_POINT.y - 4 bytes */

    size_t buffer_size = sizeof(buffer);
    uint32_t value = 0xdeadbeef;
    uint32_t value2 = 0x11223344;
    uint32_t *ptr;
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(buffer, buffer_size, &offset, &dgst);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (dgst.size, 4);
    ptr = (uint32_t *)dgst.buffer;
    assert_int_equal (le32toh(*ptr), value);
    assert_int_equal (offset, 6);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal(buffer, buffer_size, &offset, &point);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (point.point.x.size, 4);
    ptr = (uint32_t *)point.point.x.buffer;
    assert_int_equal (le32toh(*ptr), value);
    assert_int_equal (point.point.y.size, 4);
    ptr = (uint32_t *)point.point.y.buffer;
    assert_int_equal (le32toh(*ptr), value2);
    assert_int_equal (offset, 20);
}

/*
 * Unmarshal success case with offset
 */
static void
tpm2b_unmarshal_success_offset(void **state)
{
    TPM2B_DIGEST dgst = {0};
    TPM2B_ECC_POINT point = {0};
    size_t offset = 6;
    uint8_t buffer[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* random 6 bytes offset */
                         0x00, 0x04, 0xef, 0xbe, 0xad, 0xde, /* digest of 4 bytes */
                         0x00, 0x10, /* size of TPM2B_ECC_POINT - 16 bytes */
                         0x00, 0x08, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,   /* ECC_POINT.x - 8 bytes */
                         0x00, 0x04, 0x44, 0x33, 0x22, 0x11 }; /* ECC_POINT.y - 4 bytes */

    size_t buffer_size = sizeof(buffer);
    uint32_t value = 0xdeadbeef;
    uint64_t value2 = 0xdeadbeefdeadbeefULL;
    uint32_t value3 = 0x11223344;
    uint32_t *ptr;
    uint64_t *ptr2;
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(buffer, buffer_size, &offset, &dgst);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (dgst.size, 4);
    ptr = (uint32_t *)dgst.buffer;
    assert_int_equal (le32toh(*ptr), value);
    assert_int_equal (offset, 12);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal(buffer, buffer_size, &offset, &point);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (point.point.x.size, 8);
    ptr2 = (uint64_t *)point.point.x.buffer;
    assert_int_equal (le64toh(*ptr2), value2);
    assert_int_equal (point.point.y.size, 4);
    ptr = (uint32_t *)point.point.y.buffer;
    assert_int_equal (le32toh(*ptr), value3);
    assert_int_equal (offset, 30);
}

/*
 * Test case ensures a NULL buffer parameter produces a BAD_REFERENCE RC.
 */
void
tpm2b_unmarshal_buffer_null (void **state)
{
    TPM2B_DIGEST dgst = {0};
    TPM2B_ECC_POINT point = {0};
    TSS2_RC rc;
    size_t offset = 0;

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal (NULL, 1, NULL, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal (NULL, 1, NULL, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal (NULL, 1, &offset, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal (NULL, 1, &offset, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal (NULL, 1, NULL, &dgst);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal (NULL, 1, NULL, &point);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);
}
/*
 * Test case ensures a NULL dest and offset parameters produce an
 * INSUFFICIENT_BUFFER RC.
 */
void
tpm2b_unmarshal_dest_null (void **state)
{
    uint8_t buffer [1];
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, sizeof (buffer), NULL, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal (buffer, 1, NULL, NULL);
    assert_int_equal (rc, TSS2_MU_RC_BAD_REFERENCE);
}

/*
 * Test case ensures the offset is updated when dest is NULL
 * and offset is valid
 */
void
tpm2b_unmarshal_dest_null_offset_valid (void **state)
{
    size_t  offset = 0;
    uint8_t buffer[] = { 0x00, 0x04, 0xef, 0xbe, 0xad, 0xde, /* digest of 4 bytes */
                             0x00, 0x10, /* size of TPM2B_ECC_POINT - 16 bytes */
                             0x00, 0x08, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,   /* ECC_POINT.x - 8 bytes */
                             0x00, 0x04, 0x44, 0x33, 0x22, 0x11 }; /* ECC_POINT.y - 4 bytes */
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, sizeof (buffer), &offset, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 6);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal (buffer, sizeof (buffer), &offset, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 24);
}

/*
 * Invalid case with not big enough buffer
 */
static void
tpm2b_unmarshal_buffer_size_lt_data_nad_lt_offset(void **state)
{
    TPM2B_DIGEST dgst = {4, {0x00, 0x01, 0x02, 0x03}};
    TPM2B_ECC_POINT point = {sizeof(TPMS_ECC_POINT), {0}};
    uint8_t buffer[sizeof(dgst) + sizeof(point)] = { 0 };
    size_t offset = sizeof(dgst) - 5;
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, 6, &offset, &dgst);
    assert_int_equal (rc, TSS2_MU_RC_INSUFFICIENT_BUFFER);
    assert_int_equal (offset, sizeof(dgst) - 5);

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal (buffer, 1, &offset, &point);
    assert_int_equal (rc, TSS2_MU_RC_INSUFFICIENT_BUFFER);
    assert_int_equal (offset, sizeof(dgst) - 5);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tpm2b_marshal_success),
        cmocka_unit_test(tpm2b_marshal_success_offset),
        cmocka_unit_test(tpm2b_marshal_buffer_null_with_offset),
        cmocka_unit_test(tpm2b_marshal_buffer_null_offset_null),
        cmocka_unit_test(tpm2b_marshal_buffer_size_lt_data_nad_lt_offset),
        cmocka_unit_test(tpm2b_unmarshal_success),
        cmocka_unit_test(tpm2b_unmarshal_success_offset),
        cmocka_unit_test(tpm2b_unmarshal_buffer_null),
        cmocka_unit_test(tpm2b_unmarshal_dest_null),
        cmocka_unit_test(tpm2b_unmarshal_dest_null_offset_valid),
        cmocka_unit_test(tpm2b_unmarshal_buffer_size_lt_data_nad_lt_offset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
