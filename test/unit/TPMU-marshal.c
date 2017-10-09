#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <sapi/tss2_mu.h>
#include <marshal/tss2_endian.h>

/*
 * Success case
 */
static void
tpmu_marshal_success(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig)] = { 0 };
    size_t  buffer_size = sizeof(buffer);
    TPMS_SIGNATURE_ECDSA *ptr;
    TPM2B_ECC_PARAMETER *ptr2;
    TSS2_RC rc;

    memset(ha.sha512, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Marshal(&ha, TPM_ALG_SHA512, buffer, buffer_size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (memcmp(buffer, ha.sha512, SHA512_DIGEST_SIZE), 0);

    sig.ecdsa.hash = TPM_ALG_SHA1;
    sig.ecdsa.signatureR.t.size = 4;
    sig.ecdsa.signatureR.t.buffer[0] = 'a';
    sig.ecdsa.signatureR.t.buffer[1] = 'b';
    sig.ecdsa.signatureR.t.buffer[2] = 'c';
    sig.ecdsa.signatureR.t.buffer[3] = 'd';
    sig.ecdsa.signatureS.t.size = 4;
    sig.ecdsa.signatureS.t.buffer[0] = 'e';
    sig.ecdsa.signatureS.t.buffer[1] = 'd';
    sig.ecdsa.signatureS.t.buffer[2] = 'f';
    sig.ecdsa.signatureS.t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&sig, TPM_ALG_ECDSA, buffer, buffer_size, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    ptr = (TPMS_SIGNATURE_ECDSA *) buffer;
    assert_int_equal (ptr->hash, HOST_TO_BE_16(TPM_ALG_SHA1));
    assert_int_equal (ptr->signatureR.t.size, HOST_TO_BE_16(4));
    assert_int_equal (ptr->signatureR.t.buffer[0], 'a');
    assert_int_equal (ptr->signatureR.t.buffer[1], 'b');
    assert_int_equal (ptr->signatureR.t.buffer[2], 'c');
    assert_int_equal (ptr->signatureR.t.buffer[3], 'd');
    ptr2 = (TPM2B_ECC_PARAMETER *) (buffer + 8);
    assert_int_equal (ptr2->t.size, HOST_TO_BE_16(4));
    assert_int_equal (ptr2->t.buffer[0], 'e');
    assert_int_equal (ptr2->t.buffer[1], 'd');
    assert_int_equal (ptr2->t.buffer[2], 'f');
    assert_int_equal (ptr2->t.buffer[3], 'g');

}
/*
 * Success case with a valid offset
 */
static void
tpmu_marshal_success_offset(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig) + 10] = { 0 };
    size_t  buffer_size = sizeof(buffer);
    TPMS_SIGNATURE_ECDSA *ptr;
    TPM2B_ECC_PARAMETER *ptr2;
    size_t offset = 10;
    TSS2_RC rc;

    memset(ha.sha512, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Marshal(&ha, TPM_ALG_SHA512, buffer, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (memcmp(buffer + 10, ha.sha512, SHA512_DIGEST_SIZE), 0);
    assert_int_equal (offset, 10 + SHA512_DIGEST_SIZE);

    sig.ecdsa.hash = TPM_ALG_SHA1;
    sig.ecdsa.signatureR.t.size = 4;
    sig.ecdsa.signatureR.t.buffer[0] = 'a';
    sig.ecdsa.signatureR.t.buffer[1] = 'b';
    sig.ecdsa.signatureR.t.buffer[2] = 'c';
    sig.ecdsa.signatureR.t.buffer[3] = 'd';
    sig.ecdsa.signatureS.t.size = 4;
    sig.ecdsa.signatureS.t.buffer[0] = 'e';
    sig.ecdsa.signatureS.t.buffer[1] = 'd';
    sig.ecdsa.signatureS.t.buffer[2] = 'f';
    sig.ecdsa.signatureS.t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&sig, TPM_ALG_ECDSA, buffer, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    ptr = (TPMS_SIGNATURE_ECDSA *) (buffer + 10 + SHA512_DIGEST_SIZE);
    assert_int_equal (ptr->hash, HOST_TO_BE_16(TPM_ALG_SHA1));
    assert_int_equal (ptr->signatureR.t.size, HOST_TO_BE_16(4));
    assert_int_equal (ptr->signatureR.t.buffer[0], 'a');
    assert_int_equal (ptr->signatureR.t.buffer[1], 'b');
    assert_int_equal (ptr->signatureR.t.buffer[2], 'c');
    assert_int_equal (ptr->signatureR.t.buffer[3], 'd');
    ptr2 = (TPM2B_ECC_PARAMETER *) (buffer + 10 + SHA512_DIGEST_SIZE + 8);
    assert_int_equal (ptr2->t.size, HOST_TO_BE_16(4));
    assert_int_equal (ptr2->t.buffer[0], 'e');
    assert_int_equal (ptr2->t.buffer[1], 'd');
    assert_int_equal (ptr2->t.buffer[2], 'f');
    assert_int_equal (ptr2->t.buffer[3], 'g');
    assert_int_equal (offset, 10 + SHA512_DIGEST_SIZE + 2 + ((2 + 1 + 1 + 1 + 1) * 2));
}

/*
 * Success case with a null buffer
 */
static void
tpmu_marshal_buffer_null_with_offset(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig) + 10] = { 0 };
    size_t  buffer_size = sizeof(buffer);
    size_t offset = 10;
    TSS2_RC rc;

    memset(ha.sha512, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Marshal(&ha, TPM_ALG_SHA512, NULL, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 10 + SHA512_DIGEST_SIZE);

    sig.ecdsa.hash = TPM_ALG_SHA1;
    sig.ecdsa.signatureR.t.size = 4;
    sig.ecdsa.signatureR.t.buffer[0] = 'a';
    sig.ecdsa.signatureR.t.buffer[1] = 'b';
    sig.ecdsa.signatureR.t.buffer[2] = 'c';
    sig.ecdsa.signatureR.t.buffer[3] = 'd';
    sig.ecdsa.signatureS.t.size = 4;
    sig.ecdsa.signatureS.t.buffer[0] = 'e';
    sig.ecdsa.signatureS.t.buffer[1] = 'd';
    sig.ecdsa.signatureS.t.buffer[2] = 'f';
    sig.ecdsa.signatureS.t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&sig, TPM_ALG_ECDSA, NULL, buffer_size, &offset);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 10 + SHA512_DIGEST_SIZE + 2 + ((2 + 1 + 1 + 1 + 1) * 2));
}

/*
 * Invalid case with a null buffer and a null offset
 */
static void
tpmu_marshal_buffer_null_offset_null(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    TSS2_RC rc;

    rc = Tss2_MU_TPMU_HA_Marshal(&ha, TPM_ALG_SHA512, NULL, sizeof(ha), NULL);
    assert_int_equal (rc, TSS2_TYPES_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&sig, TPM_ALG_ECDSA, NULL, sizeof(sig), NULL);
    assert_int_equal (rc, TSS2_TYPES_RC_BAD_REFERENCE);
}

/*
 * Invalid case with not big enough buffer
 */
static void
tpmu_marshal_buffer_size_lt_data_nad_lt_offset(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig) + 10] = { 0 };
    size_t offset = 10;
    TSS2_RC rc;

    memset(ha.sha512, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Marshal(&ha, TPM_ALG_SHA512, buffer, SHA512_DIGEST_SIZE - 1, &offset);
    assert_int_equal (rc, TSS2_TYPES_RC_INSUFFICIENT_BUFFER);
    assert_int_equal (offset, 10);

    sig.ecdsa.hash = TPM_ALG_SHA1;
    sig.ecdsa.signatureR.t.size = 4;
    sig.ecdsa.signatureR.t.buffer[0] = 'a';
    sig.ecdsa.signatureR.t.buffer[1] = 'b';
    sig.ecdsa.signatureR.t.buffer[2] = 'c';
    sig.ecdsa.signatureR.t.buffer[3] = 'd';
    sig.ecdsa.signatureS.t.size = 4;
    sig.ecdsa.signatureS.t.buffer[0] = 'e';
    sig.ecdsa.signatureS.t.buffer[1] = 'd';
    sig.ecdsa.signatureS.t.buffer[2] = 'f';
    sig.ecdsa.signatureS.t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&sig, TPM_ALG_ECDSA, buffer, 12, &offset);
    assert_int_equal (rc, TSS2_TYPES_RC_INSUFFICIENT_BUFFER);
    assert_int_equal (offset, 10);
}

/*
 * Success case
 */
static void
tpmu_unmarshal_success(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig)] = { 0 };
    size_t  buffer_size = sizeof(buffer);
    TPMS_SIGNATURE_ECDSA *ptr;
    TPM2B_ECC_PARAMETER *ptr2;
    size_t offset = 0;
    TSS2_RC rc;

    memset(buffer, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Unmarshal(buffer, buffer_size, &offset, TPM_ALG_SHA512, &ha);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, SHA512_DIGEST_SIZE);
    assert_int_equal (memcmp(buffer, ha.sha512, SHA512_DIGEST_SIZE), 0);

    offset = 0;
    ptr = (TPMS_SIGNATURE_ECDSA *) buffer;
    ptr2 = (TPM2B_ECC_PARAMETER *) (buffer + 8);
    ptr->hash = HOST_TO_BE_16(TPM_ALG_SHA1);
    ptr->signatureR.t.size = HOST_TO_BE_16(4);
    ptr->signatureR.t.buffer[0] = 'a';
    ptr->signatureR.t.buffer[1] = 'b';
    ptr->signatureR.t.buffer[2] = 'c';
    ptr->signatureR.t.buffer[3] = 'd';
    ptr2->t.size = HOST_TO_BE_16(4);
    ptr2->t.buffer[0] = 'e';
    ptr2->t.buffer[1] = 'd';
    ptr2->t.buffer[2] = 'f';
    ptr2->t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buffer, buffer_size, &offset, TPM_ALG_ECDSA, &sig);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 14);
    assert_int_equal (sig.ecdsa.hash, TPM_ALG_SHA1);
    assert_int_equal (sig.ecdsa.signatureR.t.size, 4);
    assert_int_equal (sig.ecdsa.signatureR.t.buffer[0], 'a');
    assert_int_equal (sig.ecdsa.signatureR.t.buffer[1], 'b');
    assert_int_equal (sig.ecdsa.signatureR.t.buffer[2], 'c');
    assert_int_equal (sig.ecdsa.signatureR.t.buffer[3], 'd');
    assert_int_equal (sig.ecdsa.signatureS.t.size, 4);
    assert_int_equal (sig.ecdsa.signatureS.t.buffer[0], 'e');
    assert_int_equal (sig.ecdsa.signatureS.t.buffer[1], 'd');
    assert_int_equal (sig.ecdsa.signatureS.t.buffer[2], 'f');
    assert_int_equal (sig.ecdsa.signatureS.t.buffer[3], 'g');
}

/*
 * Invalid test case with buffer null and dest null
 */
static void
tpmu_unmarshal_dest_null_buff_null(void **state)
{
    size_t offset = 1;
    TSS2_RC rc;

    rc = Tss2_MU_TPMU_HA_Unmarshal(NULL, SHA512_DIGEST_SIZE, &offset, TPM_ALG_SHA512, NULL);
    assert_int_equal (rc, TSS2_TYPES_RC_BAD_REFERENCE);
    assert_int_equal (offset, 1);

    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(NULL, 32, &offset, TPM_ALG_ECDSA, NULL);
    assert_int_equal (rc, TSS2_TYPES_RC_BAD_REFERENCE);
    assert_int_equal (offset, 1);
}

/*
 * Invalid test case with offset null and dest null
 */
static void
tpmu_unmarshal_buffer_null_offset_null(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig)] = { 0 };
    size_t  buffer_size = sizeof(buffer);
    TSS2_RC rc;

    rc = Tss2_MU_TPMU_HA_Unmarshal(buffer, buffer_size, NULL, TPM_ALG_SHA512, NULL);
    assert_int_equal (rc, TSS2_TYPES_RC_BAD_REFERENCE);

    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buffer, buffer_size, NULL, TPM_ALG_ECDSA, NULL);
    assert_int_equal (rc, TSS2_TYPES_RC_BAD_REFERENCE);
}

/*
 * Test case ensures the offset is updated when dest is NULL
 * and offset is valid
 */
static void
tpmu_unmarshal_dest_null_offset_valid(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig)] = { 0 };
    size_t  buffer_size = sizeof(buffer);
    TPMS_SIGNATURE_ECDSA *ptr;
    TPM2B_ECC_PARAMETER *ptr2;
    size_t offset = 0;
    TSS2_RC rc;

    memset(buffer, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Unmarshal(buffer, buffer_size, &offset, TPM_ALG_SHA512, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, SHA512_DIGEST_SIZE);

    offset = 0;
    ptr = (TPMS_SIGNATURE_ECDSA *) buffer;
    ptr2 = (TPM2B_ECC_PARAMETER *) (buffer + 8);
    ptr->hash = HOST_TO_BE_16(TPM_ALG_SHA1);
    ptr->signatureR.t.size = HOST_TO_BE_16(4);
    ptr->signatureR.t.buffer[0] = 'a';
    ptr->signatureR.t.buffer[1] = 'b';
    ptr->signatureR.t.buffer[2] = 'c';
    ptr->signatureR.t.buffer[3] = 'd';
    ptr2->t.size = HOST_TO_BE_16(4);
    ptr2->t.buffer[0] = 'e';
    ptr2->t.buffer[1] = 'd';
    ptr2->t.buffer[2] = 'f';
    ptr2->t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buffer, buffer_size, &offset, TPM_ALG_ECDSA, NULL);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (offset, 14);
}

/*
 * Invalid case with not big enough buffer. Make sure offest is untouched.
 */
static void
tpmu_unmarshal_buffer_size_lt_data_nad_lt_offset(void **state)
{
    TPMU_HA ha = {0};
    TPMU_SIGNATURE sig = {0};
    uint8_t buffer[sizeof(ha) + sizeof(sig)] = { 0 };
    TPMS_SIGNATURE_ECDSA *ptr;
    TPM2B_ECC_PARAMETER *ptr2;
    size_t offset = 5;
    TSS2_RC rc;

    memset(buffer, 'a', SHA512_DIGEST_SIZE);
    rc = Tss2_MU_TPMU_HA_Unmarshal(buffer, SHA512_DIGEST_SIZE - 1, &offset, TPM_ALG_SHA512, &ha);
    assert_int_equal (rc, TSS2_TYPES_RC_INSUFFICIENT_BUFFER);
    assert_int_equal (offset, 5);

    ptr = (TPMS_SIGNATURE_ECDSA *) buffer;
    ptr2 = (TPM2B_ECC_PARAMETER *) (buffer + 8);
    ptr->hash = HOST_TO_BE_16(TPM_ALG_SHA1);
    ptr->signatureR.t.size = HOST_TO_BE_16(4);
    ptr->signatureR.t.buffer[0] = 'a';
    ptr->signatureR.t.buffer[1] = 'b';
    ptr->signatureR.t.buffer[2] = 'c';
    ptr->signatureR.t.buffer[3] = 'd';
    ptr2->t.size = HOST_TO_BE_16(4);
    ptr2->t.buffer[0] = 'e';
    ptr2->t.buffer[1] = 'd';
    ptr2->t.buffer[2] = 'f';
    ptr2->t.buffer[3] = 'g';

    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buffer, 14, &offset, TPM_ALG_ECDSA, &sig);
    assert_int_equal (rc, TSS2_TYPES_RC_INSUFFICIENT_BUFFER);
    assert_int_equal (offset, 5);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tpmu_marshal_success),
        cmocka_unit_test (tpmu_marshal_success_offset),
        cmocka_unit_test (tpmu_marshal_buffer_null_with_offset),
        cmocka_unit_test (tpmu_marshal_buffer_null_offset_null),
        cmocka_unit_test (tpmu_marshal_buffer_size_lt_data_nad_lt_offset),
        cmocka_unit_test (tpmu_unmarshal_success),
        cmocka_unit_test (tpmu_unmarshal_dest_null_buff_null),
        cmocka_unit_test (tpmu_unmarshal_buffer_null_offset_null),
        cmocka_unit_test (tpmu_unmarshal_dest_null_offset_valid),
        cmocka_unit_test (tpmu_unmarshal_buffer_size_lt_data_nad_lt_offset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
