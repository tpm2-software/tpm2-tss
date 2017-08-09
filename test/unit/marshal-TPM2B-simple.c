#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tpm20.h"
#include "sys_api_marshalUnmarshal.h"
#include "sysapi_util.h"

typedef struct {
    uint8_t     *buffer;
    size_t       buffer_size;
    TSS2_RC      rc;
} marshal_simple2b_t;

/* This is the structure we will marshal */
TPM2B_NAME name2b = {
    .t = {
        .size = 0x16,
        .name = {
            0x00, 0x04, 0x5d, 0x12, 0x1e, 0xd0, 0xf7, 0x4e,
            0x82, 0xa8, 0x5d, 0xe7, 0x43, 0x93, 0x9b, 0x2e,
            0xb4, 0x96, 0xe7, 0x70, 0x8e, 0x38,
        }
    }
};
/* This is what the name2b should look like fully marshalled */
uint8_t name2b_marshalled[] = {
    0x00, 0x16, 0x00, 0x04, 0x5d, 0x12, 0x1e, 0xd0,
    0xf7, 0x4e, 0x82, 0xa8, 0x5d, 0xe7, 0x43, 0x93,
    0x9b, 0x2e, 0xb4, 0x96, 0xe7, 0x70, 0x8e, 0x38,
};
size_t marshalled_size = sizeof (name2b_marshalled);

static int
marshal_TPM2B_NAME_setup (void **state)
{
    marshal_simple2b_t *data;

    data              = calloc (1, sizeof (marshal_simple2b_t));
    data->buffer_size = sizeof (TPM2B_NAME);
    data->buffer      = calloc (1, data->buffer_size);
    data->rc          = TSS2_RC_SUCCESS;

    *state = data;
    return 0;
}

static int
marshal_TPM2B_NAME_teardown (void **state)
{
    marshal_simple2b_t *data;

    data = (marshal_simple2b_t*)*state;
    if (data) {
        if (data->buffer)
            free (data->buffer);
        free (data);
    }
    return 0;
}
/**
 * Make a call to Marshal_UINT16 function that should succeed. The *_setup
 * function is expected to have allocated sufficient buffer to hold a
 * uint16_t. This test just 'marshals' a known uint16_t into this data buffer
 * and then compares the value to the expected result.
 * The workings of the Marshal_UINT16 function is a bit complex, so we
 * assert the expected results as well.
 */
static void
marshal_TPM2B_NAME_good (void **state)
{
    marshal_simple2b_t *data;
    /**
     * This is what the above TPM2B_NAME should look like when marshalled.
     * Interestingly enough the only thing that changes by order is the size
     * field. The 'name' field is marshalled as a byte buffer so endianness
     * doesn't change.
     */
    data = (marshal_simple2b_t*)*state;
    uint8_t *nextData = data->buffer;

    Marshal_Simple_TPM2B (data->buffer,
                          data->buffer_size,
                          &nextData,
                          (TPM2B*)&name2b,
                          &data->rc);
    /**
     * uint16_t that was marshalled into the data buffer should be equal to
     * the expected value (data converted from host byte order to network
     * byte order).
     */
    assert_memory_equal (data->buffer, name2b_marshalled, marshalled_size);
    /**
     * The Marshal_* functions advance the 'nextData' parameter by the size of
     * the marshalled data.
     */
    assert_int_equal (data->buffer, nextData - marshalled_size);
    /* Finally the return code should indicate success. */
    assert_int_equal (data->rc, TSS2_RC_SUCCESS);
}
static void
unmarshal_TPM2B_NAME_good (void **state)
{
    /**
     * rc must be initialized to success or the unmarshal function will do
     * nothing.
     */
    TSS2_RC rc = TSS2_RC_SUCCESS;
    TPM2B_NAME name2b_unmarshal = { .b = {0}, };
    /**
     * Unmarshal_Simple_TPM2B compares the size field in the destination
     * structure to the size indicated by the marshalled data in the buffer
     * that's being unmarshalled. So we must set the size to the maximum size
     * possible.
     */
    name2b_unmarshal.t.size = sizeof (name2b_unmarshal.t.name);

    uint8_t *nextData = name2b_marshalled;

    Unmarshal_Simple_TPM2B (name2b_marshalled,
                            marshalled_size,
                            &nextData,
                            &name2b_unmarshal.b,
                            &rc);
    /* The return code should indicate success */
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    /* The size of the unmarshalled structure should match the reference */
    assert_int_equal (name2b_unmarshal.t.size, name2b.t.size);
    /* the contents of the name buffer should match the reference */
    assert_memory_equal (name2b_unmarshal.t.name, name2b.t.name, name2b.t.size);
}
int
main (void)
{
    const struct CMUnitTest tests [] = {
        cmocka_unit_test_setup_teardown (marshal_TPM2B_NAME_good,
                                  marshal_TPM2B_NAME_setup,
                                  marshal_TPM2B_NAME_teardown),
        cmocka_unit_test (unmarshal_TPM2B_NAME_good),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
