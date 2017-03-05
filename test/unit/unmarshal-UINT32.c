#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>
#include "sapi/tpm20.h"

#include "sys_api_marshalUnmarshal.h"
#include "sysapi_util.h"

typedef struct {
    uint8_t *buffer;
    size_t   buffer_size;
    uint32_t data_host;
    uint32_t data_net;
    TSS2_RC  rc;
} marshal_uint32_data_t;

void
unmarshal_UINT32_setup (void **state)
{
    marshal_uint32_data_t *data;

    data              = calloc (1, sizeof (marshal_uint32_data_t));
    data->buffer      = calloc (1, sizeof (uint32_t));
    data->buffer_size = sizeof (uint32_t);
    data->data_host   = 0xdeadbeef;
    data->data_net    = htonl (data->data_host);
    data->rc          = TSS2_RC_SUCCESS;

    /**
     * copy test data into the buffer in network byte order, this is what we
     * will be unmarshalling
     */
    memcpy (data->buffer, &data->data_net, sizeof (data->data_net));

    *state = data;
}

void
unmarshal_UINT32_teardown (void **state)
{
    marshal_uint32_data_t *data;

    data = (marshal_uint32_data_t*)*state;
    if (data) {
        if (data->buffer)
            free (data->buffer);
        free (data);
    }
}
/**
 * Make a call to Unmarshal_UINT32 function that should succeed. The *_setup
 * function is expected to have allocated sufficient buffer to hold a
 * uint32_t. This test just 'unmarshals' a known uint32_t from this data
 * buffer and then compares the value to the expected result.
 */
void
unmarshal_UINT32_good (void **state)
{
    marshal_uint32_data_t *data;
    uint32_t               data_unmarshalled = 0;

    data = (marshal_uint32_data_t*)*state;
    uint8_t *nextData = data->buffer;

    Unmarshal_UINT32 (data->buffer,
                      data->buffer_size,
                      &nextData,
                      &data_unmarshalled,
                      &data->rc);
    /**
     * uint32_t that was marshalled into the data buffer should be equal to
     * the expected value (data converted from host byte order to network
     * byte order).
     */
    assert_int_equal (data_unmarshalled, data->data_host);
    /**
     * The Marshal_* functions advance the 'nextData' parameter by the size of
     * the marshalled data.
     */
    assert_int_equal (data->buffer, nextData - sizeof (uint32_t));
    /* Finally the return code should indicate success. */
    assert_int_equal (data->rc, TSS2_RC_SUCCESS);
}
int
main (void)
{
    const UnitTest tests [] = {
        unit_test_setup_teardown (unmarshal_UINT32_good,
                                  unmarshal_UINT32_setup,
                                  unmarshal_UINT32_teardown),
    };
    return run_tests (tests);
}
