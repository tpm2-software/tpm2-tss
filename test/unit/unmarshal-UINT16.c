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
    uint16_t data_host;
    uint16_t data_net;
    TSS2_RC  rc;
} marshal_uint16_data_t;

void
unmarshal_UINT16_setup (void **state)
{
    marshal_uint16_data_t *data;

    data              = calloc (1, sizeof (marshal_uint16_data_t));
    data->buffer      = calloc (1, sizeof (uint16_t));
    data->buffer_size = sizeof (uint16_t);
    data->data_host   = 0xdead;
    data->data_net    = htons (data->data_host);
    data->rc          = TSS2_RC_SUCCESS;

    /**
     * copy test data into the buffer in network byte order, this is what we
     * will be unmarshalling
     */
    memcpy (data->buffer, &data->data_net, sizeof (data->data_net));

    *state = data;
}

void
unmarshal_UINT16_teardown (void **state)
{
    marshal_uint16_data_t *data;

    data = (marshal_uint16_data_t*)*state;
    if (data) {
        if (data->buffer)
            free (data->buffer);
        free (data);
    }
}
/**
 * Make a call to Unmarshal_UINT16 function that should succeed.
 * The *_setup function has already copied a UINT16 into a data buffer in
 * network byte order (marshalled form). This function uses the
 * Unmarshal_UINT16 function to get this UINT16 back out of the data buffer
 * and into the host by te order for comparison to the reference value
 * in the 'data_host' field of the marshal_uint16_data_t structure.
 */
void
unmarshal_UINT16_good (void **state)
{
    marshal_uint16_data_t *data;
    uint16_t               data_unmarshalled = 0;

    data = (marshal_uint16_data_t*)*state;
    uint8_t *nextData = data->buffer;

    Unmarshal_UINT16 (data->buffer,
                      data->buffer_size,
                      &nextData,
                      &data_unmarshalled,
                      &data->rc);
    /**
     * uint16_t that was unmarshalled from the data buffer should be equal to
     * the data_host member of the test data structure.
     */
    assert_int_equal (data_unmarshalled, data->data_host);
    /**
     * The Unmarshal_* functions advance the 'nextData' parameter by the size of
     * the marshalled data.
     */
    assert_int_equal (data->buffer, nextData - sizeof (uint16_t));
    /* Finally the return code should indicate success. */
    assert_int_equal (data->rc, TSS2_RC_SUCCESS);
}
int
main (void)
{
    const UnitTest tests [] = {
        unit_test_setup_teardown (unmarshal_UINT16_good,
                                  unmarshal_UINT16_setup,
                                  unmarshal_UINT16_teardown),
    };
    return run_tests (tests);
}
