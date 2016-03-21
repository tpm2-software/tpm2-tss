#include <tcti/tcti_device.h>

/* Determine the size of a TCTI context structure. Requires calling the
 * initialization function for the device TCTI with the first parameter
 * (the TCTI context) NULL.
 */
size_t
tcti_dev_init_size (void **state)
{
    void *my_state = *state;
    size_t tcti_size = 0;
    TSS2_RC ret = TSS2_RC_SUCCESS;

    ret = InitDeviceTcti (NULL, &tcti_size, NULL, 0, 0, NULL);
    if (ret != TSS2_RC_SUCCESS)
        return 0;
    else
        return tcti_size;
}
