# I2C TCTI Helper

The I2C TCTI helper can be used for TPM communication over I2C e.g. in embedded systems.
It uses user supplied methods for I2C and timing operations in order to be platform independent.
These methods are supplied to `Tss2_Tcti_I2c_Helper_Init` via the `TSS2_TCTI_I2C_HELPER_PLATFORM` struct.

## Platform methods

Documentation detailing the implementation of platform methods can be found in `tss2_tcti_i2c_helper.h`.
For an example implementation that uses the I2C TCTI helper to communicate with an I2C-based TPM over the
FTDI MPSSE USB to I2C bridge, refer to the `tcti-i2c-ftdi` module.