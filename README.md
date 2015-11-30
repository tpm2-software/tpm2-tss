## TPM (Trusted Platform Module) 2.0 Software Stack (TSS):

This stack consists of the following layers from top to bottom:
* _Feature API (FAPI), see [specification 0.12](http://www.trustedcomputinggroup.org/resources/tss_feature_api_specification), (published but still in progress and unimplemented)_
* _Enhanced System API (ESAPI), (specification in progress and unimplemented)_
* System API (SAPI), see [1.0 specification](http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification), (public, 0.97 implementation complete)
* TPM Command Transmission Interface (TCTI), used by SAPI to communicate with next lower layer (either the TAB/RM or TPM 2.0 device driver), see [SAPI specification](http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification)
* Trusted Access Broker/Resource Manager (TAB/RM), see [0.91 specification](http://www.trustedcomputinggroup.org/resources/tss_tab_and_resource_manager), (public, implementation complete)

Since the FAPI and ESAPI haven't been implemented yet, this repository only contains the SAPI and layers below it, plus a test application for exercising the SAPI.

**For more details on this code and how to install and use it, the [Readme.pdf](https://github.com/01org/TPM2.0-TSS/blob/master/Readme.pdf) file is a good place to start.**

## Build and Installation instructions:
Instructions for building and installing the TPM2.0-TSS are provided in the [INSTALL](https://github.com/01org/TPM2.0-TSS/blob/master/INSTALL) file.

## Resources
TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).
