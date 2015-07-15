**This site contains the code for the TPM (Trusted Platform Module) 2.0 Software Stack (TSS).**

This stack consists of the following layers from top to bottom:
* _Feature API (FAPI):  [specification 0.12 published](http://www.trustedcomputinggroup.org/resources/tss_feature_api_specification) but still in progress and unimplemented_
* _Enhanced System API (ESAPI):  specification in progress and unimplemented_
* System API (SAPI) [1.0 specification public] (http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification), 0.97 implementation complete
* TPM Command Transmission Interface (TCTI):  Used by SAPI to communicate with next lower layer (either the TAB/RM or TPM 2.0 device driver) see [SAPI specification]((http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification)
* Trusted Access Broker/Resource Manager (TAB/RM):  [0.91 specification](http://www.trustedcomputinggroup.org/resources/tss_tab_and_resource_manager) public, implementation complete
* TCTI:  this send TCTI layer is used to communicate with the TPM 2.0 driver.

Since the FAPI and ESAPI haven't been implemented yet, this repository only contains the SAPI and layers below it, plus a test application for excercising the SAPI.

**For more details on this code and how to install and use it, the [Readme.pdf](https://github.com/01org/TPM2.0-TSS/blob/master/systemApi/Readme.pdf) file is a good place to start.**

**For release details, review the [TPM 2.0 library release notes.pdf](https://github.com/01org/TPM2.0-TSS/blob/master/systemApi/TPM%202.0%20library%20release%20notes.pdf) document.**

**TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).**
