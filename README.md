[![Build Status](https://travis-ci.org/01org/TPM2.0-TSS.svg?branch=master)](https://travis-ci.org/01org/TPM2.0-TSS)
[![Coverity Scan](https://img.shields.io/coverity/scan/3997.svg)](https://scan.coverity.com/projects/tpm2-tss)

## TPM (Trusted Platform Module) 2.0 Software Stack (TSS):

This stack consists of the following layers from top to bottom:
* _Feature API (FAPI), see [specification 0.12](http://www.trustedcomputinggroup.org/resources/tss_feature_api_specification), (published but still in progress and unimplemented)_
* _Enhanced System API (ESAPI), (specification in progress and unimplemented)_
* System API (SAPI), see [1.0 specification](http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification), (public, 0.97 implementation complete). This layer implements the system layer API level of the TSS 2.0 specification.   These functions can be used to access all TPM 2.0 functions as described in Part 3 of the TPM 2.0 specification.  The usefulness of this code extends to all users of the TPM, even those not planning to use the upper layers of the TSS.
* TPM Command Transmission Interface (TCTI), used by SAPI to communicate with next lower layer (either the TAB/RM or TPM 2.0 device driver), see [SAPI specification](http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification)
* Trusted Access Broker/Resource Manager (TAB/RM), see [0.91 specification](http://www.trustedcomputinggroup.org/resources/tss_tab_and_resource_manager), (public, implementation complete).  This layer sits between the system API library code and the TPM.  It is a daemon that handles all multi-process coordination and manages the TPM's internal resources transparently to applications.

Since the FAPI and ESAPI haven't been implemented yet, this repository only contains the SAPI and layers below it, plus a test application for exercising the SAPI.

The test application, tpmclient, tests many of the commands against the TPM 2.0 simulator.  The tpmclient application can be altered and used as a sandbox to test and develop any TPM 2.0 command sequences, and provides an excellent development and learning vehicle.

## Build and Installation Instructions:

* [Build and test the TPM 2.0 simulator](doc/simulator.md)
* Build and install TPM2.0-TSS for Linux: see [INSTALL](INSTALL)
* [Build TPM2.0-TSS for Windows](doc/buildwindows.md)

## [Run Instructions](doc/run.md)

## [Architecture/Block Diagram](doc/arch.md)

## [Code Layout](doc/layout.md)

## Resources
TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).
