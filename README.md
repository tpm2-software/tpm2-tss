[![Build Status](https://travis-ci.org/01org/TPM2.0-TSS.svg?branch=master)](https://travis-ci.org/01org/TPM2.0-TSS)

# WARNING: Resource Manager Deprecated
The current resource manager implementation in [$(srcdir)/resourcemgr/resourcemgr.c](https://github.com/01org/TPM2.0-TSS/blob/master/resourcemgr/resourcemgr.c) should be considered a prototype only.
It is not suitable for regular use as it has numerous threading issues and likely other latent bugs that can't be quantified without significant investment of time and resources.
As such we've decided to write a new implementation as a proper daemon using dbus and more modern development practices.
Patches fixing issues with the existing resource manager are welcome but this code will be removed as soon as the replacement is ready.

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
* Instructions to build and install TPM2.0-TSS are available in the [INSTALL](INSTALL) file.

## Test Instructions
This repository contains a test suite intended to exercise the TCTI and SAPI code.
This test suite is *not* intended to test the functions provided by a TPM implementation and so this test suite should only be run against a TPM simulator.
If this test suite is executed against the local TPM it may cause damage to the TPM (NV storage wear out etc).
You have been warned.

### Simulator
The TPM library specification contains reference code sufficient to construct a software TPM 2.0 simulator.
This code was provided by Microsoft and they provide a binary download for Windows [here](https://www.microsoft.com/en-us/download/details.aspx?id=52507).
IBM has repackaged this code with a few Makefiles so that the Microsoft code can be built and run on Linux systems.
The Linux version of the Microsoft TPM 2.0 simulator can be obtained [here](https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm532.tar).
Once you've downloaded and successfully built and execute the simulator it will, by default, be accepting connections on the localhost, port 2321.

Issues building or running the simulator should be reported to the IBM software TPM2 project.

NOTE: The Intel TCG TSS is currently tested against the 532 version of the simulator.
Compatibility with later versions has not yet been tested.

### Resource Manager
The current test suite implemented in the tpmclient program requires that the resource manager (resourcemgr) be running.
This is due to the test suite requiring session resources beyond those available in the TPM2 simulator.
The resource manager is thus required to "virtualize" the session resources.
For the resource manager to connect to the simulator the `-sim` option must be supplied as an option when executing it:

```
$ resourcemgr/resourcemgr -sim
```

### Test suite: TPM Client
The test suite is implemented in the tpmclient program.
This is a monolithic C program that exercises various TCTI and SAPI API calls.
Once the test environment is set up (simulator and resource manager are built and running), the tpmclient program can be executed:

```
$ test/tpmclient/tpmclient
```

The `tpmclient` program will run either until completion, or until an error occurs.
Please report failures in a Github 'issue' with a full log of the test run.
Thus must include output from the `resourcemgr` as well as the `tpmclient` program.
This output must include full debug messages which requires that the libraries and binaries be built with debug flags enabled.
See [INSTALL](INSTALL) for instructions.

## [Architecture/Block Diagram](doc/arch.md)

## [Code Layout](doc/layout.md)

## Resources
TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).
