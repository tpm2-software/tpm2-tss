[![Linux Build Status](https://travis-ci.org/tpm2-software/tpm2-tss.svg?branch=master)](https://travis-ci.org/tpm2-software/tpm2-tss)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/2rdmyn1ndkiavngn?svg=true)](https://ci.appveyor.com/project/tpm2-software/tpm2-tss)
[![Coverity Scan](https://img.shields.io/coverity/scan/3997.svg)](https://scan.coverity.com/projects/tpm2-tss)
[![Coverage Status](https://coveralls.io/repos/github/01org/tpm2-tss/badge.svg?branch=master)](https://coveralls.io/github/01org/tpm2-tss?branch=master)

# Overview
This repository hosts source code implementing the Trusted Computing Group's (TCG) TPM2 Software Stack (TSS).
This stack consists of the following layers from top to bottom:

* Enhanded System API (ESAPI) as described in the  [TSS 2.0 Enhanced System API (ESAPI) Specification](https://trustedcomputinggroup.org/wp-content/uploads/TSS_ESAPI_Version-0.9_Revision-04_reviewEND030918.pdf).
This API is a 1-to-1 mapping of the TPM2 commands documented in Part 3 of the TPM2 specification.
Additionally there are asynchronous versions of each command.
In addition to SAPI, the ESAPI performs tracking of meta data for TPM object and automatic calculation of session based authorization and encryption values.
Both the synchronous and asynchronous API are exposed through a single library: libesapi.
* System API (SAPI) as described in the  [system level API and TPM command transmission interface specification](http://www.trustedcomputinggroup.org/resources/tss_system_level_api_and_tpm_command_transmission_interface_specification).
This API is a 1-to-1 mapping of the TPM2 commands documented in Part 3 of the TPM2 specification.
Additionally there are asynchronous versions of each command.
These asynchronous variants may be useful for integration into event-driven programming environments.
Both the synchronous and asynchronous API are exposed through a single library: libsapi.
* TPM Command Transmission Interface (TCTI) that is described in the same specification.
This API provides a standard interface to transmit / receive TPM command / response buffers.
It is expected that any number of libraries implementing the TCTI API will be implemented as a way to abstract various platform specific IPC mechanisms.
Currently this repository provides two TCTI implementations: libtcti-device and libtcti-socket.
The prior should be used for direct access to the TPM through the Linux kernel driver.
The later implements the protocol exposed by the Microsoft software TPM2 simulator.

# Build and Installation Instructions:
Instructions to build and install tpm2-tss are available in the [INSTALL](INSTALL.md) file.

# Getting in Touch:
If you're looking to discuss the source code in this project or get some questions answered you should join the 01org TPM2 mailing list: https://lists.01.org/mailman/listinfo/tpm2.
We've also got an IRC channel set up on [FreeNode](https://freenode.net/) called #tpm2.0-tss.

# Test Suite
This repository contains a test suite intended to exercise the TCTI, SAPI and ESAPI code.
This test suite is *not* intended to test a TPM implementation and so this test suite should only be run against a TPM simulator.
If this test suite is executed against a TPM other than the software simulator it may cause damage to the TPM (NV storage wear out etc).
You have been warned.

## Simulator
The TPM library specification contains reference code sufficient to construct a software TPM 2.0 simulator.
This code was provided by Microsoft and they provide a binary download for Windows [here](https://www.microsoft.com/en-us/download/details.aspx?id=52507).
IBM has repackaged this code with a few Makefiles so that the Microsoft code can be built and run on Linux systems.
The Linux version of the Microsoft TPM 2.0 simulator can be obtained [here](https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm974.tar.gz).
Once you've downloaded and successfully built and execute the simulator it will, by default, be accepting connections on the localhost, port 2321.

Issues building or running the simulator should be reported to the IBM software TPM2 project.

NOTE: The Intel TCG TSS is currently tested against the 974 version of the simulator.
Compatibility with later versions has not yet been tested.

## Testing
To test the various TCTI, SAPI and ESAPI api calls, unit and integraion tests can
be run by configuring the build to enable unit testing and running the "check"
build target. It is recommended to use a simulator for testing, and the
simulator will be automatically launched by the tests. Please review the
dependency list in [INSTALL](INSTALL.md) for dependencies when building
the test suite.
```
$ ./configure --enable-unit --with-simulatorbin=$HOME/ibmtpm/src/tpm_server
$ make -j$(nproc) check
```
This will generate a file called "test-suite.log" in the root of the build
directory.

Please report failures in a Github 'issue' with a full log of the test run.

NOTE: The unit and integration tests can be enabled independently.
The --enable-unit option controls uint tests, and --with-simulatorbin controls
the integration test.

# [Architecture/Block Diagram](doc/arch.md)
SAPI library, TAB/RM, and Test Code Block Diagram:
![Architecture Block Diagram](doc/TSS%20block%20diagram.png)

# Project Layout
├── common  : utility functions used by multiple components  
├── doc     : various bits of documentation  
├── esapi   : system API implementation  
│   ├── esapi       : enhanced system API implementation  
│   └── esapi_util  : utility functions used by ESAPI implementation  
├── include : header files unstalled in $(includedir)  
│   ├── esapi       : header file for ESAPI library  
│   ├── sapi        : header files for TPM2 types and core libraries  
│   └── tcti        : header files for TCTI libraries  
├── lib     : data files used by the build or installed into $(libdir)  
├── log     : logging functions  
├── m4      : autoconf support macros  
├── man     : man pages  
├── marshal : TPM2 type marshalling library implementation  
├── script  : scripts used by the build or CI  
├── sysapi  : system API implementation  
│   ├── include     : headers internal to the SAPI  
│   ├── sysapi      : system API implementation  
│   └── sysapi_util : utility functions used by system API implementation  
├── tcti    : TCTI implementation  
└── test    : test code  
    ├── integration : integration test harness and test cases  
    ├── tpmclient   : monolithic, legacy test application  
    └── unit        : unit tests  
