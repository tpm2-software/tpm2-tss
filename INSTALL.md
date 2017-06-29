This file contains instructions to build and install the TSS libraries.

# Dependencies
To build and install the tpm2.0-tss software the following dependencies are
required:
* GNU Autoconf
* GNU Autoconf archive
* GNU Automake
* GNU Libtool
* C compiler
* C Library Development Libraries and Header Files
* pkg-config

The following are dependencies only required when building the test suite.
Most users will not need to install these dependencies:
* cmocka unit test framework

## Ubuntu
```
$ sudo apt -y update
$ sudo apt -y install \
  autoconf-archive \
  libcmocka0 \
  libcmocka-dev \
  build-essential \
  git \
  pkg-config \
  gcc \
  g++ \
  m4 \
  libtool \
  automake \
  autoconf
```

# Building From Source
## Bootstrapping the Build
To configure the tpm2.0-tss source code first run the bootstrap script, which
generates list of source files, and creates the configure script:
```
$ ./bootstrap
```

## Configuring the Build
Then run the configure script, which generates the makefiles:
```
$ ./configure
```

## Compiling the Libraries
Then compile the code using make:
```
$ make -j$(nproc)
```

## Installing the Libraries
Once you've built the tpm2.0-tss software it can be installed with:
```
$ sudo make install
```

This will install the libraries and the resource manager to locations
determined at configure time. See the output of ./configure --help for the
available options. Typically you won't need to do much more than provide an
alternative --prefix option at configure time, and maybe DESTDIR at install
time if you're packaging for a distro.

**NOTE**: It may be necessary to run ldconfig (as root) to update the run-time
bindings before executing a program that links against libsapi or a TCTI
library:
```
$ sudo ldconfig
```

## Building In A Container

If you are having trouble installing the dependencies on your machine you can
build in a container.

```
$ docker build -t tpm2 .
$ docker run --name temp tpm2 /bin/true
$ docker cp temp:/TPM2.0-TSS TPM2.0-TSS
$ docker rm temp
```

TPM2.0-TSS is now in your working directory and contains all the built files.
