This file contains instructions to build and install the TSS libraries.

# Dependencies
To build and install the tpm2-tss software the following software packages
are required. In many cases dependencies are platform specific and so the
following sections describe them for the supported platforms.

## GNU/Linux:
* GNU Autoconf
* GNU Autoconf archive
* GNU Automake
* GNU Libtool
* C compiler
* C Library Development Libraries and Header Files
* pkg-config
* uriparser
* libgcrypt

The following are dependencies only required when building the test suite.
Most users will not need to install these dependencies:
* cmocka unit test framework

### Ubuntu
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
  liburiparser-dev \
  libgcrypt20-dev \
  autoconf
```

### Fedora

There is a package already, so the package build dependencies information can be
used to make sure that the needed packages to compile from source are installed:

```
$ sudo dnf builddep tpm2-tss
```

## Windows
Windows dlls built using the Clang/LLVM "Platform Toolset" are currently
prototypes. We have only tested using Visual Studio 2017 with the Universal
C Runtime (UCRT) version 10.0.16299.0. Building the type marshalling library
(tss2-mu.dll) and the system API (tss2-sapi.dll) should be as simple as
loading the tpm2-tss solution (tpm2-tss.sln) with a compatible and properly
configured version of Visual Studio 2017 and pressing the 'build' button.

### References
Visual Studio 2017 with "Clang for Windows": https://blogs.msdn.microsoft.com/vcblog/2017/03/07/use-any-c-compiler-with-visual-studio/
Universal CRT overview & setup instructions: https://docs.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt

# Building From Source
## Bootstrapping the Build
To configure the tpm2-tss source code first run the bootstrap script, which
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
Once you've built the tpm2-tss software it can be installed with:
```
$ sudo make install
```

This will install the libraries to a location determined at configure time.
See the output of ./configure --help for the available options. Typically you
won't need to do much more than provide an alternative --prefix option at
configure time, and maybe DESTDIR at install time if you're packaging for a
distro.

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
$ docker cp temp:/tpm2-tss tpm2-tss
$ docker rm temp
```

tpm2-tss is now in your working directory and contains all the built files.
