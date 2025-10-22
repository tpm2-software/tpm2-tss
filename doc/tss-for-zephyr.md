# TSS for Zephyr Example with Remote TPM
## Compiling the TSS for Zephyr in QEMU and connect to Hostside TPM Simulator with Remote TCTI


This example shows how to compile the TSS for an application running in [Zephyr RTOS](https://zephyrproject.org/).
The app is executed on QEMU and uses the remote TCTI to connect to a hostside Software TPM.

## Building the TSS

### 1. Adding TSS and mbedTLS to the Zephyr project

To integrate the TSS for Zephyr, the following files needs to be adjusted.

#### west.yml

```yaml
manifest:
    remotes:
        [...]
        - name: tpm2-software
            url-base: https://github.com/tpm2-software

    projects:
        [...]
        - name: tpm2-tss
          remote: tpm2-software
          revision: master
          path: my_zephyr_app/lib/tpm2-tss

        - name: mbedtls
          remote: zephyrproject-rtos
          revision: v3.0.0
          path: modules/crypto/mbedtls
```

#### prj.conf

```yaml
[...]
# Enable Basic POSIX and socket support
CONFIG_STATIC_INIT_GNU=y # TSS requires GNU-style constructors
CONFIG_POSIX_API=y # Needed by TSS for "open, read, write, lseek, close"
CONFIG_FILE_SYSTEM=y # Needed by TSS for "open, read, write, lseek, close"

# Enable MBEDTLS Crypto Library
CONFIG_MBEDTLS=y
CONFIG_MBEDTLS_BUILTIN=y
CONFIG_APP_LINK_WITH_MBEDTLS=y

# Add minimal networking configuration
CONFIG_MAIN_STACK_SIZE=5000
CONFIG_NETWORKING=y
CONFIG_NET_IPV4=y
CONFIG_NET_TCP=y

CONFIG_PCIE=y
CONFIG_NET_L2_ETHERNET=y
CONFIG_NET_QEMU_ETHERNET=y
CONFIG_NET_CONFIG_SETTINGS=y
CONFIG_NET_CONFIG_MY_IPV4_ADDR="192.0.2.1"
CONFIG_NET_CONFIG_PEER_IPV4_ADDR="192.0.2.2"

[...]
```

#### CMakeLists.txt

Follow Zephyr instruction steps for including an [external library](
https://docs.zephyrproject.org/latest/samples/application_development/external_lib/README.html).

```cmake
[...]
## 1. Including external static libraries

# The external static library that we are linking with does not know
# how to build for this platform so we export all the flags used in
# this zephyr build to the external build system.
#
# Other external build systems may be self-contained enough that they
# do not need any build information from zephyr. Or they may be
# incompatible with certain zephyr options and need them to be
# filtered out.
zephyr_get_include_directories_for_lang_as_string(       C includes)
zephyr_get_system_include_directories_for_lang_as_string(C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(       C definitions)
zephyr_get_compile_options_for_lang_as_string(           C options)

if(DEFINED CMAKE_C_COMPILER_TARGET)
  set(target_flag "--target=${CMAKE_C_COMPILER_TARGET}")
endif()

set(external_project_cflags
  "${target_flag} ${includes} ${definitions} ${options} ${system_includes}"
  )

include(ExternalProject)

### 1. External Project: TSS

# Add an external project to be able download and build the third
# party library. In this case downloading is not necessary as it has
# been committed to the repository.
set(mylib_src_dir_tss   ${CMAKE_CURRENT_SOURCE_DIR}/lib/tpm2-tss)
set(mylib_build_dir_tss ${CMAKE_CURRENT_BINARY_DIR}/lib/tpm2-tss)


set(MYLIB_INCLUDE_DIR_TSS ${mylib_src_dir_tss}/include)

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
# https://www.gnu.org/software/make/manual/html_node/MAKE-Variable.html
set(submake "$(MAKE)")
else() # Obviously no MAKEFLAGS. Let's hope a "make" can be found somewhere.
set(submake "make")
endif()

set(mylib_cflags "-I${CMAKE_CURRENT_SOURCE_DIR}/../modules/crypto/mbedtls/include")

set(mylib_config_str
"./bootstrap" && "./configure" "--host=x86_64" "--with-crypto=mbed" "--enable-nodl" "--disable-tcti-cmd" "--disable-tcti-device" "--disable-tcti-spidev"  "--disable-tcti-swtpm" "--disable-tcti-pcap" "--disable-tcti-spi-ftdi" "--disable-tcti-spi-ltt2go" "--disable-tcti-i2c-ftdi" "--disable-tcti-libtpms" "--disable-fapi" "--disable-policy"
)

set(mylib_cflags "${external_project_cflags} ${mylib_cflags}")

set(mylib_cmakeargs "-DCMAKE_INCLUDE_PATH=${CMAKE_SOURCE_DIR}../modules/crypto/mbedtls_build/include" "-DCMAKE_LIBRARY_PATH=${CMAKE_SOURCE_DIR}../modules/crypto/mbedtls_build/library")

ExternalProject_Add(
  libtss2       # Name for custom target
  PREFIX     ${mylib_build_dir_tss} # Root dir for entire project
  SOURCE_DIR ${mylib_src_dir_tss}
  BINARY_DIR ${mylib_src_dir_tss} # This particular build system is invoked from the root
  CONFIGURE_COMMAND ${mylib_config_str}
  BUILD_COMMAND
  ${submake}
  PREFIX=${mylib_build_dir_tss}
  CC=${CMAKE_C_COMPILER}
  AR=${CMAKE_AR}
  CFLAGS=${mylib_cflags}
  CMAKE_ARGS ${mylib_cmakeargs}
  UPDATE_COMMAND "" # Skip updates for every build
  INSTALL_COMMAND "" # This particular build system has no install command
  BUILD_BYPRODUCTS ${mylib_src_dir_tss}/src/tss2-sys/.libs/libtss2-sys.a ${mylib_src_dir_tss}/src/tss2-esys/.libs/libtss2-esys.a ${mylib_src_dir_tss}/src/tss2-mu/.libs/libtss2-mu.a ${mylib_src_dir_tss}/src/tss2-tcti/.libs/libtss2-tcti-mssim.a ${mylib_src_dir_tss}/src/tss2-tcti/.libs/libtss2-tctildr.a
)

add_library(libtss2-mu STATIC IMPORTED GLOBAL)
set_target_properties(libtss2-mu PROPERTIES IMPORTED_LOCATION             ${mylib_src_dir_tss}/src/tss2-mu/.libs/libtss2-mu.a)
set_target_properties(libtss2-mu PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${MYLIB_INCLUDE_DIR_TSS})

add_library(libtss2-sys STATIC IMPORTED GLOBAL)
set_target_properties(libtss2-sys PROPERTIES IMPORTED_LOCATION             ${mylib_src_dir_tss}/src/tss2-sys/.libs/libtss2-sys.a)
set_target_properties(libtss2-sys PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${MYLIB_INCLUDE_DIR_TSS})

add_library(libtss2-esys STATIC IMPORTED GLOBAL)
set_target_properties(libtss2-esys PROPERTIES IMPORTED_LOCATION             ${mylib_src_dir_tss}/src/tss2-esys/.libs/libtss2-esys.a)
set_target_properties(libtss2-esys PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${MYLIB_INCLUDE_DIR_TSS})

add_library(libtss2-tcti-mssim STATIC IMPORTED GLOBAL)
set_target_properties(libtss2-tcti-mssim PROPERTIES IMPORTED_LOCATION             ${mylib_src_dir_tss}/src/tss2-tcti/.libs/libtss2-tcti-mssim.a)
set_target_properties(libtss2-tcti-mssim PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${MYLIB_INCLUDE_DIR_TSS})

add_library(libtss2-tctildr STATIC IMPORTED GLOBAL)
set_target_properties(libtss2-tctildr PROPERTIES IMPORTED_LOCATION             ${mylib_src_dir_tss}/src/tss2-tcti/.libs/libtss2-tctildr.a)
set_target_properties(libtss2-tctildr PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${MYLIB_INCLUDE_DIR_TSS})

add_dependencies(
  libtss2-mu
  libtss2-sys
  libtss2-esys
  libtss2-tctildr
  libtss2-tcti-mssim
  libtss2
)
target_link_libraries(app PUBLIC libtss2-esys libtss2-sys libtss2-tctildr libtss2-tcti-mssim libtss2-mu)
[...]
```

#### main.c

Example additions to use the TSS library in main.c.

```c
[...]
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

char *tcti_name = "mssim:host=192.0.2.2,port=2321";
[...]

int main(void){
    [...]
    int rc = 0;

    /* Initialize variables for context.*/
    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    rc = Tss2_TctiLdr_Initialize(tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS){
        printf("Error: Tss2_TctiLdr_Initialize\n");
        return 1;
    }
    printf("Tss2_TctiLdr_Initialize\n");

    rc = Esys_Initialize(&ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error: Esys_Initialize\n");
        return 1;
    }
    printf("Esys_Initialize\n");

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error: Esys_Startup\n");
        return 1;
    }
    printf("Esys_Startup\n");

    TPM2B_DIGEST *randomBytes;
    UINT16 requested = 12;
    rc = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, requested, &randomBytes);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error: Esys_GetRandom\n");
        return 1;
    }
    printf("Esys_GetRandom\n");

    printf("Random: ");
    for(int i=0; i<randomBytes->size; i++){
      printf("%02x", randomBytes->buffer[i]);
    }
    printf("\n");

    Tss2_TctiLdr_Finalize(&tcti_ctx);
    printf("Tss2_TctiLdr_Finalize\n");

    Esys_Finalize(&ctx);
    printf("Esys_Finalize\n");

    return rc;
}
```

### 2. Compile the MbedTLS library as standalone

Follow Zephyr instruction steps for [compiling MBedTLS with cmake](https://github.com/zephyrproject-rtos/mbedtls?tab=readme-ov-file#cmake).

```console
mkdir /path/to/build_dir && cd /path/to/build_dir
cmake /path/to/mbedtls_source
cmake --build .
```

### 3. Build the project (in this case for Qemu)

```console
west build -p always -b qemu_x86 my_zephyr_app
```

## Running the application

### Step 1 (Terminal 1)

For connecting QEMU to the host follow the [Networking with QEMU Ethernet guide](https://docs.zephyrproject.org/latest/connectivity/networking/qemu_eth_setup.html#networking-with-eth-qemu).


```console
user@tss:/# /home/zephyrproject/tools/net-tools/net-setup.sh
Using ./zeth.conf configuration file.
Creating zeth
```

### Step 2 (Terminal 2)

Next, the Software TPM (e.g., [ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref)) needs to be started (Terminal 2).

```console
user@tss:/# /home/ms-tpm-20-ref/TPMCmd/Simulator/src/tpm2-simulator
Crypto implementation information:
  Symmetric:   OpenSSL (3.0.2)
  Hashing:     OpenSSL (3.0.2)
  Math:        TPMBigNum/OpenSSL (3.0.2)
LIBRARY_COMPATIBILITY_CHECK is ON
Platform server listening on port 2322
TPM command server listening on port 2321
```

### Step 3 (Terminal 3)

Finally, the Zephyr QEMU application can be started.

```console
(.venv) user@tss:/home/user# west build -t run
```


#### Example Output

```console
(.venv) user@tss:/home/user# west build -t run
-- west build: running target run
[0/1] To exit from QEMU enter: 'CTRL+a, x'[QEMU] CPU: qemu32,+nx,+pae
SeaBIOS (version zephyr-v1.0.0-0-g31d4e0e-dirty-20200714_234759-fv-az50-zephyr)


iPXE (http://ipxe.org) 00:02.0 CA00 PCI2.10 PnP PMM+01F92120+01EF2120 CA00


Booting from ROM..

*** Booting Zephyr OS build v4.0.0-3808-gc057f91eb56f ***
[00:00:00.030,000] <inf> net_config: Initializing network
[00:00:00.030,000] <inf> net_config: IPv4 address: 192.0.2.1
[00:00:00.140,000] <inf> net_config: IPv6 address: 2001:db8::1
[00:00:00.140,000] <inf> net_config: IPv6 address: 2001:db8::1
uart:~$ Tss2_TctiLdr_Initialize
Esys_Initialize
Esys_Startup
Esys_GetRandom
Random: 03e61dfcf7d1a8d8af18a93d
Tss2_TctiLdr_Finalize
Esys_Finalize
```
# License

This work is licensed under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
