# SPDX-FileCopyrightText: 2026 Ahmed Samy
# SPDX-License-Identifier: BSD-2-Clause

# Clang/LLVM toolchain for Windows
# Usage: -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/clang.cmake

# Use vswhere to find the VS installation path without hardcoding version/edition
find_program(_VSWHERE vswhere
    PATHS "C:/Program Files (x86)/Microsoft Visual Studio/Installer"
    NO_DEFAULT_PATH
)
if(_VSWHERE)
    execute_process(
        COMMAND "${_VSWHERE}" -latest -property installationPath
        OUTPUT_VARIABLE _VS_INSTALL_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    file(GLOB _MSVC_TOOL_DIRS "${_VS_INSTALL_PATH}/VC/Tools/MSVC/*/bin/Hostx64/x64")
endif()

# Locate the MASM assembler: ml64.exe for x64/default, ml.exe for x86
if(VCPKG_TARGET_TRIPLET MATCHES "^x86-")
    file(GLOB _MSVC_TOOL_DIRS_X86
        "${_VS_INSTALL_PATH}/VC/Tools/MSVC/*/bin/Hostx64/x86")
    find_program(_ML_PATH ml
        HINTS
            "$ENV{VCToolsInstallDir}/bin/Hostx64/x86"
            ${_MSVC_TOOL_DIRS_X86}
    )
    if(_ML_PATH)
        set(CMAKE_ASM_MASM_COMPILER "${_ML_PATH}")
    else()
        set(CMAKE_ASM_MASM_COMPILER ml.exe)
    endif()
else()
    find_program(_ML64_PATH ml64
        HINTS
            "$ENV{VCToolsInstallDir}/bin/Hostx64/x64"
            ${_MSVC_TOOL_DIRS}
    )
    if(_ML64_PATH)
        set(CMAKE_ASM_MASM_COMPILER "${_ML64_PATH}")
    else()
        set(CMAKE_ASM_MASM_COMPILER ml64.exe)
    endif()
endif()

set(CMAKE_SYSTEM_NAME Windows)

# Find Clang - bundled with VS (preferred) or standalone LLVM install
find_program(CLANG_CL_PATH clang-cl
    HINTS
        "${_VS_INSTALL_PATH}/VC/Tools/Llvm/x64/bin"
        "$ENV{VCToolsInstallDir}/../../Llvm/x64/bin"
    PATHS
        "C:/Program Files/LLVM/bin"
        "C:/Program Files (x86)/LLVM/bin"
        "$ENV{LLVM_PATH}/bin"
)

if(VCPKG_TARGET_TRIPLET MATCHES "^x86-")
    set(_CLANG_TARGET "--target=i686-pc-windows-msvc")
elseif(VCPKG_TARGET_TRIPLET MATCHES "^arm64-")
    set(_CLANG_TARGET "--target=aarch64-pc-windows-msvc")
elseif(VCPKG_TARGET_TRIPLET MATCHES "^arm-")
    set(_CLANG_TARGET "--target=armv7-pc-windows-msvc")
endif()

if(_CLANG_TARGET STREQUAL "--target=i686-pc-windows-msvc")
    foreach(_env_var IN ITEMS LIB LIBPATH)
        set(_val "$ENV{${_env_var}}")
        if(_val)
            string(REPLACE "\\x64" "\\x86" _val "${_val}")
            string(REPLACE "/x64"  "/x86"  _val "${_val}")
            set(ENV{${_env_var}} "${_val}")
        endif()
    endforeach()
endif()

if(CLANG_CL_PATH)
    set(CMAKE_C_COMPILER "${CLANG_CL_PATH}")
    set(CMAKE_CXX_COMPILER "${CLANG_CL_PATH}")
    if(_CLANG_TARGET)
        set(CMAKE_C_FLAGS_INIT   "${_CLANG_TARGET}")
        set(CMAKE_CXX_FLAGS_INIT "${_CLANG_TARGET}")
    endif()
    get_filename_component(_llvm_bin_dir "${CLANG_CL_PATH}" DIRECTORY)
    find_program(LLVM_LIB_PATH llvm-lib PATHS "${_llvm_bin_dir}" NO_DEFAULT_PATH)
    if(LLVM_LIB_PATH)
        set(CMAKE_AR "${LLVM_LIB_PATH}")
    endif()
    find_program(LLD_LINK_PATH lld-link PATHS "${_llvm_bin_dir}" NO_DEFAULT_PATH)
    if(LLD_LINK_PATH)
        set(CMAKE_LINKER "${LLD_LINK_PATH}")
        set(_lld_base_flags "/INCREMENTAL:NO /MANIFEST:EMBED")

        if(_CLANG_TARGET STREQUAL "--target=i686-pc-windows-msvc" AND _VS_INSTALL_PATH)
            file(GLOB _msvc_x86_dirs "${_VS_INSTALL_PATH}/VC/Tools/MSVC/*/lib/x86")
            list(SORT _msvc_x86_dirs ORDER DESCENDING)
            if(_msvc_x86_dirs)
                list(GET _msvc_x86_dirs 0 _msvc_x86_lib)
                cmake_path(NATIVE_PATH _msvc_x86_lib _msvc_x86_lib)
                string(APPEND _lld_base_flags " /LIBPATH:\"${_msvc_x86_lib}\"")
            endif()

            cmake_host_system_information(RESULT _winsdk_root
                QUERY WINDOWS_REGISTRY
                "HKLM/SOFTWARE/Microsoft/Windows Kits/Installed Roots"
                VALUE "KitsRoot10")
            string(REGEX REPLACE "[/\\\\]$" "" _winsdk_root "${_winsdk_root}")
            foreach(_sdk_sub IN ITEMS ucrt um)
                file(GLOB _sdk_sub_dirs "${_winsdk_root}/Lib/*/${_sdk_sub}/x86")
                list(SORT _sdk_sub_dirs ORDER DESCENDING)
                if(_sdk_sub_dirs)
                    list(GET _sdk_sub_dirs 0 _sdk_sub_lib)
                    cmake_path(NATIVE_PATH _sdk_sub_lib _sdk_sub_lib)
                    string(APPEND _lld_base_flags " /LIBPATH:\"${_sdk_sub_lib}\"")
                endif()
            endforeach()
        endif()

        set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_lld_base_flags}")
        set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_lld_base_flags}")
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG    "/DEBUG" CACHE STRING "" FORCE)
        set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/DEBUG" CACHE STRING "" FORCE)
    endif()
else()
    set(CMAKE_C_COMPILER clang-cl)
    set(CMAKE_CXX_COMPILER clang-cl)
endif()

# Tell CMake that clang-cl uses MSVC-style standard flags
set(CMAKE_CXX_COMPILER_FRONTEND_VARIANT "MSVC")
set(CMAKE_C_COMPILER_FRONTEND_VARIANT "MSVC")

# Override CMake's default debug flags: clang-cl doesn't accept -O0, use /Od
set(CMAKE_C_FLAGS_DEBUG "/Od /Zi" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi" CACHE STRING "" FORCE)

set(CMAKE_CXX_STANDARD 23 CACHE STRING "")
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "")

# Override the standard compile option so CMake passes /std:c++latest
set(CMAKE_CXX23_STANDARD_COMPILE_OPTION "/std:c++latest")
set(CMAKE_CXX23_EXTENSION_COMPILE_OPTION "/std:c++latest")

set(CLANG_FLAGS_COMMON
    -fno-rtti
    -Wno-c99-designator
    -Wno-invalid-noreturn
)

set(CLANG_FLAGS_DEBUG -g /Od)
set(CLANG_FLAGS_RELEASE -O2)
set(CLANG_FLAGS_AVX2 -mavx2)
set(CLANG_FLAGS_SSE2 -msse2)

# For WDK/kernel targets, Clang may need Windows SDK includes
if(DEFINED WDK_INCLUDE_DIRS)
    message(STATUS "Clang: Using WDK includes from toolchain")
endif()

# Clang/LLVM info
execute_process(
    COMMAND "${CMAKE_CXX_COMPILER}" --version
    OUTPUT_VARIABLE CLANG_VERSION_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "Clang version: ${CLANG_VERSION_OUTPUT}")