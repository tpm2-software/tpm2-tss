# Clang/LLVM toolchain for Windows
# Usage: -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/clang.cmake

# Locate ml64.exe (MASM assembler) from MSVC installation
find_program(_ML64_PATH ml64
    PATHS
        "$ENV{VCToolsInstallDir}/bin/Hostx64/x64"
        "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/*/bin/Hostx64/x64"
        "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/*/bin/Hostx64/x64"
        "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64"
)
if(_ML64_PATH)
    set(CMAKE_ASM_MASM_COMPILER "${_ML64_PATH}")
else()
    set(CMAKE_ASM_MASM_COMPILER ml64.exe)
endif()

set(CMAKE_SYSTEM_NAME Windows)

# Find Clang from default LLVM install locations
find_program(CLANG_CL_PATH clang-cl
    PATHS
        "C:/Program Files/LLVM/bin"
        "C:/Program Files (x86)/LLVM/bin"
        "$ENV{LLVM_PATH}/bin"
)

if(CLANG_CL_PATH)
    set(CMAKE_C_COMPILER "${CLANG_CL_PATH}")
    set(CMAKE_CXX_COMPILER "${CLANG_CL_PATH}")
    # Use llvm-lib (MSVC-compatible archiver) instead of llvm-ar
    get_filename_component(_llvm_bin_dir "${CLANG_CL_PATH}" DIRECTORY)
    find_program(LLVM_LIB_PATH llvm-lib PATHS "${_llvm_bin_dir}" NO_DEFAULT_PATH)
    if(LLVM_LIB_PATH)
        set(CMAKE_AR "${LLVM_LIB_PATH}")
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

# Clang doesn't use /GR-, /bigobj, /arch: flags like MSVC
# Map common MSVC flags to Clang equivalents

# Clang compile flags (will be applied with COMPILE_LANGUAGE generator expressions in CMakeLists)
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