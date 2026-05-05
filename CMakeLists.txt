cmake_minimum_required(VERSION 3.10)
project(tpm2-tss LANGUAGES C)

set(CMAKE_C_STANDARD 17 CACHE STRING "")
set(CMAKE_C_STANDARD_REQUIRED ON CACHE BOOL "")

set(VCPKG_TARGET_ARCHITECTURE x64)
if(BUILD_SHARED_LIBS)
	set(VCPKG_TARGET_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet for dynamic build" FORCE)
	set(VCPKG_LIBRARY_LINKAGE dynamic)
	set(VCPKG_CRT_LINKAGE dynamic)

	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
else()
	set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "vcpkg triplet for static build" FORCE)
	set(VCPKG_LIBRARY_LINKAGE static)
	set(VCPKG_CRT_LINKAGE static)

	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_compile_definitions(
	$<$<CONFIG:Debug>:_DEBUG>
	_WINDOWS
	_USRDLL
	MAXLOGLEVEL=$<$<CONFIG:Debug>:6>$<$<NOT:$<CONFIG:Debug>>:3>
	strtok_r=strtok_s
)

option(BUILD_TSS2_MU "Build tss2-mu library" ON)
option(BUILD_TSS2_RC "Build tss2-rc library" ON)
option(BUILD_TSS2_SYS "Build tss2-sys library" OFF)
option(BUILD_TSS2_ESYS "Build tss2-esys library" OFF)
option(BUILD_TSS2_TCTI "Build tss2-tcti library" OFF)
option(BUILD_ALL "Build all tss2 libraries" ON)
if(BUILD_ALL)
	set(BUILD_TSS2_MU ON)
	set(BUILD_TSS2_RC ON)
	set(BUILD_TSS2_SYS ON)
	set(BUILD_TSS2_ESYS ON)
	set(BUILD_TSS2_TCTI ON)
endif()

if(BUILD_TSS2_RC)
	add_subdirectory(src/tss2-rc)
endif()
if(BUILD_TSS2_MU)
	add_subdirectory(src/tss2-mu)
endif()
if(BUILD_TSS2_SYS)
	add_subdirectory(src/tss2-sys)
endif()
if(BUILD_TSS2_ESYS)
	add_subdirectory(src/tss2-esys)
endif()
if(BUILD_TSS2_TCTI)
	add_subdirectory(src/tss2-tcti)
endif()
