find_package(OpenSSL REQUIRED)

# Allow exclusion list via variable or command line (semicolon-separated)
set(ESYS_EXCLUDE "esys_crypto_mbed.c;${ESYS_EXCLUDE}" CACHE STRING "Files to exclude from esys sources (semicolon-separated)")

file(GLOB ESYS_SRC *.c api/*.c)

if(ESYS_EXCLUDE)
    foreach(_src ${ESYS_EXCLUDE})
        foreach(_file ${ESYS_SRC})
            get_filename_component(_file_name "${_file}" NAME)
            if(_file_name STREQUAL "${_src}")
                list(REMOVE_ITEM ESYS_SRC "${_file}")
            endif()
        endforeach()
    endforeach()
endif()

add_library(tss2-esys ${ESYS_SRC})

target_include_directories(tss2-esys PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/../../include
	${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
	${CMAKE_CURRENT_SOURCE_DIR}/../../util
	${CMAKE_CURRENT_SOURCE_DIR}/..
	${CMAKE_CURRENT_SOURCE_DIR}
)
set_target_properties(tss2-esys PROPERTIES
	COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C,CXX>:$<$<CONFIG:Debug>:/MTd>$<$<CONFIG:Release>:/MT>>"
)
target_compile_definitions(tss2-esys PUBLIC TSS2ESYS_EXPORTS OSSL)
target_link_libraries(tss2-esys PUBLIC tss2-sys tss2-mu OpenSSL::Crypto)
