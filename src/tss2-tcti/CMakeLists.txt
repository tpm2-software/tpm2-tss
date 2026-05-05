# tss2-tcti-mssim
add_library(tss2-tcti-mssim
    tcti-mssim.c
    tcti-common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util-io/io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/key-value-parse.c
)
target_include_directories(tss2-tcti-mssim PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(tss2-tcti-mssim PUBLIC tss2-mu ws2_32)
set_target_properties(tss2-tcti-mssim PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C,CXX>:$<$<CONFIG:Debug>:/MTd>$<$<CONFIG:Release>:/MT>>"
    OUTPUT_NAME "tss2-tcti-mssim"
)
if(MSVC OR WIN32)
    target_link_options(tss2-tcti-mssim PRIVATE "/DEF:${CMAKE_SOURCE_DIR}/lib/tss2-tcti-mssim.def")
endif()
target_compile_definitions(tss2-tcti-mssim PUBLIC _WINSOCKAPI_ TSS2TCTIMSSIM_EXPORTS)

# tss2-tcti-tbs
add_library(tss2-tcti-tbs
    tcti-tbs.c
    tcti-common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/log.c
)
target_include_directories(tss2-tcti-tbs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(tss2-tcti-tbs PUBLIC tss2-mu Tbs)
set_target_properties(tss2-tcti-tbs PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C,CXX>:$<$<CONFIG:Debug>:/MTd>$<$<CONFIG:Release>:/MT>>"
    OUTPUT_NAME "tss2-tcti-tbs"
)
if(MSVC OR WIN32)
    target_link_options(tss2-tcti-tbs PRIVATE "/DEF:${CMAKE_SOURCE_DIR}/lib/tss2-tcti-tbs.def")
endif()

# tss2-tctildr
add_library(tss2-tctildr
    tctildr.c
    tctildr-nodl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/log.c
)
target_include_directories(tss2-tctildr PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(tss2-tctildr PUBLIC tss2-mu)
set_target_properties(tss2-tctildr PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C,CXX>:$<$<CONFIG:Debug>:/MTd>$<$<CONFIG:Release>:/MT>>"
    OUTPUT_NAME "tss2-tctildr"
)
if(MSVC OR WIN32)
    target_link_options(tss2-tctildr PRIVATE "/DEF:${CMAKE_SOURCE_DIR}/lib/tss2-tctildr.def")
endif()
