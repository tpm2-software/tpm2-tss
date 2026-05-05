file(GLOB MU_SRC *.c)
add_library(tss2-mu ${MU_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/log.c)
target_compile_definitions(tss2-mu PUBLIC libtss2_mu_EXPORTS)
set_target_properties(tss2-mu PROPERTIES OUTPUT_NAME "tss2-mu")
if(MSVC OR WIN32)
	target_link_options(tss2-mu PRIVATE "/DEF:${CMAKE_SOURCE_DIR}/lib/tss2-mu.def")
endif()
set_target_properties(tss2-mu PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C,CXX>:$<$<CONFIG:Debug>:/MTd>$<$<CONFIG:Release>:/MT>>"
)
target_include_directories(tss2-mu PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/../../include
	${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
	${CMAKE_CURRENT_SOURCE_DIR}/../../util
	${CMAKE_CURRENT_SOURCE_DIR}/..
)
