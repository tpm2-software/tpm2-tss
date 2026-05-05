file(GLOB RC_SRC *.c)
add_library(tss2-rc ${RC_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/log.c)
set_target_properties(tss2-rc PROPERTIES OUTPUT_NAME "tss2-rc")
target_compile_definitions(tss2-rc PUBLIC libtss2_rc_EXPORTS)
if(MSVC OR WIN32)
	target_link_options(tss2-rc PRIVATE "/DEF:${CMAKE_SOURCE_DIR}/lib/tss2-rc.def")
endif()
set_target_properties(tss2-rc PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C,CXX>:$<$<CONFIG:Debug>:/MTd>$<$<CONFIG:Release>:/MT>>"
)
target_include_directories(tss2-rc PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/../../include
	${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
	${CMAKE_CURRENT_SOURCE_DIR}/../../util
	${CMAKE_CURRENT_SOURCE_DIR}/..
)
