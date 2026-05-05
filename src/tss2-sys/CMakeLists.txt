file(GLOB SYSAPI_SRC api/*.c)
add_library(tss2-sys ${SYSAPI_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/log.c)
target_compile_definitions(tss2-sys PUBLIC libtss2_sys_EXPORTS)
set_target_properties(tss2-sys PROPERTIES OUTPUT_NAME "tss2-sys")
if(MSVC OR WIN32)
	target_link_options(tss2-sys PRIVATE "/DEF:${CMAKE_SOURCE_DIR}/lib/tss2-sys.def")
endif()
target_include_directories(tss2-sys PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/../../include
	${CMAKE_CURRENT_SOURCE_DIR}/../../include/tss2
	${CMAKE_CURRENT_SOURCE_DIR}/../../util
	${CMAKE_CURRENT_SOURCE_DIR}/..
	${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(tss2-sys PUBLIC tss2-mu)
