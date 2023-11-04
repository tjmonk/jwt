cmake_minimum_required(VERSION 3.10)

project(tjwt
	VERSION ${TJWT_VERSION}
	DESCRIPTION "TJWT Library"
)

include(GNUInstallDirs)

add_library( ${PROJECT_NAME} SHARED
	src/tjwt.c
)

set_target_properties( ${PROJECT_NAME} PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
)

set(TJWT_HEADERS inc/tjwt/tjwt.h)

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${TJWT_HEADERS}")

target_compile_options( ${PROJECT_NAME}
	PRIVATE
	-Wall
	-Wextra
	-Wpedantic
	-Werror
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE
		.
	PUBLIC
		inc
)

target_link_libraries( ${PROJECT_NAME}
	PRIVATE
		tjson
        ssl
        crypto
)

install(TARGETS ${PROJECT_NAME}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tjwt)

