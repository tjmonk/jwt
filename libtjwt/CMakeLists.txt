cmake_minimum_required(VERSION 3.10)

project(tjwt
	VERSION ${TJWT_VERSION}
	DESCRIPTION "TJWT Library"
)

include(GNUInstallDirs)

find_package(OpenSSL REQUIRED)

set(TJWT_SOURCES )
list(APPEND TJWT_SOURCES src/tjwt.c)

if( ${OPENSSL_VERSION} VERSION_LESS 3 )
	message("Using OpenSSL 1.x")
	list(APPEND TJWT_SOURCES src/ssl1.c)
else()
	message("Using OpenSSL 3.x")
	list(APPEND TJWT_SOURCES src/ssl3.c)
endif()


add_library( ${PROJECT_NAME} SHARED
	${TJWT_SOURCES}
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

