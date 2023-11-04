cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(tjwt-test
	VERSION ${TJWT_VERSION}
	DESCRIPTION "JWT Test Utility"
)

add_executable( ${PROJECT_NAME}
	src/jwttest.c
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE inc
)

target_link_libraries( ${PROJECT_NAME}
	tjwt
    tjson
    ssl
    crypto
)

set_target_properties( ${PROJECT_NAME}
		       PROPERTIES OUTPUT_NAME jwttest
)

target_compile_options( ${PROJECT_NAME}
	PRIVATE
	-Wall
	-Wextra
	-Wpedantic
	-Werror
)

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
