cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(jwt
    VERSION ${TJWT_VERSION}
    DESCRIPTION "JWT Decoder/Validator"
)

set(CMAKE_BUILD_TYPE Debug)

add_executable( ${PROJECT_NAME}
    src/jwt.c
)

target_include_directories( ${PROJECT_NAME}
    PRIVATE ../libtjwt/inc
    PRIVATE .
)

target_link_libraries( ${PROJECT_NAME}
    ssl
    crypto
    tjwt
)

set_target_properties( ${PROJECT_NAME}
    PROPERTIES
    OUTPUT_NAME jwt
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
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
