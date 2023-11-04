cmake_minimum_required(VERSION 3.10)

set(TJWT_VERSION 0.1)

project(TJWT
    VERSION ${TJWT_VERSION}
    DESCRIPTION "JWT Validator"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(libtjwt)
add_subdirectory(test)
