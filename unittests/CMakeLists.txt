#
# MIT License
#
# Copyright (c) 2019 Maarten Hoeben
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
cmake_minimum_required(VERSION 3.1)

#
# Project
#
project("hserv-unittests")

#
# Dependencies
#
find_package(OpenSSL REQUIRED)

#
# Executable
#
add_executable(${PROJECT_NAME}
    src/main.c

    src/test_harray.c
    src/test_hbuffer.c
    src/test_hfs.c
    src/test_hhash_map.c
    src/test_hlist.c
    src/test_hserv.c
    src/test_hws.c
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    C_STANDARD 99
)

target_compile_options(${PROJECT_NAME} PRIVATE
    -Werror
    -Wall
    -Wextra
    -Wstrict-aliasing
    -pedantic
    -Wunreachable-code
    -Wcast-align
    -Wcast-qual
    -Winit-self
    -Wmissing-include-dirs
    -Wredundant-decls
    -Wshadow
    -Wstrict-overflow=5
    -Wswitch-default
    -Wundef
    -Wno-variadic-macros
    -Wformat-nonliteral

    $<$<CONFIG:Debug>:>
    $<$<CONFIG:Release>:>

    $<$<COMPILE_LANG_AND_ID:C,GNU>:
        -Wlogical-op
    >

    $<$<COMPILE_LANG_AND_ID:C,Clang>:
        -Wstring-conversion
    >
)

if (OPENSSL_FOUND)
    target_compile_options(${PROJECT_NAME} PRIVATE -DHSERV_HAVE_OPENSSL)
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
    src
    ../include
    ../src
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
)

add_custom_target(run-${PROJECT_NAME}
    ALL
    COMMENT "Running ${PROJECT_NAME} unittests"
    COMMAND ${PROJECT_NAME}
    DEPENDS ${PROJECT_NAME}
)

