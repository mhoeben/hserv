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
project("hserv")

#
# Dependencies
#
find_package(OpenSSL)

if (HSERV_ENABLE_UNITTESTS)
    add_subdirectory(unittests)
endif ()

#
# Executable
#
add_executable(${PROJECT_NAME}
    include/harray.h
    include/hbuffer.h
    include/hfs.h
    include/hhash_map.h
    include/hlist.h
    include/hserv.h
    include/hws.h

    src/main.c
    src/server.c
    src/server.h
    src/utility.c
    src/utility.h
    src/websocket.c
    src/websocket.h
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
    target_compile_options(${PROJECT_NAME} PRIVATE -DHSERV_HAVE_OPENSSL -DHWS_HAVE_OPENSSL)
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    src
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)

