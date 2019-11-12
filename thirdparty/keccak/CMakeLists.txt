#   Copyright (C) 2015-2019 Virgil Security, Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.


# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

if(NOT KECCAK_LIBRARY)
    message(STATUS "Skip building library 'keccack' - option KECCAK_LIBRARY is OFF.")
endif()


# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
set(KECCAK_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/keccak CACHE PATH INTERNAL)

include(ExternalProject)
ExternalProject_Add(keccak-ext
        GIT_REPOSITORY
            https://github.com/XKCP/XKCP
        GIT_TAG
            e8e6b1d45861ea6fc0957ab27a401f42aef0d033
        UPDATE_COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/xkcp.CMakeLists.txt <SOURCE_DIR>/CMakeLists.txt &&
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/xkcp.lib.CMakeLists.txt <SOURCE_DIR>/lib/CMakeLists.txt
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DBUILD_SHARED_LIBS=OFF"
            "-DCMAKE_INSTALL_PREFIX=${KECCAK_INSTALL_LOCATION}"
            "-DCMAKE_INSTALL_LIBDIR=lib"
            "-DXKCP_IMPL=reference"
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
set(KECCAK_LIB_NAME "${CMAKE_STATIC_LIBRARY_PREFIX}keccak${CMAKE_STATIC_LIBRARY_SUFFIX}")
file(MAKE_DIRECTORY "${KECCAK_INSTALL_LOCATION}/include")
file(MAKE_DIRECTORY "${KECCAK_INSTALL_LOCATION}/include/${KECCAK_LIB_NAME}.headers")

add_library(keccak STATIC IMPORTED GLOBAL)

add_dependencies(keccak keccak-ext)

set_target_properties(keccak
        PROPERTIES
        IMPORTED_LOCATION
            "${KECCAK_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}keccak${CMAKE_STATIC_LIBRARY_SUFFIX}"

        )

set_property(TARGET keccak
        PROPERTY INTERFACE_INCLUDE_DIRECTORIES
            "${KECCAK_INSTALL_LOCATION}/include"
            "${KECCAK_INSTALL_LOCATION}/include/${KECCAK_LIB_NAME}.headers"
        )

# ---------------------------------------------------------------------------
#   Alias library alias
# ---------------------------------------------------------------------------
if(NOT TARGET XKCP::keccak)
    add_library(XKCP::keccak ALIAS keccak)
endif()
