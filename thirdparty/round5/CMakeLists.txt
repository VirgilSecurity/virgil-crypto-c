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

if(NOT ROUND5_LIBRARY)
    message(STATUS "Skip building library 'round5' - option ROUND5_LIBRARY is OFF.")
endif()


# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------
#
# keccak
#
if(NOT TARGET XKCP::keccak)
    message(FATAL_ERROR "Required library 'keccak' is not found - looking for target 'XKCP::keccak'.")
endif()

#
# mbedTLS
#
if(NOT TARGET mbed::crypto)
    message(FATAL_ERROR "Required library 'mbedcrypto' is not found - looking for target 'mbed::crypto'.")
endif()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
set(ROUND5_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/round5)

include(ExternalProject)
ExternalProject_Add(round5-ext
        GIT_REPOSITORY
            https://github.com/round5/code
        GIT_TAG
            24b9738b0e39ce2115cc6b1f639359f5f459bd3e
        UPDATE_COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/round5.CMakeLists.txt <SOURCE_DIR>/CMakeLists.txt &&
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/round5.reference.CMakeLists.txt <SOURCE_DIR>/reference/CMakeLists.txt &&
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/r5_dem_mbedtls.c <SOURCE_DIR>/reference/src/r5_dem_mbedtls.c
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${ROUND5_INSTALL_LOCATION}"
            "-DCMAKE_INSTALL_LIBDIR=lib"
            "-DALG=R5ND_5PKE_5d"
            "-DNO_OPENSSL_SHAKE=YES"
            "-DUSE_AES_DRBG=NO"
            "-DOPTIMIZED=OFF"
            "-DCONFIGURABLE=OFF"
            "-DCRYPTO_ENGINE_MBEDTLS=ON"
            "-DCRYPTO_ENGINE_OPENSSL=OFF"
            "-DKECCAK_INSTALL_LOCATION=${KECCAK_INSTALL_LOCATION}"
            "-DMBEDTLS_INSTALL_LOCATION=${MBEDTLS_INSTALL_LOCATION}"
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${ROUND5_INSTALL_LOCATION}/include)

add_library(round5 STATIC IMPORTED GLOBAL)

add_dependencies(round5-ext XKCP::keccak)
add_dependencies(round5-ext mbed::crypto)
add_dependencies(round5 round5-ext)

set_property(TARGET round5
        PROPERTY INTERFACE_COMPILE_DEFINITIONS
            R5ND_5PKE_5d
        )

set_property(TARGET round5
        PROPERTY INTERFACE_LINK_LIBRARIES
            XKCP::keccak
            mbed::crypto
        )

set_target_properties(round5
        PROPERTIES
        IMPORTED_LOCATION
            "${ROUND5_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}round5${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${ROUND5_INSTALL_LOCATION}/include"
        )

# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${ROUND5_INSTALL_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            DIRECTORY "${ROUND5_INSTALL_LOCATION}/lib/"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FILES_MATCHING REGEX "round5"
            PATTERN "cmake" EXCLUDE
            )
endif()
