#   Copyright (C) 2015-2026 Virgil Security, Inc.
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

if(NOT MLDSA_LIBRARY)
    message(STATUS "Skip building library 'mldsa-native' - option MLDSA_LIBRARY is OFF.")
    return()
endif()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
set(MLDSA_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/mldsa-native)

include(ExternalProject)
ExternalProject_Add(mldsa-native-ext
        URL
            https://github.com/pq-code-package/mldsa-native/archive/refs/tags/v1.0.0-beta.tar.gz
        URL_HASH
            SHA256=85bebfbb38dd7abb104bfd1a9b070754f515495f60dff6407b0f327c1b291831
        PATCH_COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/mldsa.CMakeLists.txt <SOURCE_DIR>/CMakeLists.txt &&
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/mldsa_config_65.h <SOURCE_DIR>/mldsa/mldsa_config_65.h
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${MLDSA_INSTALL_LOCATION}"
            "-DCMAKE_INSTALL_LIBDIR=lib"
        BUILD_BYPRODUCTS "${MLDSA_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mldsa65${CMAKE_STATIC_LIBRARY_SUFFIX}"
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${MLDSA_INSTALL_LOCATION}/include)

add_library(mldsa65 STATIC IMPORTED GLOBAL)

add_dependencies(mldsa65 mldsa-native-ext)

set_target_properties(mldsa65
        PROPERTIES
        IMPORTED_LOCATION
            "${MLDSA_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mldsa65${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${MLDSA_INSTALL_LOCATION}/include"
        )

# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${MLDSA_INSTALL_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            )
endif()

if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            DIRECTORY "${MLDSA_INSTALL_LOCATION}/lib/"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FILES_MATCHING REGEX "mldsa65"
            PATTERN "cmake" EXCLUDE
            )
endif()
