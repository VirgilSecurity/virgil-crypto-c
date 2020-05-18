#   Copyright (C) 2015-2020 Virgil Security, Inc.
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

if(NOT JSON_C_LIBRARY)
    message(STATUS "Skip building library 'json_c' - option JSON_C_LIBRARY is OFF.")
endif()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
set(JSON_C_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/json_c)

include(ExternalProject)
ExternalProject_Add(json_c-ext
        GIT_REPOSITORY
            https://github.com/json-c/json-c
        GIT_TAG
            json-c-0.14-20200419
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${JSON_C_INSTALL_LOCATION}"
            "-DCMAKE_INSTALL_LIBDIR=lib"
            "-DBUILD_SHARED_LIBS=OFF"
            "-DENABLE_THREADING=OFF"
            "-DENABLE_TESTING=${JSON_C_ENABLE_TESTING}"
            "-DBUILD_SPEEDTEST=${JSON_C_BUILD_SPEEDTEST}"
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${JSON_C_INSTALL_LOCATION}/include)

add_library(json_c STATIC IMPORTED GLOBAL)

add_dependencies(json_c json_c-ext)

set_target_properties(json_c
        PROPERTIES
        IMPORTED_LOCATION
            "${JSON_C_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}json-c${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${JSON_C_INSTALL_LOCATION}/include"
        )

# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${JSON_C_INSTALL_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            DIRECTORY "${JSON_C_INSTALL_LOCATION}/lib/"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FILES_MATCHING REGEX "json_c"
            PATTERN "cmake" EXCLUDE
            )
endif()
