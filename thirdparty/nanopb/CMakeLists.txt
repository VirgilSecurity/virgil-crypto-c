#   Copyright (c) 2015-2017 Virgil Security Inc.
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
#   Configuration options
# ---------------------------------------------------------------------------

include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

if(NOT NANOPB_LIBRARY)
    message(STATUS "Skip build of library: nanopb")
    return()
endif()

# ---------------------------------------------------------------------------
#   Build Options
# ---------------------------------------------------------------------------
set(NANOPB_INSTALL_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/protobuf-nanopb")

if(CMAKE_HOST_APPLE)
    set(NANOPB_BIN_URL "https://jpa.kapsi.fi/nanopb/download/nanopb-0.3.9.1-macosx-x86.tar.gz")
    set(NANOPB_BIN_HASH "ca960a90cfd27428b08c02deae6f77ce44bf37f9bf1e2044721f4397d1418c86")

elseif(CMAKE_HOST_WIN32)
    set(NANOPB_BIN_URL "https://jpa.kapsi.fi/nanopb/download/nanopb-0.3.9.1-windows-x86.zip")
    set(NANOPB_BIN_HASH "4a6fee9397619db14b695f19625c6b29f04c89cf4294f88c6426677b84610051")

else()
    set(NANOPB_BIN_URL "https://jpa.kapsi.fi/nanopb/download/nanopb-0.3.9.1-linux-x86.tar.gz")
    set(NANOPB_BIN_HASH "ee18b12ea11376e6b6d89a2cab4592fb1fbaeff3252f180608c9a7632594a12e")
endif()


# ---------------------------------------------------------------------------
#   Load library and generator as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)

ExternalProject_Add(protobuf-nanopb-bin-ext
        URL "${NANOPB_BIN_URL}"
        URL_HASH SHA256=${NANOPB_BIN_HASH}
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/protobuf-nanopb-bin-ext"
        BUILD_IN_SOURCE
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND cmake -E copy_directory
            "${CMAKE_CURRENT_BINARY_DIR}/protobuf-nanopb-bin-ext/src/protobuf-nanopb-bin-ext/generator-bin"
            "${NANOPB_INSTALL_LOCATION}/bin"
        )


ExternalProject_Add(protobuf-nanopb-ext
        GIT_REPOSITORY
            https://github.com/nanopb/nanopb
        GIT_TAG
            0.3.9.1
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${NANOPB_INSTALL_LOCATION}"
            "-DBUILD_SHARED_LIBS=OFF"
            "-Dnanopb_BUILD_RUNTIME=ON"
            "-Dnanopb_BUILD_GENERATOR=OFF"
            "-Dnanopb_MSVC_STATIC_RUNTIME=ON"
        BUILD_BYPRODUCTS
            "${NANOPB_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-nanopb${CMAKE_STATIC_LIBRARY_SUFFIX}"
            "${NANOPB_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-nanopbd${CMAKE_STATIC_LIBRARY_SUFFIX}"
        )


# ---------------------------------------------------------------------------
#   Import protobuf model compiler as a target
# ---------------------------------------------------------------------------
add_executable(protoc IMPORTED GLOBAL)

add_dependencies(protoc protobuf-nanopb-bin-ext)

set_target_properties(protoc
        PROPERTIES
        IMPORTED_LOCATION
            "${NANOPB_INSTALL_LOCATION}/bin/protoc${CMAKE_EXECUTABLE_SUFFIX}"
        )


# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${NANOPB_INSTALL_LOCATION}/include)

#
# nonopb
#
add_library(protobuf-nanopb STATIC IMPORTED GLOBAL)

add_dependencies(protobuf-nanopb protobuf-nanopb-ext)

set_target_properties(protobuf-nanopb
        PROPERTIES
        IMPORTED_LOCATION
            "${NANOPB_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-nanopb${CMAKE_STATIC_LIBRARY_SUFFIX}"
        IMPORTED_LOCATION_DEBUG
            "${NANOPB_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-nanopbd${CMAKE_STATIC_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES
            "${NANOPB_INSTALL_LOCATION}/include"
        )


# ---------------------------------------------------------------------------
#   Alias library alias
# ---------------------------------------------------------------------------
if(NOT TARGET nanopb::protobuf-nanopb)
    add_library(nanopb::protobuf-nanopb ALIAS protobuf-nanopb)
endif()


# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------

#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${NANOPB_INSTALL_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            DIRECTORY "${NANOPB_INSTALL_LOCATION}/lib/"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            PATTERN "cmake" EXCLUDE
            )
endif()

#
# Install CMake configuration files.
#
if(VIRGIL_INSTALL_DEPS_CMAKE)
    install(
            DIRECTORY "${NANOPB_INSTALL_LOCATION}/lib/cmake"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            )
endif()
