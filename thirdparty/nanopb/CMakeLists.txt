#   Copyright (C) 2015-2022 Virgil Security, Inc.
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

if(NOT PB_LIBRARY)
    message(STATUS "Skip build of library: nanopb")
    return()
endif()

# ---------------------------------------------------------------------------
#   Build Options
# ---------------------------------------------------------------------------
set(NANOPB_INSTALL_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/protobuf-nanopb")

if(CMAKE_HOST_APPLE)
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-osx-universal_binary.zip")
    set(PROTOC_BIN_HASH "52df502b263da20f3311b23b5c6553d10cc25c6ebb85df381d80a2806b6a698b")

elseif(CMAKE_HOST_WIN32)
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-win64.zip")
    set(PROTOC_BIN_HASH "ce64f49bdeddef49ce4bd313a8f59bcf92fcf67b5831efbf66170386d2e66948")

elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-linux-aarch_64.zip")
    set(PROTOC_BIN_HASH "1de522032a8b194002fe35cab86d747848238b5e4de4f99648372079f5b46f9a")

elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-linux-x86_64.zip")
    set(PROTOC_BIN_HASH "0ad949f04a6a174da83cdcbdb36dee0a4925272a5b6d83f79a6bf9852076d53f")

else()
    message(FATAL_ERROR "Unsupported host system processor: ${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()

# ---------------------------------------------------------------------------
#   System introspection
# ---------------------------------------------------------------------------
if(CMAKE_HOST_WIN32)
    set(HOST_EXECUTABLE_SUFFIX ".exe")
endif()

# ---------------------------------------------------------------------------
#   Optionally load and import protobuf generator as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)

ExternalProject_Add(protobuf-bin-ext
        URL "${PROTOC_BIN_URL}"
        URL_HASH SHA256=${PROTOC_BIN_HASH}
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/protobuf-bin-ext"
        BUILD_IN_SOURCE
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "${CMAKE_COMMAND}" -E copy_directory
            "${CMAKE_CURRENT_BINARY_DIR}/protobuf-bin-ext/src/protobuf-bin-ext/bin"
            "${NANOPB_INSTALL_LOCATION}/bin"
        )

add_executable(protoc IMPORTED GLOBAL)

add_dependencies(protoc protobuf-bin-ext)

set(PROTOC_EXE "${NANOPB_INSTALL_LOCATION}/bin/protoc${HOST_EXECUTABLE_SUFFIX}")
message(STATUS "PROTOC_EXE: ${PROTOC_EXE}")

set_target_properties(protoc PROPERTIES IMPORTED_LOCATION "${PROTOC_EXE}")


# ---------------------------------------------------------------------------
#   Load and build nanopb as an external project
# ---------------------------------------------------------------------------
ExternalProject_Add(protobuf-nanopb-ext
        GIT_REPOSITORY
            https://github.com/nanopb/nanopb
        GIT_TAG
            nanopb-0.4.9
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${NANOPB_INSTALL_LOCATION}"
            "-DBUILD_SHARED_LIBS=OFF"
            "-Dnanopb_BUILD_RUNTIME=ON"
            "-Dnanopb_BUILD_GENERATOR=ON"
            "-Dnanopb_MSVC_STATIC_RUNTIME=ON"
            "-DCMAKE_INSTALL_LIBDIR=lib"
            "-Dnanopb_PROTOC_PATH=${PROTOC_EXE}"
        PATCH_COMMAND
            ${CMAKE_COMMAND}
                -DPB_H_FILE="${CMAKE_CURRENT_BINARY_DIR}/protobuf-nanopb-ext-prefix/src/protobuf-nanopb-ext/pb.h"
                -DPB_ENABLE_MALLOC=${PB_ENABLE_MALLOC}
                -DPB_NO_PACKED_STRUCTS=${PB_NO_PACKED_STRUCTS}
                -DPB_MAX_REQUIRED_FIELDS=${PB_MAX_REQUIRED_FIELDS}
                -DPB_FIELD_32BIT=${PB_FIELD_32BIT}
                -DPB_NO_ERRMSG=${PB_NO_ERRMSG}
                -DPB_BUFFER_ONLY=${PB_BUFFER_ONLY}
                -P "${CMAKE_CURRENT_LIST_DIR}/patch_pb.h.cmake"
        BUILD_BYPRODUCTS
            "${NANOPB_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-nanopb${CMAKE_STATIC_LIBRARY_SUFFIX}"
            "${NANOPB_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-nanopbd${CMAKE_STATIC_LIBRARY_SUFFIX}"
        DEPENDS
            protobuf-bin-ext
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${NANOPB_INSTALL_LOCATION}/include)
file(MAKE_DIRECTORY ${NANOPB_INSTALL_LOCATION}/include/nanopb)

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
            "${NANOPB_INSTALL_LOCATION}/include;${NANOPB_INSTALL_LOCATION}/include/nanopb"
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
