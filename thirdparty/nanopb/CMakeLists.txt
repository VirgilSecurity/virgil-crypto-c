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
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-osx-x86_64.zip")
    set(PROTOC_BIN_HASH "ab11029340de61bb707a4d564ceeb580d31436f5466fad2194c91beb040aa828")

elseif(CMAKE_HOST_WIN32)
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-win32.zip")
    set(PROTOC_BIN_HASH "ec9081e6f0ad1b7e2737673eacbda9a9c0046ab4a25f7b5cfcd833c419e11469")

else()
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-linux-x86_64.zip")
    set(PROTOC_BIN_HASH "b9ff821d2a4f9e9943dc2a13e6a76d99c7472dac46ddd3718a3a4c3b877c044a")
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

set_target_properties(protoc PROPERTIES IMPORTED_LOCATION "${PROTOC_EXE}")


# ---------------------------------------------------------------------------
#   Load and build nanopb as an external project
# ---------------------------------------------------------------------------
ExternalProject_Add(protobuf-nanopb-ext
        GIT_REPOSITORY
            https://github.com/nanopb/nanopb
        GIT_TAG
            0.4.5
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

ExternalProject_Add_Step(protobuf-nanopb-ext install-nanopb-generator
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
                    "<SOURCE_DIR>/generator/nanopb_generator.py"
                    "${NANOPB_INSTALL_LOCATION}/generator/nanopb_generator.py"
        COMMENT
            "Install file: nanopb_generator.py"
        DEPENDEES
            install
        )

ExternalProject_Add_Step(protobuf-nanopb-ext install-nanopb-protoc-gen-nanopb
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
                    "<SOURCE_DIR>/generator/protoc-gen-nanopb"
                    "${NANOPB_INSTALL_LOCATION}/generator/protoc-gen-nanopb"
        COMMENT
            "Install file: protoc-gen-nanopb"
        DEPENDEES
            install
        )

ExternalProject_Add_Step(protobuf-nanopb-ext install-nanopb-protoc-gen-nanopb-win
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
                    "<SOURCE_DIR>/generator/protoc-gen-nanopb.bat"
                    "${NANOPB_INSTALL_LOCATION}/generator/protoc-gen-nanopb.bat"
        COMMENT
            "Install file: protoc-gen-nanopb.bat"
        DEPENDEES
            install
        )

ExternalProject_Add_Step(protobuf-nanopb-ext install-nanopb-utils
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
                    "<SOURCE_DIR>/generator/proto/_utils.py"
                    "${NANOPB_INSTALL_LOCATION}/generator/proto/_utils.py"
        COMMENT
            "Install file: _utils.py"
        DEPENDEES
            install
        )

ExternalProject_Add_Step(protobuf-nanopb-ext install-nanopb-pb2
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
                    "<BINARY_DIR>/nanopb_pb2.py"
                    "${NANOPB_INSTALL_LOCATION}/generator/proto/nanopb_pb2.py"
        COMMENT
            "Install file: nanopb_pb2.py"
        DEPENDEES
            install
        )

# ---------------------------------------------------------------------------
#   Defines path to nanopb protobuf generator script.
# ---------------------------------------------------------------------------
set(NANOPB_GENERATOR "${NANOPB_INSTALL_LOCATION}/generator/nanopb_generator.py" CACHE PATH "" FORCE)

if(UNIX OR CYGWIN)
    set(PROTOC_GEN_NANOPB "${NANOPB_INSTALL_LOCATION}/generator/protoc-gen-nanopb" CACHE PATH "" FORCE)
else()
    set(PROTOC_GEN_NANOPB "${NANOPB_INSTALL_LOCATION}/generator/protoc-gen-nanopb.bat" CACHE PATH "" FORCE)
endif()

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
