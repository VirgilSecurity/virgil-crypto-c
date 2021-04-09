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
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-osx-x86_64.zip")
    set(PROTOC_BIN_HASH "0decc6ce5beed07f8c20361ddeb5ac7666f09cf34572cca530e16814093f9c0c")

elseif(CMAKE_HOST_WIN32)
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-win32.zip")
    set(PROTOC_BIN_HASH "65e5d6f890e8df5b6b411e3fdbad04c33b2bd34a3576f343a8986589bd8d05e2")

else()
    set(PROTOC_BIN_URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip")
    set(PROTOC_BIN_HASH "6003de742ea3fcf703cfec1cd4a3380fd143081a2eb0e559065563496af27807")
endif()

# ---------------------------------------------------------------------------
#   Optionally load and import protobuf generator as an external project
# ---------------------------------------------------------------------------
include(FetchContent)

if(WIN32 AND NOT CYGWIN)
    set(EXECUTABLE_SUFFIX ".exe")
endif()

if(TARGET protoc)
    set(PROTOC_EXE protoc)

elseif(COMMAND find_host_program)
    find_host_program(PROTOC_EXE NAMES protoc${EXECUTABLE_SUFFIX})

else()
    find_program(PROTOC_EXE NAMES protoc${EXECUTABLE_SUFFIX})
endif()


if(NOT PROTOC_EXE)
    FetchContent_Declare(
        protobuf-bin-ext
        URL "${PROTOC_BIN_URL}"
        URL_HASH SHA256=${PROTOC_BIN_HASH}
    )

    FetchContent_MakeAvailable(protobuf-bin-ext)

    add_executable(protoc IMPORTED GLOBAL)

    set_target_properties(protoc
            PROPERTIES
            IMPORTED_LOCATION
                "${protobuf-bin-ext_SOURCE_DIR}/bin/protoc${EXECUTABLE_SUFFIX}"
            )

    set(PROTOC_EXE_EXE protoc)
endif()

# ---------------------------------------------------------------------------
#   Load and build nanopb library as an external project
# ---------------------------------------------------------------------------
FetchContent_Declare(
    nanopb
    GIT_REPOSITORY https://github.com/nanopb/nanopb
    GIT_TAG 0.4.5
)


FetchContent_GetProperties(nanopb)
if(NOT nanopb_POPULATED)
    FetchContent_Populate(nanopb)

    add_subdirectory(${nanopb_SOURCE_DIR} ${nanopb_BINARY_DIR})

    target_include_directories(protobuf-nanopb-static
        INTERFACE $<BUILD_INTERFACE:${nanopb_SOURCE_DIR}>
    )

    target_compile_definitions(protobuf-nanopb-static PUBLIC
        $<$<BOOL:${PB_ENABLE_MALLOC}>:PB_ENABLE_MALLOC>
        $<$<BOOL:${PB_NO_PACKED_STRUCTS}>:PB_NO_PACKED_STRUCTS>
        $<$<BOOL:${PB_MAX_REQUIRED_FIELDS}>:PB_MAX_REQUIRED_FIELDS>
        $<$<BOOL:${PB_FIELD_16BIT}>:PB_FIELD_16BIT>
        $<$<BOOL:${PB_FIELD_32BIT}>:PB_FIELD_32BIT>
        $<$<BOOL:${PB_NO_ERRMSG}>:PB_NO_ERRMSG>
        $<$<BOOL:${PB_BUFFER_ONLY}>:PB_BUFFER_ONLY>
    )
endif()


if(NOT TARGET nanopb::protobuf-nanopb)
    add_library(nanopb::protobuf-nanopb ALIAS protobuf-nanopb-static)
endif()


# ---------------------------------------------------------------------------
#   Defines path to nanopb protobuf plugin script
# ---------------------------------------------------------------------------
if(UNIX OR CYGWIN)
    set(PROTOC_GEN_NANOPB "${nanopb_SOURCE_DIR}/generator/protoc-gen-nanopb" CACHE INTERNAL "")
else()
    set(PROTOC_GEN_NANOPB "${nanopb_SOURCE_DIR}/generator/protoc-gen-nanopb.bat" CACHE INTERNAL "")
endif()
