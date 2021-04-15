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
#   Optionally load and import protobuf generator as an external project
# ---------------------------------------------------------------------------
include(FetchContent)

if(WIN32 AND NOT CYGWIN)
    set(EXECUTABLE_SUFFIX ".exe")
endif()

if(TARGET protoc)
    get_target_property(PROTOC_EXE protoc LOCATION)

elseif(COMMAND find_host_program)
    find_host_program(PROTOC_EXE NAMES protoc${EXECUTABLE_SUFFIX})

else()
    find_program(PROTOC_EXE NAMES protoc${EXECUTABLE_SUFFIX})
endif()


if(NOT PROTOC_EXE)
    FetchContent_Declare(
        protoc_bin
        URL "${PROTOC_BIN_URL}"
        URL_HASH SHA256=${PROTOC_BIN_HASH}
    )

    FetchContent_GetProperties(protoc_bin)
    if(NOT protoc_bin_POPULATED)
        FetchContent_Populate(protoc_bin)

        add_executable(protoc IMPORTED GLOBAL)

        set(PROTOC_EXE "${protoc_bin_SOURCE_DIR}/bin/protoc${EXECUTABLE_SUFFIX}")

        set_target_properties(protoc
            PROPERTIES
            IMPORTED_LOCATION "${PROTOC_EXE}"
        )
    endif()
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

    set(nanopb_PROTOC_PATH "${PROTOC_EXE}")

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
#   Defines path to nanopb protobuf generator script.
# ---------------------------------------------------------------------------
set(NANOPB_GENERATOR "${nanopb_SOURCE_DIR}/generator/nanopb_generator.py" CACHE PATH "" FORCE)
