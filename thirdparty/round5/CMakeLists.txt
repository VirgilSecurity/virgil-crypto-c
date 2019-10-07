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

get_property(KECCAK_INCLUDE_DIRECTORIES TARGET XKCP::keccak PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
get_property(KECCAK_LIBRARIES TARGET XKCP::keccak PROPERTY IMPORTED_LOCATION)

#
# OpenSSL
#
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(NOT ENV{OPENSSL_ROOT_DIR} AND EXISTS "/usr/local/opt/openssl@1.1")
        set(ENV{OPENSSL_ROOT_DIR} "/usr/local/opt/openssl@1.1")
    endif()
endif()
set(OPENSSL_USE_STATIC_LIBS YES)
find_package(OpenSSL 1.1.1 REQUIRED)

# ---------------------------------------------------------------------------
#   Prpeare options for 'Make' utility
# ---------------------------------------------------------------------------
#
# CPATH
#
foreach(inc_dir IN LISTS KECCAK_INCLUDE_DIRECTORIES OPENSSL_INCLUDE_DIR)
    if(DEFINED CPATH)
        set(CPATH "${CPATH}:${inc_dir}")
    else()
        set(CPATH "${inc_dir}")
    endif()
endforeach()

#
# LIBRARY_PATH
#
foreach(lib IN LISTS KECCAK_LIBRARIES OPENSSL_CRYPTO_LIBRARY)
    get_filename_component(lib_dir "${lib}" DIRECTORY)
    if(DEFINED LIBRARY_PATH)
        set(LIBRARY_PATH "${LIBRARY_PATH}:${lib_dir}")
    else()
        set(LIBRARY_PATH "${lib_dir}")
    endif()
    set(lib_dir)
endforeach()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
find_program(MAKE_EXE NAMES make)

include(ExternalProject)
ExternalProject_Add(round5-ext
        GIT_REPOSITORY
            https://github.com/round5/code
        GIT_TAG
            24b9738b0e39ce2115cc6b1f639359f5f459bd3e
        BUILD_IN_SOURCE TRUE
        CONFIGURE_COMMAND ""
        BUILD_COMMAND CPATH=${CPATH} LIBRARY_PATH=${LIBRARY_PATH} ${MAKE_EXE} ALG=R5ND_1KEM_0d reference
        INSTALL_COMMAND ""
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
set(ROUND5_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/round5-ext-prefix/src/round5-ext/reference")

add_library(round5 OBJECT IMPORTED GLOBAL)

add_dependencies(round5-ext XKCP::keccak)
add_dependencies(round5 round5-ext)

set_property(TARGET round5
        PROPERTY INTERFACE_COMPILE_DEFINITIONS
            R5ND_1KEM_0d
        )

set_property(TARGET round5
        PROPERTY IMPORTED_OBJECTS
            "${ROUND5_LOCATION}/build/.o/a_fixed.o"
            "${ROUND5_LOCATION}/build/.o/a_random.o"
            "${ROUND5_LOCATION}/build/.o/cca_encrypt.o"
            "${ROUND5_LOCATION}/build/.o/cpa_kem.o"
            "${ROUND5_LOCATION}/build/.o/drbg.o"
            "${ROUND5_LOCATION}/build/.o/little_endian.o"
            "${ROUND5_LOCATION}/build/.o/misc.o"
            "${ROUND5_LOCATION}/build/.o/pack.o"
            "${ROUND5_LOCATION}/build/.o/parameters.o"
            "${ROUND5_LOCATION}/build/.o/r5_cca_kem.o"
            "${ROUND5_LOCATION}/build/.o/r5_cca_pke.o"
            "${ROUND5_LOCATION}/build/.o/r5_core.o"
            "${ROUND5_LOCATION}/build/.o/r5_cpa_kem.o"
            "${ROUND5_LOCATION}/build/.o/r5_cpa_pke.o"
            "${ROUND5_LOCATION}/build/.o/r5_dem.o"
            "${ROUND5_LOCATION}/build/.o/r5_hash.o"
            "${ROUND5_LOCATION}/build/.o/r5_memory.o"
            "${ROUND5_LOCATION}/build/.o/r5_parameter_sets.o"
            "${ROUND5_LOCATION}/build/.o/shake.o"
            "${ROUND5_LOCATION}/build/.o/xef_ref.o"
            "${ROUND5_LOCATION}/build/.o/rng/true_rng.o"
        )

file(MAKE_DIRECTORY "${ROUND5_LOCATION}/src")
file(MAKE_DIRECTORY "${ROUND5_LOCATION}/src/rng")
set_property(TARGET round5
        PROPERTY INTERFACE_INCLUDE_DIRECTORIES
            "${ROUND5_LOCATION}/src"
            "${ROUND5_LOCATION}/src/rng"
        )
