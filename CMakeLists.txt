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
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(virgil_crypto VERSION 0.19.0 LANGUAGES C)


# ---------------------------------------------------------------------------
#   Forced build options
# ---------------------------------------------------------------------------
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
#   Global policies
# ---------------------------------------------------------------------------
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

# ---------------------------------------------------------------------------
#   Helper modules
# ---------------------------------------------------------------------------
include("cmake/find_host_utils.cmake")
include("cmake/clangformat.cmake")
include("cmake/helpers.cmake")
include("cmake/TransitiveArgs.cmake")
include("cmake/TransitiveToolchainArgs.cmake")
include("cmake/protobuf.cmake")


# ---------------------------------------------------------------------------
#   Version options
# ---------------------------------------------------------------------------
set(VIRGIL_CRYPTO_VERSION_LABEL "rc.13" CACHE STRING "Version label, i.e. beta, rc1.")

# ---------------------------------------------------------------------------
#   Build options
# ---------------------------------------------------------------------------

#
# Global
#
option(BUILD_SHARED_LIBS "On/Off build shared libraries." OFF)

#
# Test
#
option(ENABLE_TESTING "On/Off integration tests." ON)
option(ENABLE_HEAVY_TESTS "On/Off execution of heavy tests." OFF)
option(ENABLE_PROFILING "On/Off GProf compilation options." OFF)
option(ENABLE_FUZZY_TESTING "On/Off fyzzy tests." OFF)
option(ENABLE_BENCHMARKING "On/Off execution of benchmarks." OFF)

#
# Code formatting
#
option(ENABLE_CLANGFORMAT "On/Off formatting source code with clangformat." ON)

option(VIRGIL_C_TESTING "On/Off C library integration tests." ON)
option(VIRGIL_C_MT_TESTING "On/Off C library multi-threading tests." OFF)

#
# Libraries
#
option(VIRGIL_LIB_COMMON "Build 'common' library" ON)
option(VIRGIL_LIB_FOUNDATION "Build 'foundation' library" ON)
option(VIRGIL_LIB_ED25519 "Build 'ed25519' library" ON)
option(VIRGIL_LIB_RATCHET "Build 'ratchet' library" ON)
option(VIRGIL_LIB_PHE "Build 'phe' library" ON)

#
# Programs
#
option(VIRGIL_PROGRAMS "Build programs." OFF)

#
# Features
#
option(VIRGIL_POST_QUANTUM "Enable post-quantum cryptography." ON)

#
# Threading
#
option(VIRGIL_DISABLE_MULTI_THREADING "Disable multi-threading safety across all libraries (single-threaded targets only)." OFF)

#
# Wrappers
#
option(VIRGIL_WRAP_ALL "Build all available wrappers on the given platform" OFF)
option(VIRGIL_WRAP_GO "Build 'Golang' wrapper" OFF)
option(VIRGIL_WRAP_PHP "Build 'PHP' wrapper" OFF)
option(VIRGIL_WRAP_JAVA "Build 'Java' wrapper" OFF)
option(VIRGIL_WRAP_WASM "Build 'WebAssembly' wrapper" OFF)


# ---------------------------------------------------------------------------
#   Platfrom specific.
# ---------------------------------------------------------------------------
set(VIRGIL_PLATFORM_HDR "" CACHE STRING "Name or path to the header file that contains platform specific definitions.")
set(VIRGIL_PLATFORM_INC_DIR "" CACHE STRING "Path to the platform specific include directory.")
set(VIRGIL_PLATFORM_ALLOC "" CACHE STRING "Platform specific allocation function, takes 1 argument with a size.")
set(VIRGIL_PLATFORM_DEALLOC "" CACHE STRING "Platform specific de-allocation function, takes 1 argument with a pointer.")

# ---------------------------------------------------------------------------
#   Install options
# ---------------------------------------------------------------------------

#
# Core
#
option(VIRGIL_INSTALL_HDRS "Install headers" ON)
option(VIRGIL_INSTALL_LIBS "Install libraries" ON)
option(VIRGIL_INSTALL_CMAKE "Install CMake configuration files" ON)

#
# External dependencies
#
option(VIRGIL_INSTALL_DEPS_HDRS "Install dependencies headers" ON)
option(VIRGIL_INSTALL_DEPS_LIBS "Install dependencies libraries" ON)
option(VIRGIL_INSTALL_DEPS_CMAKE "Install dependencies CMake configuration file" ON)

#
# Wrappers
#
option(VIRGIL_INSTALL_WRAP_SRCS "Install wrapper sources" ON)
option(VIRGIL_INSTALL_WRAP_LIBS "Install wrapper libraries" ON)
option(VIRGIL_INSTALL_WRAP_DEPS "Install wrapper dependencies" ON)


# ---------------------------------------------------------------------------
#   Installation paths options
# ---------------------------------------------------------------------------

#
# Use common options from the module 'GNUInstallDirs'.
#
include(GNUInstallDirs)

# ---------------------------------------------------------------------------
#   Library shall be built in python virtual environment
# ---------------------------------------------------------------------------
if (NOT DEFINED ENV{VIRTUAL_ENV})
    message(STATUS "Create python virtual environment...")
    set(ENV{VIRTUAL_ENV} "${CMAKE_CURRENT_BINARY_DIR}/.venv")
    execute_process(COMMAND python3 -m venv "$ENV{VIRTUAL_ENV}")
endif()

set(ENV{PATH} "$ENV{VIRTUAL_ENV}/bin:$ENV{PATH}")
execute_process(COMMAND pip3 install -U -r "${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt")

# ---------------------------------------------------------------------------
#   Dependencies / thirdparty libraries
# ---------------------------------------------------------------------------

#
# Allow access to mbedTLS private struct members during 2.x -> 3.x migration.
#
add_compile_definitions(MBEDTLS_ALLOW_PRIVATE_ACCESS)

#
# MbedTLS
#
if(VIRGIL_LIB_FOUNDATION)
    add_subdirectory("thirdparty/mbedtls")
endif()

#
# Ed25519
#
if(VIRGIL_LIB_ED25519)
    add_subdirectory("thirdparty/ed25519")
endif()

#
# Protobuf
#
add_subdirectory("thirdparty/nanopb")

#
# Post-quantum
#
if(VIRGIL_POST_QUANTUM)
    set(VSCF_POST_QUANTUM ON CACHE BOOL "Enable post-quantum cryptography for foundation library." FORCE)
    add_subdirectory("thirdparty/falcon")
    add_subdirectory("thirdparty/mlkem-native")
    add_subdirectory("thirdparty/mldsa-native")
else()
    set(VSCF_POST_QUANTUM OFF CACHE BOOL "Enable post-quantum cryptography for foundation library." FORCE)
endif()

# ---------------------------------------------------------------------------
#   Library core libraries
# ---------------------------------------------------------------------------

if(VIRGIL_DISABLE_MULTI_THREADING)
    set(VSC_MULTI_THREADING  OFF CACHE BOOL "" FORCE)
    set(VSCF_MULTI_THREADING OFF CACHE BOOL "" FORCE)
    set(VSCE_MULTI_THREADING OFF CACHE BOOL "" FORCE)
    set(VSCR_MULTI_THREADING OFF CACHE BOOL "" FORCE)
endif()

add_subdirectory("library/platform")

if(VIRGIL_LIB_COMMON)
    add_subdirectory("library/common")
endif()

if(VIRGIL_LIB_FOUNDATION)
    add_subdirectory("library/foundation")
endif()

if(VIRGIL_LIB_RATCHET)
    add_subdirectory("library/ratchet")
endif()

if(VIRGIL_LIB_PHE)
    add_subdirectory("library/phe")
endif()


# ---------------------------------------------------------------------------
#   Integration tests
# ---------------------------------------------------------------------------
if(ENABLE_TESTING)
    include(CTest)
endif()

if(ENABLE_TESTING AND VIRGIL_C_TESTING AND NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
#   Benchmarks
# ---------------------------------------------------------------------------

if(ENABLE_BENCHMARKING AND NOT CMAKE_CROSSCOMPILING)
    add_subdirectory("benchmarks")
endif()

# ---------------------------------------------------------------------------
#   Programs / Examples
# ---------------------------------------------------------------------------
if(VIRGIL_PROGRAMS)
    add_subdirectory("programs")
endif()

# ---------------------------------------------------------------------------
#   Library wrappers
# ---------------------------------------------------------------------------
if(VIRGIL_WRAP_ALL OR VIRGIL_WRAP_GO)
    add_subdirectory("wrappers/go")
endif()

if(VIRGIL_WRAP_ALL OR VIRGIL_WRAP_PHP)
    add_subdirectory("wrappers/php")
endif()

if(VIRGIL_WRAP_ALL OR VIRGIL_WRAP_JAVA)
    add_subdirectory("wrappers/java")
endif()

if(VIRGIL_WRAP_WASM)
    add_subdirectory("wrappers/wasm")
endif()


# ---------------------------------------------------------------------------
#   Code line stats
# ---------------------------------------------------------------------------
find_program(CLOC_EXECUTABLE cloc)

if(CLOC_EXECUTABLE)
    add_custom_target(cloc-common
            COMMAND ${CLOC_EXECUTABLE}
                "${CMAKE_CURRENT_LIST_DIR}/library/common/include/virgil/crypto/common"
                "${CMAKE_CURRENT_LIST_DIR}/library/common/include/virgil/crypto/common/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/common/src"
            COMMENT "Calculate lines of the 'common' library..."
            )

    add_custom_target(cloc-foundation
            COMMAND ${CLOC_EXECUTABLE}
                "${CMAKE_CURRENT_LIST_DIR}/library/foundation/include/virgil/crypto/foundation"
                "${CMAKE_CURRENT_LIST_DIR}/library/foundation/include/virgil/crypto/foundation/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/foundation/src"
            COMMENT "Calculate lines of the 'foundation' library..."
            )

    add_custom_target(cloc-ratchet
            COMMAND ${CLOC_EXECUTABLE}
                "${CMAKE_CURRENT_LIST_DIR}/library/ratchet/include/virgil/crypto/ratchet"
                "${CMAKE_CURRENT_LIST_DIR}/library/ratchet/include/virgil/crypto/ratchet/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/ratchet/src"
            COMMENT "Calculate lines of the 'ratchet' library..."
            )

    add_custom_target(cloc)
    add_dependencies(cloc cloc-common cloc-foundation cloc-ratchet)
endif()


# ---------------------------------------------------------------------------
#   Configure CPack
# ---------------------------------------------------------------------------

#
#  Use [MAJOR].[MINOR] package version if it is not a cross-compiling build
#
if(CMAKE_CROSSCOMPILING)
    set(SYSTEM_VERSION_SHORT ${CMAKE_SYSTEM_VERSION})
else()
    string(REGEX REPLACE "([0-9]+\\.[0-9]+).*" "\\1" SYSTEM_VERSION_SHORT "${CMAKE_SYSTEM_VERSION}")
endif()

set(VIRGIL_PACKAGE_LANGUAGE "C" CACHE STRING "[CPack] Package language name (used in the archive name)")
set(VIRGIL_PACKAGE_LANGUAGE_VERSION "" CACHE STRING "[CPack] Package language version (used in the archive name)")
set(VIRGIL_PACKAGE_PLATFORM "${CMAKE_SYSTEM_NAME}" CACHE STRING "[CPack] Platform name (used in the archive name)")
set(VIRGIL_PACKAGE_PLATFORM_VERSION "${SYSTEM_VERSION_SHORT}" CACHE STRING "[CPack] Platform version (used in the archive name)")
set(VIRGIL_PACKAGE_PLATFORM_ARCH "" CACHE STRING "[CPack] Platform architecture (used in the archive name)")

#
#  Define package name in the format "library-language[-platform]", where
#     library = name-version
#     language = name[-version]
#     platform = name[-version][-arch]
#
set(VIRGIL_PACKAGE_NAME "virgil-crypto-c")

# Keep archive names stable and predictable across CI.
# Desired format (lower-cased):
#   virgil-crypto-c-<version>[-<label>]-<language>[-<lang_version>]-<platform>[-<arch>]
list(APPEND VIRGIL_PACKAGE_NAME ${virgil_crypto_VERSION})

if(VIRGIL_CRYPTO_VERSION_LABEL)
    list(APPEND VIRGIL_PACKAGE_NAME ${VIRGIL_CRYPTO_VERSION_LABEL})
endif()

list(APPEND VIRGIL_PACKAGE_NAME ${VIRGIL_PACKAGE_LANGUAGE})

if(VIRGIL_PACKAGE_LANGUAGE_VERSION)
    list(APPEND VIRGIL_PACKAGE_NAME ${VIRGIL_PACKAGE_LANGUAGE_VERSION})
endif()

list(APPEND VIRGIL_PACKAGE_NAME ${VIRGIL_PACKAGE_PLATFORM})

if(VIRGIL_PACKAGE_PLATFORM_ARCH)
    list(APPEND VIRGIL_PACKAGE_NAME ${VIRGIL_PACKAGE_PLATFORM_ARCH})
endif()

string(REPLACE ";" "-" VIRGIL_PACKAGE_NAME "${VIRGIL_PACKAGE_NAME}")
string(TOLOWER "${VIRGIL_PACKAGE_NAME}" VIRGIL_PACKAGE_NAME)


if(WIN32)
    set(CPACK_GENERATOR ZIP)
else()
    set(CPACK_GENERATOR TGZ)
endif()
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Virgil Security Crypto library")
set(CPACK_PACKAGE_VENDOR "Virgil Security, Inc.")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_LIST_DIR}/LICENSE")
set(CPACK_PACKAGE_FILE_NAME "${VIRGIL_PACKAGE_NAME}")
set(CPACK_OUTPUT_FILE_PREFIX "packages" CACHE STRING "Output directory for CPack archives")

include (CPack)
