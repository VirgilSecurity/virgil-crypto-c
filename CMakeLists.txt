#   Copyright (C) 2015-2018 Virgil Security Inc.
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

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(virgil_crypto_c_top VERSION 0.1.0 LANGUAGES C)


# ---------------------------------------------------------------------------
#   Forced build options
# ---------------------------------------------------------------------------
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# ---------------------------------------------------------------------------
#   Helper modules
# ---------------------------------------------------------------------------
include("cmake/clangformat.cmake")
include("cmake/helpers.cmake")
include("cmake/TransitiveArgs.cmake")
include("cmake/TransitiveToolchainArgs.cmake")
include("cmake/protobuf.cmake")


# ---------------------------------------------------------------------------
#   Build options
# ---------------------------------------------------------------------------

#
# Global
#
option(BUILD_SHARED_LIBS "On/Off build shared libraries." OFF)

#
# Test & bench
#
option(ENABLE_TESTING "On/Off library integration tests." ON)
option(ENABLE_BENCHMARKS "On/Off build library benchmarks." ON)

#
# Libraries
#
option(VIRGIL_LIB_COMMON "Build 'common' library" ON)
option(VIRGIL_LIB_FOUNDATION "Build 'foundation' library" ON)
option(VIRGIL_LIB_PYTHIA "Build 'pythia' library" ON)
option(VIRGIL_LIB_ED25519 "Build 'ed25519' library" ON)
option(VIRGIL_LIB_RATCHET "Build 'ratchet' library" ON)
option(VIRGIL_LIB_PHE "Build 'phe' library" ON)

#
# Wrappers
#
option(VIRGIL_WRAP_ALL "Build all available wrappers on the given platform" OFF)
option(VIRGIL_WRAP_GO "Build 'Golang' wrapper" OFF)


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
option(VIRGIL_INSTALL_WRAP_STANDALONE "Install each wrapper to separate directory" ON)


# ---------------------------------------------------------------------------
#   Installation paths options
# ---------------------------------------------------------------------------

#
# Use common options from the module 'GNUInstallDirs'.
#
include(GNUInstallDirs)

#
# Define installation options for wrappers.
#
set(VIRGIL_INSTALL_WRAP_PREFIX "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Path where available wrappers will be installed")


# ---------------------------------------------------------------------------
#   Dependencies / thirdparty libraries
# ---------------------------------------------------------------------------

#
# MbedTLS
#
if(VIRGIL_LIB_FOUNDATION OR VIRGIL_LIB_PYTHIA)
    add_subdirectory("thirdparty/mbedtls")
endif()

#
# Pythia
#
if(VIRGIL_LIB_PYTHIA)
    add_subdirectory("thirdparty/pythia")
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


# ---------------------------------------------------------------------------
#   Library core libraries
# ---------------------------------------------------------------------------

if(VIRGIL_LIB_COMMON)
    add_subdirectory("library/common")
endif()

if(VIRGIL_LIB_FOUNDATION)
    add_subdirectory("library/foundation")
endif()

if(VIRGIL_LIB_PYTHIA)
    add_subdirectory("library/pythia")
endif()

if(VIRGIL_LIB_RATCHET)
    add_subdirectory("library/ratchet")
endif()

if(VIRGIL_LIB_PHE)
    add_subdirectory("library/phe")
endif()


# ---------------------------------------------------------------------------
#   Library wrappers
# ---------------------------------------------------------------------------
if(VIRGIL_WRAP_ALL OR VIRGIL_WRAP_GO)
    add_subdirectory("wrappers/go")
endif()


# ---------------------------------------------------------------------------
#   Integration tests
# ---------------------------------------------------------------------------
if(ENABLE_TESTING AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    add_subdirectory(tests)
endif()


# ---------------------------------------------------------------------------
#   Benchmarks
# ---------------------------------------------------------------------------
if(ENABLE_BENCHMARKS AND NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(benchmarks)
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

    add_custom_target(cloc-pythia
            COMMAND ${CLOC_EXECUTABLE}
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/include/virgil/crypto/pythia"
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/include/virgil/crypto/pythia/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/src"
            COMMENT "Calculate lines of the 'pythia' library..."
            )

    add_custom_target(cloc-ratchet
            COMMAND ${CLOC_EXECUTABLE}
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/include/virgil/crypto/pythia"
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/include/virgil/crypto/pythia/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/src"
            COMMENT "Calculate lines of the 'pythia' library..."
            )

    add_custom_target(cloc)
    add_dependencies(cloc cloc-common cloc-foundation cloc-pythia cloc-ratchet)
endif()
