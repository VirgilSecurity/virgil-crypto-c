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

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# The root project is LANGUAGES C; the C++ wrapper enables CXX for itself.
project(virgil_crypto_cpp VERSION ${virgil_crypto_VERSION} LANGUAGES CXX)

# ---------------------------------------------------------------------------
#   Third-party dependencies
# ---------------------------------------------------------------------------
# tl::expected is the only external dependency (header-only, CC0). It backs the
# public expected<T, Error> error type and is safe under -fno-exceptions.
# Note: GSL is intentionally NOT used — interface/delegate arguments are passed
# by reference (const T&), which is non-nullable by construction, so gsl::not_null
# is unnecessary.
#
# Pinned to a tag; on CMake >= 3.24 FIND_PACKAGE_ARGS lets a system-installed
# tl-expected satisfy the dependency (find_package first, fetch as fallback) so
# distro packages / find_package consumers don't re-download it.
set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
# Let tl::expected install its own package + headers so it lands in an export set;
# our exported targets reference tl::expected and the Config re-finds it via
# find_dependency(tl-expected).
set(EXPECTED_BUILD_PACKAGE ON CACHE BOOL "" FORCE)
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
    FetchContent_Declare(tl_expected
        GIT_REPOSITORY https://github.com/TartanLlama/expected.git
        GIT_TAG v1.1.0
        FIND_PACKAGE_ARGS NAMES tl-expected
    )
else()
    FetchContent_Declare(tl_expected
        GIT_REPOSITORY https://github.com/TartanLlama/expected.git
        GIT_TAG v1.1.0
    )
endif()
FetchContent_MakeAvailable(tl_expected)

set(VIRGIL_CPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Each wrapper is a header (declarations) + .cpp (definitions) pair, so every library
# is a STATIC target compiling its generated sources. The public headers forward-declare
# the C handles, so consumers do not transitively pull the C library headers.

# ---------------------------------------------------------------------------
#   foundation-cpp
# ---------------------------------------------------------------------------
file(GLOB VIRGIL_FOUNDATION_CPP_SRCS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/foundation/*.cpp")
add_library(foundation-cpp STATIC ${VIRGIL_FOUNDATION_CPP_SRCS})
add_library(virgil::foundation-cpp ALIAS foundation-cpp)
target_include_directories(foundation-cpp PUBLIC
    "$<BUILD_INTERFACE:${VIRGIL_CPP_INCLUDE_DIR}>"
    "$<INSTALL_INTERFACE:include>"
)
target_compile_features(foundation-cpp PUBLIC cxx_std_20)
target_link_libraries(foundation-cpp PUBLIC vsc::foundation tl::expected)

# ---------------------------------------------------------------------------
#   ratchet-cpp / phe-cpp
# ---------------------------------------------------------------------------
# Both depend on foundation types (Random, PrivateKey, PublicKey), so they link
# virgil::foundation-cpp for its headers + include dir, plus their own C library.
file(GLOB VIRGIL_RATCHET_CPP_SRCS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ratchet/*.cpp")
add_library(ratchet-cpp STATIC ${VIRGIL_RATCHET_CPP_SRCS})
add_library(virgil::ratchet-cpp ALIAS ratchet-cpp)
target_compile_features(ratchet-cpp PUBLIC cxx_std_20)
target_link_libraries(ratchet-cpp PUBLIC virgil::foundation-cpp vsc::ratchet tl::expected)

file(GLOB VIRGIL_PHE_CPP_SRCS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/phe/*.cpp")
add_library(phe-cpp STATIC ${VIRGIL_PHE_CPP_SRCS})
add_library(virgil::phe-cpp ALIAS phe-cpp)
target_compile_features(phe-cpp PUBLIC cxx_std_20)
target_link_libraries(phe-cpp PUBLIC virgil::foundation-cpp vsc::phe tl::expected)

# ---------------------------------------------------------------------------
#   Install + CMake package export (find_package + FetchContent parity)
# ---------------------------------------------------------------------------
# The in-tree `virgil::<name>-cpp` ALIASes above serve add_subdirectory/FetchContent
# consumers; install(EXPORT ... NAMESPACE virgil::) gives find_package consumers the
# identical target names. The generated Config re-finds the C libraries and
# tl::expected via find_dependency.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(VIRGIL_INSTALL_LIBS)
    install(TARGETS foundation-cpp ratchet-cpp phe-cpp
        EXPORT VirgilCryptoCppTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )
endif()

if(VIRGIL_INSTALL_HDRS)
    install(DIRECTORY "${VIRGIL_CPP_INCLUDE_DIR}/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )
endif()

if(VIRGIL_INSTALL_CMAKE)
    set(VIRGIL_CPP_CMAKE_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/VirgilCryptoCpp")
    install(EXPORT VirgilCryptoCppTargets
        NAMESPACE virgil::
        DESTINATION "${VIRGIL_CPP_CMAKE_DIR}"
    )
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/VirgilCryptoCppConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/VirgilCryptoCppConfig.cmake"
        INSTALL_DESTINATION "${VIRGIL_CPP_CMAKE_DIR}"
    )
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/VirgilCryptoCppConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/VirgilCryptoCppConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/VirgilCryptoCppConfigVersion.cmake"
        DESTINATION "${VIRGIL_CPP_CMAKE_DIR}"
    )
endif()
