#
# Copyright (C) 2015-2018 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
set(RELIC_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/relic)
set(RELIC_ARGS_FILE ${CMAKE_CURRENT_LIST_DIR}/relic-args.cmake)

if(RELIC_USE_GMP)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DARITH=gmp)
endif()

if(RELIC_USE_PTHREAD)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DERRMO=ERRMO_SPTHREAD)
endif()

if(RELIC_USE_EXT_RNG)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DRAND=CALL)
endif()

if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND RELIC_CMAKE_ARGS "-DCMAKE_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE}")
endif()

# ---------------------------------------------------------------------------
#   Load relic as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)
ExternalProject_Add(relic-ext
        GIT_REPOSITORY https://github.com/VirgilSecurity/relic
        GIT_TAG c16932f83899f06acd28304a1ce49e9602409a8d
        CMAKE_ARGS
                -G${CMAKE_GENERATOR}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_INSTALL_PREFIX=${RELIC_LOCATION} ${RELIC_CMAKE_ARGS}
                -C "${RELIC_ARGS_FILE}" -C "${TRANSITIVE_ARGS_FILE}")

# ---------------------------------------------------------------------------
#   Import relic libary as a target
# ---------------------------------------------------------------------------
add_library(relic STATIC IMPORTED GLOBAL)
add_dependencies(relic relic-ext)
file(MAKE_DIRECTORY ${RELIC_LOCATION}/include)
set_target_properties(relic PROPERTIES
        IMPORTED_LOCATION ${RELIC_LOCATION}/lib/librelic_s.a
        INTERFACE_INCLUDE_DIRECTORIES ${RELIC_LOCATION}/include)

# ---------------------------------------------------------------------------
#   Install
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/relic-config-version.cmake"
        VERSION 0.4.0
        COMPATIBILITY SameMajorVersion)

configure_package_config_file(
        "${CMAKE_CURRENT_LIST_DIR}/relic-config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/relic-config.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/relic")

configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/relic-targets-release.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/relic-targets-release.cmake"
        @ONLY)


install(FILES ${RELIC_LOCATION}/lib/librelic_s.a DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES
            "${CMAKE_CURRENT_BINARY_DIR}/relic-config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/relic-config-version.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/relic-targets-release.cmake"
            "${CMAKE_CURRENT_LIST_DIR}/relic-targets.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/relic"
        COMPONENT dev)

install(DIRECTORY "${RELIC_LOCATION}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT dev
        FILES_MATCHING PATTERN "*.h")
