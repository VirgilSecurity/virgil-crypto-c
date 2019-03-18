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

cmake_minimum_required(VERSION 3.8)

project(pythia VERSION 0.2.2 LANGUAGES C)
set(CMAKE_C_STANDARD 99)

# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# ---------------------------------------------------------------------------
#   Dependencies
# ---------------------------------------------------------------------------

#
# Relic
#
if(NOT TARGET relic)
    message(FATAL_ERROR "Required library 'relic' is not found - looking for target 'relic'.")
endif()

if(RELIC_USE_GMP)
    find_package(GMP REQUIRED)

    if(NOT GMP_FOUND)
        message(FATAL_ERROR "Library GMP is required, but not found.")
    endif()
endif()

# ---------------------------------------------------------------------------
#   Library
# ---------------------------------------------------------------------------
add_library(pythia "")
set_target_properties (pythia PROPERTIES DEBUG_POSTFIX "_d")
set_target_properties (pythia PROPERTIES POSITION_INDEPENDENT_CODE ON)

configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia/pythia_conf.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/include/pythia/pythia_conf.h @ONLY)


target_sources(pythia
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia/pythia.h
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia/pythia_buf.h
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia/pythia_buf_sizes.h
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia/pythia_init.h
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia/pythia_wrapper.h
        ${CMAKE_CURRENT_BINARY_DIR}/include/pythia/pythia_conf.h

        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_buf_exports.h
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_buf_sizes_c.h
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_c.h
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_init_c.h

        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_buf.c
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_buf_exports.c
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_buf_sizes.c
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_c.c
        ${CMAKE_CURRENT_LIST_DIR}/src/pythia_wrapper.c
        )


target_include_directories(pythia
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/pythia>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/pythia>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>
        PUBLIC $<BUILD_INTERFACE:${GMP_INCLUDES}>
        PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(pythia PUBLIC relic)

if(RELIC_USE_GMP AND GMP_FOUND)
    target_link_libraries(pythia PRIVATE ${GMP_LIBRARIES})
endif()

# ---------------------------------------------------------------------------
#   Tests
# ---------------------------------------------------------------------------
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

#
# Enable profiling
#
if(ENABLE_PROFILING)
    if(COMMAND enable_target_profiling)
        enable_target_profiling(pythia)
    else()
        message(STATUS "To enable profiling create function 'enable_target_profiling(<target>)'.")
    endif()
endif()

#
# Enable pedantic mode
#
if(COMMAND enable_target_pedantic)
    enable_target_pedantic(pythia)
else()
    message(STATUS "To enable pedantic mode create function 'enable_target_pedantic(<target>)'.")
endif()

# ---------------------------------------------------------------------------
#   Install
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/pythia-config-version.cmake"
        COMPATIBILITY SameMajorVersion)

configure_package_config_file(
        "${CMAKE_CURRENT_LIST_DIR}/pythia-config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/pythia-config.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pythia")

install(TARGETS pythia EXPORT pythia-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(EXPORT pythia-targets
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pythia"
        COMPONENT dev)

install(FILES
            "${CMAKE_CURRENT_BINARY_DIR}/pythia-config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/pythia-config-version.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pythia"
        COMPONENT dev)

install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT dev
        FILES_MATCHING PATTERN "*.h")

install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT dev
        FILES_MATCHING PATTERN "*.h")
