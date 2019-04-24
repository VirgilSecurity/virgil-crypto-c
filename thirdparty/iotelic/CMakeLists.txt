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
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(iotelic VERSION 1.0.0 LANGUAGES C)


# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
set(IOTELIC_BSP_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/iotelic)

include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")


# ---------------------------------------------------------------------------
#   Load iotelic BSP as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)
ExternalProject_Add(iotelic-bsp-ext
        GIT_REPOSITORY https://github.com/VirgilSecurity/virgil-iot-bsp.git
        GIT_TAG 33aff2cdfbc4434cfcdd4482a3bf46b5abf55bc9
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        TEST_COMMAND ""
        INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_BINARY_DIR}/iotelic-bsp-ext-prefix/src/iotelic-bsp-ext/iotelic"
            "${IOTELIC_BSP_LOCATION}/include"
        )


# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Define sources
#
add_library(iotelic STATIC "")

add_dependencies(iotelic iotelic-bsp-ext)

target_sources(iotelic
        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/src/iotelic_sp_interface.c"
        )

target_include_directories(iotelic
        PUBLIC
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/sp/bsp/include>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/sp/bsp/driver>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/sp/crypto/inc>"

        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/app>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/bsp>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/gpio>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/compiler/gcc>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/dbglog>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/io_lib>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/os_shim>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/pib>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/pkt>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/plc_lib>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/uart>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/upgrade>"
        "$<BUILD_INTERFACE:${IOTELIC_BSP_LOCATION}/include/ap/inc/utils>"

        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
        )



# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
include (CMakePackageConfigHelpers)

#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY
                "${CMAKE_CURRENT_LIST_DIR}/include/"
                "${IOTELIC_BSP_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            COMPONENT dev
            FILES_MATCHING PATTERN "*.h"
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            TARGETS iotelic
            EXPORT iotelicTargets
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            )
endif()

#
# Install CMake configuration files.
#
if(VIRGIL_INSTALL_DEPS_CMAKE)
    #
    # Create 'main' config file
    #
    configure_package_config_file (
            "Config.cmake.in" "iotelicConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/iotelic"
            )

    #
    # Create 'version' config file
    #
    write_basic_package_version_file(
            "iotelicConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            )

    #
    # Install all config files
    #
    install(
            FILES
                "${CMAKE_CURRENT_BINARY_DIR}/iotelicConfig.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/iotelicConfigVersion.cmake"
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/iotelic"
            )

    install(
            EXPORT
                iotelicTargets
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/iotelic"
            )
endif()
