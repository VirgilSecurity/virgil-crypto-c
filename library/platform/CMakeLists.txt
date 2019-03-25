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

project(virgil_crypto_c_platform VERSION ${virgil_crypto_VERSION} LANGUAGES C)

add_library(platform INTERFACE)

if(DEFINED VIRGIL_PLATFORM_HDR)
    if(EXISTS "${VIRGIL_PLATFORM_HDR}")
        get_filename_component(VIRGIL_PLATFORM_HDR_RESOLVED "${VIRGIL_PLATFORM_HDR}" ABSOLUTE BASE_DIR "${CMAKE_BINARY_DIR}")
    else()
        set(VIRGIL_PLATFORM_HDR_RESOLVED "${VIRGIL_PLATFORM_HDR}")
    endif()

    set(VIRGIL_PLATFORM_INCLUDE_STATEMENT "\"${VIRGIL_PLATFORM_HDR_RESOLVED}\"" CACHE STRING "" FORCE)
endif()

if(DEFINED VIRGIL_PLATFORM_INC_DIR)
    target_include_directories(platform INTERFACE $<BUILD_INTERFACE:${VIRGIL_PLATFORM_INC_DIR}>)
endif()

#
# Add definitions.
#
target_compile_definitions(platform
    INTERFACE
        "$<BUILD_INTERFACE:$<$<BOOL:${VIRGIL_PLATFORM_INCLUDE_STATEMENT}>:VIRGIL_PLATFORM_INCLUDE_STATEMENT=${VIRGIL_PLATFORM_INCLUDE_STATEMENT}>>"
        "$<BUILD_INTERFACE:$<$<BOOL:${VIRGIL_PLATFORM_ALLOC}>:VIRGIL_PLATFORM_ALLOC=${VIRGIL_PLATFORM_ALLOC}>>"
        "$<BUILD_INTERFACE:$<$<BOOL:${VIRGIL_PLATFORM_DEALLOC}>:VIRGIL_PLATFORM_DEALLOC=${VIRGIL_PLATFORM_DEALLOC}>>"
    )

#
# Add library alias
#
add_library(vsc::platform ALIAS platform)

# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
include (CMakePackageConfigHelpers)

#
# Install libraries.
#
if(VIRGIL_INSTALL_LIBS)
    install(
            TARGETS platform
            EXPORT vsc_platformTargets
            )
endif()

#
# Install CMake configuration files.
#
if(VIRGIL_INSTALL_CMAKE)
    #
    # Create 'main' config file
    #
    configure_package_config_file (
            "Config.cmake.in" "vsc_platformConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_platform"
            )

    #
    # Create 'version' config file
    #
    write_basic_package_version_file(
            "vsc_platformConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            )

    #
    # Install all config files
    #
    install(
            FILES
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_platformConfig.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_platformConfigVersion.cmake"
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_platform"
            )

    install(
            EXPORT
                vsc_platformTargets
            NAMESPACE
                vsc::
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_platform"
            )
endif()
