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

project(virgil_crypto_c_pythia VERSION ${virgil_crypto_VERSION} LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# Virgil Security Library Common
#
if(NOT TARGET vsc::common)
    message(FATAL_ERROR
            "Required library 'Virgil Security Crypto Common' is not found - looking for target 'vsc::common'.")
endif()

#
# MbedTLS
#
if(NOT TARGET mbed::crypto)
    message(FATAL_ERROR "Required library 'MbedTLS' is not found - looking for target 'mbed::crypto'.")
endif()

#
# Pythia
#
if(NOT TARGET pythia)
    message(FATAL_ERROR "Required library 'pythia' is not found - looking for target 'pythia'.")
endif()

#
# Relic
#
if(NOT TARGET relic)
    message(FATAL_ERROR "Required library 'relic' is not found - looking for target 'relic'.")
endif()

#
# Options
#
include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Internal configuration
#
if(CMAKE_CROSSCOMPILING AND APPLE)
    set(VSCP_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK YES CACHE INTERNAL "")
endif()

#
# Define sources
#
add_library(pythia_wrap "")
include("${CMAKE_CURRENT_LIST_DIR}/sources.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/definitions.cmake")

#
# Link to dependencies
#
target_link_libraries(pythia_wrap PUBLIC vsc::common mbed::crypto pythia relic)

#
# Define specific compilation and linkage flags.
#
set_target_properties(pythia_wrap PROPERTIES
        C_STANDARD "99"
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vsc_pythia
        )

#
# Add __FILENAME__ definition, that handles file name without path, to each source file.
#
target_add_filename_definitions(pythia_wrap)

#
# Enable profiling
#
if(ENABLE_PROFILING)
    if(COMMAND enable_target_profiling)
        enable_target_profiling(pythia_wrap)
    else()
        message(STATUS "To enable profiling create function 'enable_target_profiling(<target>)'.")
    endif()
endif()

#
# Enable pedantic mode
#
if(COMMAND enable_target_pedantic)
    enable_target_pedantic(pythia_wrap)
else()
    message(STATUS "To enable pedantic mode create function 'enable_target_pedantic(<target>)'.")
endif()

#
# Add library alias
#
add_library(vsc::pythia ALIAS pythia_wrap)

#
# Format code
#
if(COMMAND add_clangformat)
    add_clangformat(pythia_wrap)
endif()


# ---------------------------------------------------------------------------
#   Apple specific
# ---------------------------------------------------------------------------
if(CMAKE_CROSSCOMPILING AND APPLE AND COMMAND target_apple_framework)
    target_apple_framework(pythia_wrap
            NAME VSCPythia
            VERSION "A"
            IDENTIFIER com.virgilsecurity.VSCPythia
            )
endif()


# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
include (CMakePackageConfigHelpers)

#
# Install headers.
#
if(VIRGIL_INSTALL_HDRS)
    install(
            DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/" "${CMAKE_CURRENT_BINARY_DIR}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            PATTERN "*.h.in" EXCLUDE
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_LIBS)
    install(
            TARGETS pythia_wrap
            EXPORT vsc_pythiaTargets
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FRAMEWORK DESTINATION "${CMAKE_INSTALL_LIBDIR}"
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
            "Config.cmake.in" "vsc_pythiaConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_pythia"
            )

    #
    # Create 'version' config file
    #
    write_basic_package_version_file(
            "vsc_pythiaConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            )

    #
    # Install all config files
    #
    install(
            FILES
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_pythiaConfig.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_pythiaConfigVersion.cmake"
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_pythia"
            )

    install(
            EXPORT
                vsc_pythiaTargets
            NAMESPACE
                vsc::
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_pythia"
            )
endif()

