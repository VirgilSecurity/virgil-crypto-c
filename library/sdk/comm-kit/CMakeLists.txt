#   Copyright (C) 2015-2021 Virgil Security, Inc.
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

project(virgil_crypto_c_comm_kit VERSION ${virgil_crypto_VERSION} LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# Virgil Security Library Core SDK
#
if(NOT TARGET vsc::core_sdk)
    message(FATAL_ERROR
            "Required library 'Virgil Security Core SDK' is not found - looking for target 'vsc::core_sdk'.")
endif()

#
# Virgil Security Library Brainkey SDK
#
if(NOT TARGET vsc::brainkey_sdk)
    message(FATAL_ERROR
            "Required library 'Virgil Security Brainkey SDK' is not found - looking for target 'vsc::brainkey_sdk'.")
endif()

#
# Virgil Security Library Keyknox SDK
#
if(NOT TARGET vsc::keyknox_sdk)
    message(FATAL_ERROR
            "Required library 'Virgil Security Keyknox SDK' is not found - looking for target 'vsc::keyknox_sdk'.")
endif()

#
# Options
#
include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

# --------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Internal configuration
#
if(CMAKE_CROSSCOMPILING AND APPLE AND BUILD_APPLE_FRAMEWORKS)
    set(VSSK_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK YES CACHE INTERNAL "")
    set(VSSK_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK YES CACHE INTERNAL "")
    set(VSSK_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK YES CACHE INTERNAL "")
endif()

#
# Library with protobuf models
#
add_subdirectory(protobuf)

#
# Define sources
#
add_library(comm_kit "")
include("${CMAKE_CURRENT_LIST_DIR}/sources.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/definitions.cmake")


#
# Define include headers
#
target_include_directories(comm_kit
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/sdk/keyknox>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/sdk/keyknox/private>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

#
# Link to dependencies
#
target_link_libraries(comm_kit PUBLIC vsc::core_sdk vsc::brainkey_sdk vsc::keyknox_sdk vsc::comm_kit_pb)

#
# Define specific compilation and linkage flags.
#
target_compile_features(comm_kit
        PUBLIC $<IF:$<AND:$<BOOL:${VSCE_HAVE_STDATOMIC_H}>,$<BOOL:${VSCE_MULTI_THREADING}>>,c_std_11,c_std_99>)

set_target_properties(comm_kit PROPERTIES
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vsc_comm_kit
        )

#
# Add __FILENAME__ definition, that handles file name without path, to each source file.
#
get_target_property(SOURCES comm_kit SOURCES)
foreach(src ${SOURCES})
    get_filename_component(file_name "${src}" NAME)
    get_filename_component(file_ext "${src}" EXT)

    if(file_ext STREQUAL ".c")
            set_property(SOURCE "${src}" APPEND_STRING PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${file_name}\"")
    endif()
endforeach()

#
# Enable profiling
#
if(ENABLE_PROFILING)
    if(COMMAND enable_target_profiling)
        enable_target_profiling(comm_kit)
    else()
        message(STATUS "To enable profiling create function 'enable_target_profiling(<target>)'.")
    endif()
endif()

#
# Enable pedantic mode
#
if(COMMAND enable_target_pedantic)
    enable_target_pedantic(comm_kit)
else()
    message(STATUS "To enable pedantic mode create function 'enable_target_pedantic(<target>)'.")
endif()

#
# Add library alias
#
add_library(vsc::comm_kit ALIAS comm_kit)

#
# Format code
#
if(COMMAND add_clangformat AND ENABLE_CLANGFORMAT)
    add_clangformat(comm_kit)
endif()


# ---------------------------------------------------------------------------
#   Apple specific
# ---------------------------------------------------------------------------
if(CMAKE_CROSSCOMPILING AND APPLE AND BUILD_APPLE_FRAMEWORKS AND COMMAND target_apple_framework)
    target_apple_framework(comm_kit
            NAME VSSCommKit
            VERSION "A"
            IDENTIFIER com.virgilsecurity.VSSCommKit
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
            TARGETS comm_kit
            EXPORT vsc_comm_kitTargets
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FRAMEWORK DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
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
            "Config.cmake.in" "vsc_comm_kitConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_comm_kit"
            )

    #
    # Create 'version' config file
    #
    write_basic_package_version_file(
            "vsc_comm_kitConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            )

    #
    # Install all config files
    #
    install(
            FILES
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_comm_kitConfig.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_comm_kitConfigVersion.cmake"
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_comm_kit"
            )

    install(
            EXPORT
                vsc_comm_kitTargets
            NAMESPACE
                vsc::
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_comm_kit"
            )
endif()

