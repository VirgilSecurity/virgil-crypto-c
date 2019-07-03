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

project(virgil_crypto_c_phe VERSION ${virgil_crypto_VERSION} LANGUAGES C)

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
# Virgil Security Library Foundation
#
if(NOT TARGET vsc::foundation)
    message(FATAL_ERROR
            "Required library 'Virgil Security Crypto Foundation' is not found - looking for target 'vsc::foundation'.")
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
if(CMAKE_CROSSCOMPILING AND APPLE)
    set(VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK YES CACHE INTERNAL "")
    set(VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK YES CACHE INTERNAL "")
endif()

#
# Library with protobuf models
#
add_subdirectory(protobuf)

#
# Define sources
#
add_library(phe "")
include("${CMAKE_CURRENT_LIST_DIR}/sources.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/definitions.cmake")


#
# Define include headers
#
target_include_directories(phe
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/phe>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/phe/private>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

#
# Link to dependencies
#
target_link_libraries(phe PUBLIC vsc::phe_pb vsc::common vsc::foundation)

#
# Define specific compilation and linkage flags.
#
target_compile_features(phe
        PUBLIC $<IF:$<AND:$<BOOL:${VSCE_HAVE_STDATOMIC_H}>,$<BOOL:${VSCE_MULTI_THREADING}>>,c_std_11,c_std_99>)

set_target_properties(phe PROPERTIES
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vsc_phe
        )

#
# Add __FILENAME__ definition, that handles file name without path, to each source file.
#
get_target_property(SOURCES phe SOURCES)
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
        enable_target_profiling(phe)
    else()
        message(STATUS "To enable profiling create function 'enable_target_profiling(<target>)'.")
    endif()
endif()

#
# Enable pedantic mode
#
if(COMMAND enable_target_pedantic)
    enable_target_pedantic(phe)
else()
    message(STATUS "To enable pedantic mode create function 'enable_target_pedantic(<target>)'.")
endif()

#
# Add library alias
#
add_library(vsc::phe ALIAS phe)

#
# Format code
#
if(COMMAND add_clangformat AND ENABLE_CLANGFORMAT)
    add_clangformat(phe)
endif()


# ---------------------------------------------------------------------------
#   Apple specific
# ---------------------------------------------------------------------------
if(CMAKE_CROSSCOMPILING AND APPLE AND COMMAND target_apple_framework)
    target_apple_framework(phe
            NAME VSCPhe
            VERSION "A"
            IDENTIFIER com.virgilsecurity.VSCPhe
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
            TARGETS phe
            EXPORT vsc_pheTargets
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
            "Config.cmake.in" "vsc_pheConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_phe"
            )

    #
    # Create 'version' config file
    #
    write_basic_package_version_file(
            "vsc_pheConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            )

    #
    # Install all config files
    #
    install(
            FILES
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_pheConfig.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_pheConfigVersion.cmake"
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_phe"
            )

    install(
            EXPORT
                vsc_pheTargets
            NAMESPACE
                vsc::
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_phe"
            )
endif()

