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

project(virgil_crypto_c_ratchet_pb VERSION ${virgil_crypto_c_ratchet_VERSION} LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# protobuf-nanopb
#
if(NOT TARGET protobuf-nanopb)
    message(FATAL_ERROR
            "Required library 'protobuf-nanopb' is not found - looking for target 'protobuf-nanopb'.")
endif()

if(NOT COMMAND target_protobuf_sources)
    message(FATAL_ERROR
            "Required function 'target_protobuf_sources' is not found. "
            "This function adds protobuf generted sources to the target based on the given models.")
endif()

# --------------------------------------------------------------------------
#   Define library with protobuf models
# ---------------------------------------------------------------------------
add_library(ratchet_pb STATIC "")

target_include_directories(ratchet_pb
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

set_target_properties(ratchet_pb PROPERTIES
        C_STANDARD "99"
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vsc_ratchet_pb
        )

target_protobuf_sources(ratchet_pb
        "${CMAKE_CURRENT_SOURCE_DIR}/RatchetMessage.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/RatchetSession.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/RatchetGroupMessage.proto"
        )

target_link_libraries(ratchet_pb nanopb::protobuf-nanopb)

#
# Proxy COMPILE_DEFINITIONS of the library protobuf-nanopb.
#
get_target_property(NANOPB_COMPILE_DEFINITIONS protobuf-nanopb INTERFACE_COMPILE_DEFINITIONS)
if(NANOPB_COMPILE_DEFINITIONS)
    set_target_properties(ratchet_pb PROPERTIES
            COMPILE_DEFINITIONS "${NANOPB_COMPILE_DEFINITIONS}"
            INTERFACE_COMPILE_DEFINITIONS "${NANOPB_COMPILE_DEFINITIONS}"
            )
endif()


#
# Add library alias
#
add_library(vsc::ratchet_pb ALIAS ratchet_pb)

# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
include (CMakePackageConfigHelpers)

#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/virgil/crypto/ratchet"
            FILES_MATCHING PATTERN "*.h"
            PATTERN "CMakeFiles" EXCLUDE
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            TARGETS ratchet_pb
            EXPORT vsc_ratchet_pbTargets
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FRAMEWORK DESTINATION "${CMAKE_INSTALL_LIBDIR}"
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
            "Config.cmake.in" "vsc_ratchet_pbConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_ratchet_pb"
            )

    #
    # Create 'version' config file
    #
    write_basic_package_version_file(
            "vsc_ratchet_pbConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            )

    #
    # Install all config files
    #
    install(
            FILES
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_ratchet_pbConfig.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/vsc_ratchet_pbConfigVersion.cmake"
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_ratchet_pb"
            )

    install(
            EXPORT
                vsc_ratchet_pbTargets
            NAMESPACE
                vsc::
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/cmake/vsc_ratchet_pb"
            )
endif()

