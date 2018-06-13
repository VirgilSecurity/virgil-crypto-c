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

project(virgil_crypto_c_pythia VERSION 0.2.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# MbedTLS
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

# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Define sources
#
add_library(vsc_pythia "")
target_sources(vsc_pythia
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/vscp_assert.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/vscp_error.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/vscp_library.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/vscp_memory.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/vscp_pythia.h"

        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/private/vscp_pythia_defs.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/vscp_assert.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscp_error.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscp_library.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscp_memory.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscp_pythia.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscp_pythia_defs.c"
        )

#
# Define include headers
#
target_include_directories(vsc_pythia
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/pythia/private>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
        )

#
# Link to dependencies
#
target_link_libraries(vsc_pythia PUBLIC vsc_common mbed::crypto pythia relic)

#
# Define specific compilation and linkage flags.
#
set_target_properties(vsc_pythia PROPERTIES
        C_STANDARD "99"
        DEBUG_POSTFIX "_d"
        )


get_target_property(SOURCES vsc_pythia SOURCES)
foreach(src ${SOURCES})
    get_filename_component(file_name "${src}" NAME)
    get_filename_component(file_ext "${src}" EXT)

    if(file_ext STREQUAL ".c")
            set_property(SOURCE "${src}" APPEND_STRING PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${file_name}\"")
    endif()
endforeach()


if(TARGET enable_profiling)
    target_link_libraries(vsc_pythia PUBLIC $<$<CONFIG:Debug>:enable_profiling>)
else()
    message("To enable pythia profiling create target 'enable_profiling'.")
endif()


if(TARGET enable_pedantic)
    target_link_libraries(vsc_pythia PRIVATE enable_pedantic)
else()
    message("To compile pythia in pedantic mode create target 'enable_pedantic'.")
endif()

#
# Add library alias
#
add_library(vsc::pythia ALIAS vsc_pythia)

#
# Format code
#
if(COMMAND add_clangformat)
    add_clangformat(vsc_pythia)
endif()


# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------

#
# Install binaries
#
install(
        TARGETS vsc_pythia
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        )

#
# Install headers
#
install(
        DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        )

