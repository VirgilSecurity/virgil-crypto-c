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

project(virgil-crypto-common VERSION 0.1.0 LANGUAGES C)


# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Define sources
#
add_library(vsc_common "")
target_sources(vsc_common
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/vsc_assert.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/vsc_buffer.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/vsc_data.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/vsc_error.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/vsc_library.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/vsc_memory.h"

        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/private/vsc_buffer_defs.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/vsc_assert.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsc_buffer.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsc_buffer_defs.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsc_error.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsc_library.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsc_memory.c"
        )

#
# Define include headers
#
target_include_directories(vsc_common
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/common>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/common/private>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
        )


#
# Define specific compilation and linkage flags.
#
set_target_properties(vsc_common PROPERTIES
        C_STANDARD "99"
        DEBUG_POSTFIX "_d"
        )


get_target_property(SOURCES vsc_common SOURCES)
foreach(src ${SOURCES})
    get_filename_component(file_name "${src}" NAME)
    get_filename_component(file_ext "${src}" EXT)

    if(file_ext STREQUAL ".c")
            set_property(SOURCE "${src}" APPEND_STRING PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${file_name}\"")
    endif()
endforeach()


if(TARGET enable_profiling)
    target_link_libraries(vsc_common PUBLIC $<$<CONFIG:Debug>:enable_profiling>)
else()
    message("To enable pythia profiling create target 'enable_profiling'.")
endif()


if(TARGET enable_pedantic)
    target_link_libraries(vsc_common PRIVATE enable_pedantic)
else()
    message("To compile pythia in pedantic mode create target 'enable_pedantic'.")
endif()

#
# Add library alias
#
add_library(vsc::common ALIAS vsc_common)
