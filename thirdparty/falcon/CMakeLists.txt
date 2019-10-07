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


# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

if(NOT FALCON_LIBRARY)
    message(STATUS "Skip building library 'falcon' - option FALCON_LIBRARY is OFF.")
endif()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
set(FALCON_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/falcon)


include(ExternalProject)
ExternalProject_Add(falcon-ext
        URL
            https://falcon-sign.info/falcon-20190918.tar.gz
        URL_HASH
            SHA256=229fca9b3116ca3ff1f0952227419fc8b2ce11ce0be74a6e92a3837bacda19a2
        PATCH_COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_LIST_DIR}/falcon.CMakeLists.txt <SOURCE_DIR>/CMakeLists.txt
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${FALCON_INSTALL_LOCATION}"
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${FALCON_INSTALL_LOCATION}/include)

add_library(falcon STATIC IMPORTED GLOBAL)

add_dependencies(falcon falcon-ext)

set_target_properties(falcon
        PROPERTIES
        IMPORTED_LOCATION
            "${FALCON_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}falcon${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${FALCON_INSTALL_LOCATION}/include"
        )
