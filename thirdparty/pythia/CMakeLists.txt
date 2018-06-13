#   Copyright (c) 2015-2017 Virgil Security Inc.
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
set(PYTHIA_INSTALL_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/pythia")
set(PYTHIA_SRC_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/pythia-ext-prefix/src/pythia-ext/src")

# ---------------------------------------------------------------------------
#   Load MbedTLS as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)
ExternalProject_Add(pythia-ext
        GIT_REPOSITORY https://github.com/VirgilSecurity/pythia
        GIT_TAG 0.2.1-alpha
        CMAKE_ARGS
            -G${CMAKE_GENERATOR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_INSTALL_PREFIX=${PYTHIA_INSTALL_LOCATION}
            -DENABLE_TESTING=OFF
            -DRELIC_USE_PTHREAD=ON
            -DRELIC_USE_EXT_RNG=ON
        )

# ---------------------------------------------------------------------------
#   Import MbedTLS libary as a target
# ---------------------------------------------------------------------------
add_library(pythia STATIC IMPORTED GLOBAL)
add_library(relic STATIC IMPORTED GLOBAL)

add_dependencies(pythia pythia-ext)

file(MAKE_DIRECTORY ${PYTHIA_INSTALL_LOCATION}/include)
file(MAKE_DIRECTORY ${PYTHIA_SRC_LOCATION})

set_target_properties(pythia
        PROPERTIES
        IMPORTED_LOCATION
            "${PYTHIA_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}pythia${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${PYTHIA_INSTALL_LOCATION}/include"
        )

set_property(TARGET pythia
        APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${PYTHIA_SRC_LOCATION}"
        )

set_target_properties(relic
        PROPERTIES
        IMPORTED_LOCATION
            "${PYTHIA_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}relic_s${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${PYTHIA_INSTALL_LOCATION}/include"
        )
