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
set(MBEDTLS_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/mbedtls)

# ---------------------------------------------------------------------------
#   Load MbedTLS as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)
ExternalProject_Add(mbedtls-ext
        GIT_REPOSITORY https://github.com/ARMmbed/mbedtls
        GIT_TAG mbedtls-2.9.0
        CMAKE_ARGS
            -G${CMAKE_GENERATOR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_INSTALL_PREFIX=${MBEDTLS_LOCATION}
            -DENABLE_TESTING=OFF
            -DENABLE_PROGRAMS=OFF
        )

# ---------------------------------------------------------------------------
#   Import MbedTLS libary as a target
# ---------------------------------------------------------------------------
add_library(mbedcrypto STATIC IMPORTED GLOBAL)

add_dependencies(mbedcrypto mbedtls-ext)

file(MAKE_DIRECTORY ${MBEDTLS_LOCATION}/include)

set_target_properties(mbedcrypto
        PROPERTIES
        IMPORTED_LOCATION
            "${MBEDTLS_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mbedcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${MBEDTLS_LOCATION}/include"
        )

if(NOT TARGET mbed::crypto)
    add_library(mbed::crypto ALIAS mbedcrypto)
endif()
