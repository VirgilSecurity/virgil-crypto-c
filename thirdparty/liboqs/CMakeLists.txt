#   Copyright (C) 2015-2026 Virgil Security, Inc.
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

if(NOT OQS_LIBRARY)
    message(STATUS "Skip building library 'liboqs' - option OQS_LIBRARY is OFF.")
endif()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
set(OQS_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/liboqs)

include(ExternalProject)
ExternalProject_Add(liboqs-ext
        GIT_REPOSITORY
            https://github.com/open-quantum-safe/liboqs
        GIT_TAG
            0.15.0
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${OQS_INSTALL_LOCATION}"
            "-DOQS_BUILD_ONLY_LIB=ON"
            # Enable or disable algorithms based on the exposed features.
            "-DOQS_ENABLE_KEM_ML_KEM=${OQS_ENABLE_KEM_ML_KEM}"
            "-DOQS_ENABLE_SIG_ML_DSA=${OQS_ENABLE_SIG_ML_DSA}"
            "-DOQS_ENABLE_SIG_FALCON=${OQS_ENABLE_SIG_FALCON}"
            # Next algorithms are not supported by Virgil Crypto so far.
            "-DOQS_ENABLE_KEM_KYBER=OFF"
            "-DOQS_ENABLE_KEM_FRODOKEM=OFF"
            "-DOQS_ENABLE_KEM_NTRUPRIME=OFF"
            "-DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF"
            "-DOQS_ENABLE_KEM_HQC=OFF"
            "-DOQS_ENABLE_SIG_SPHINCS=OFF"
            "-DOQS_ENABLE_SIG_MAYO=OFF"
            "-DOQS_ENABLE_SIG_CROSS=OFF"
            "-DOQS_ENABLE_SIG_UOV=OFF"
            "-DOQS_ENABLE_SIG_SNOVA=OFF"
            "-DOQS_ENABLE_LIBJADE_KEM_KYBER=OFF"
            "-DOQS_ENABLE_SIG_STFL_XMSS=OFF"
            "-DOQS_ENABLE_SIG_STFL_LMS=OFF"
            # Other disables
            "-DOQS_USE_OPENSSL=OFF"

        BUILD_BYPRODUCTS "${OQS_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}liboqs${CMAKE_STATIC_LIBRARY_SUFFIX}"
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${OQS_INSTALL_LOCATION}/include)

add_library(liboqs STATIC IMPORTED GLOBAL)

add_dependencies(liboqs liboqs-ext)

set_target_properties(liboqs
        PROPERTIES
        IMPORTED_LOCATION
            "${OQS_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${OQS_INSTALL_LOCATION}/include"
        )

# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------
#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${OQS_INSTALL_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            DIRECTORY "${OQS_INSTALL_LOCATION}/lib/"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FILES_MATCHING REGEX "oqs"
            PATTERN "cmake" EXCLUDE
            )
endif()
