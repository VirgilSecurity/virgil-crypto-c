#   Copyright (C) 2015-2020 Virgil Security, Inc.
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
set(MBEDTLS_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/mbedtls CACHE PATH INTERNAL)


# ---------------------------------------------------------------------------
#   Create config.h file to be used in the patch step
# ---------------------------------------------------------------------------
if(MBEDTLS_FEATURES_FILE)
    include("${MBEDTLS_FEATURES_FILE}")
endif()

#
# Options
#
include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

set(MBEDTLS_THREADING_PTHREAD OFF)
set(MBEDTLS_THREADING_SRWLOCK OFF)
if(MBEDTLS_THREADING_C)
    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(MBEDTLS_THREADING_SRWLOCK ON)
    else()
        set(MBEDTLS_THREADING_PTHREAD ON)
    endif()
endif()


set(MBEDTLS_ALT_INCLUDE_DIR "" CACHE PATH "Directory with alternative MbedTLS algorithm implementations.")
if(EXISTS "${MBEDTLS_ALT_INCLUDE_DIR}")
    file(GLOB MBEDTLS_ALT_INCLUDE_FILES "${MBEDTLS_ALT_INCLUDE_DIR}/*_alt.h")
else()
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/fake_alt.h" "")
    set(MBEDTLS_ALT_INCLUDE_FILES "${CMAKE_CURRENT_BINARY_DIR}/fake_alt.h")
endif()


#
# File configuration
#
configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/config.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/config.h"
        )


# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)
ExternalProject_Add(mbedtls-ext
        GIT_REPOSITORY
            https://github.com/VirgilSecurity/mbedtls
        GIT_TAG
            virgil-mbedtls-2.14.0-patched
        CMAKE_ARGS
            "${TRANSITIVE_ARGS}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_INSTALL_PREFIX=${MBEDTLS_INSTALL_LOCATION}"
            "-DENABLE_TESTING=OFF"
            "-DENABLE_PROGRAMS=OFF"
        PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_BINARY_DIR}/config.h"
            "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-ext-prefix/src/mbedtls-ext/include/mbedtls/config.h"
        COMMAND ${CMAKE_COMMAND} -E copy
            ${MBEDTLS_ALT_INCLUDE_FILES}
            "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-ext-prefix/src/mbedtls-ext/include/mbedtls"
        BUILD_BYPRODUCTS
            "${MBEDTLS_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mbedcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}"
        )


# Add dependency to the file 'config.h' to trigger patch step each time this file is changed.
ExternalProject_Add_StepDependencies(mbedtls-ext patch "${CMAKE_CURRENT_BINARY_DIR}/config.h")

# Add dependency to the file '*_alt.h' to trigger patch step each time this file is changed.
foreach(alt_file IN LISTS MBEDTLS_ALT_INCLUDE_FILES)
    ExternalProject_Add_StepDependencies(mbedtls-ext patch "${alt_file}")
endforeach()


# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${MBEDTLS_INSTALL_LOCATION}/include)

add_library(mbedcrypto STATIC IMPORTED GLOBAL)

add_dependencies(mbedcrypto mbedtls-ext)

set_target_properties(mbedcrypto
        PROPERTIES
        IMPORTED_LOCATION
            "${MBEDTLS_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mbedcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}"

        INTERFACE_INCLUDE_DIRECTORIES
            "${MBEDTLS_INSTALL_LOCATION}/include"
        )


# ---------------------------------------------------------------------------
#   Alias library alias
# ---------------------------------------------------------------------------
if(NOT TARGET mbed::crypto)
    add_library(mbed::crypto ALIAS mbedcrypto)
endif()


# ---------------------------------------------------------------------------
#   Install library
# ---------------------------------------------------------------------------

#
# Install headers.
#
if(VIRGIL_INSTALL_DEPS_HDRS)
    install(
            DIRECTORY "${MBEDTLS_INSTALL_LOCATION}/include/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            )
endif()

#
# Install libraries.
#
if(VIRGIL_INSTALL_DEPS_LIBS)
    install(
            DIRECTORY "${MBEDTLS_INSTALL_LOCATION}/lib/"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            FILES_MATCHING REGEX "mbedcrypto"
            PATTERN "cmake" EXCLUDE
            )
endif()
