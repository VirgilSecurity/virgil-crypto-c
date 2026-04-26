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

# cmake args shared by every liboqs ExternalProject instance.
# CMAKE_INSTALL_LIBDIR is pinned to "lib" to prevent the python-config.cmake
# transitive arg (CMAKE_INSTALL_LIBDIR=_libs) from redirecting the library
# to a path that IMPORTED_LOCATION doesn't expect.
# CMAKE_OSX_ARCHITECTURES is set per-instance (see universal-build section below).
set(_liboqs_cmake_args
    "${TRANSITIVE_ARGS}"
    "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
    "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
    "-DCMAKE_INSTALL_LIBDIR=lib"
    "-DOQS_BUILD_ONLY_LIB=ON"
    "-DOQS_DIST_BUILD=ON"
    # Enable or disable algorithms based on the exposed features.
    "-DOQS_ENABLE_KEM_ML_KEM=${OQS_ENABLE_KEM_ML_KEM}"
    "-DOQS_ENABLE_SIG_ML_DSA=${OQS_ENABLE_SIG_ML_DSA}"
    "-DOQS_ENABLE_SIG_FALCON=${OQS_ENABLE_SIG_FALCON}"
    # Algorithms not supported by Virgil Crypto.
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
    "-DOQS_USE_OPENSSL=OFF"
)

# ---------------------------------------------------------------------------
#   Universal macOS build: build each architecture separately, then lipo-merge.
#
#   liboqs detects architecture via CMAKE_SYSTEM_PROCESSOR (which always reflects
#   the HOST on macOS, not the target). When the host is Apple Silicon (arm64),
#   liboqs sets -march=armv8-a+crypto globally even in OQS_DIST_BUILD mode — that
#   flag is invalid for the x86_64 slice of a universal build.
#
#   Fix: build arm64 and x86_64 separately. For the x86_64 build, generate a
#   minimal toolchain that sets CMAKE_SYSTEM_PROCESSOR=x86_64 so that liboqs
#   detects ARCH_X86_64 instead of ARCH_ARM64v8.
# ---------------------------------------------------------------------------
set(_OQS_UNIVERSAL FALSE)
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    string(FIND "${CMAKE_OSX_ARCHITECTURES}" "arm64" _oqs_has_arm64)
    string(FIND "${CMAKE_OSX_ARCHITECTURES}" "x86_64" _oqs_has_x86_64)
    if(_oqs_has_arm64 GREATER_EQUAL 0 AND _oqs_has_x86_64 GREATER_EQUAL 0)
        set(_OQS_UNIVERSAL TRUE)
    endif()
endif()

if(_OQS_UNIVERSAL)
    # --- arm64 build (native on Apple Silicon — no toolchain override needed) ---
    ExternalProject_Add(liboqs-ext-arm64
            GIT_REPOSITORY
                https://github.com/open-quantum-safe/liboqs
            GIT_TAG
                0.15.0
            SOURCE_DIR
                "${CMAKE_CURRENT_BINARY_DIR}/liboqs-src-arm64"
            CMAKE_ARGS
                ${_liboqs_cmake_args}
                "-DCMAKE_INSTALL_PREFIX=${OQS_INSTALL_LOCATION}/arm64"
                "-DCMAKE_OSX_ARCHITECTURES=arm64"
            BUILD_BYPRODUCTS
                "${OQS_INSTALL_LOCATION}/arm64/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}"
            )

    # --- x86_64 build ---
    # Generate a minimal toolchain that overrides CMAKE_SYSTEM_PROCESSOR so liboqs
    # detects ARCH_X86_64 (not ARCH_ARM64v8) and omits ARM-specific march flags.
    set(_liboqs_x86_toolchain "${CMAKE_CURRENT_BINARY_DIR}/liboqs_x86_64_toolchain.cmake")
    file(WRITE "${_liboqs_x86_toolchain}"
        "set(CMAKE_SYSTEM_NAME Darwin)\n"
        "set(CMAKE_SYSTEM_PROCESSOR x86_64)\n"
        "set(CMAKE_OSX_ARCHITECTURES x86_64)\n"
        "set(CMAKE_OSX_SYSROOT \"${CMAKE_OSX_SYSROOT}\")\n"
        "set(CMAKE_OSX_DEPLOYMENT_TARGET \"${CMAKE_OSX_DEPLOYMENT_TARGET}\")\n"
    )

    ExternalProject_Add(liboqs-ext-x86_64
            GIT_REPOSITORY
                https://github.com/open-quantum-safe/liboqs
            GIT_TAG
                0.15.0
            SOURCE_DIR
                "${CMAKE_CURRENT_BINARY_DIR}/liboqs-src-x86_64"
            CMAKE_ARGS
                ${_liboqs_cmake_args}
                "-DCMAKE_TOOLCHAIN_FILE=${_liboqs_x86_toolchain}"
                "-DCMAKE_INSTALL_PREFIX=${OQS_INSTALL_LOCATION}/x86_64"
                "-DCMAKE_OSX_ARCHITECTURES=x86_64"
            BUILD_BYPRODUCTS
                "${OQS_INSTALL_LOCATION}/x86_64/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}"
            )

    # --- lipo-merge into a universal static library ---
    set(_oqs_universal_lib "${OQS_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}")
    file(MAKE_DIRECTORY "${OQS_INSTALL_LOCATION}/lib")

    add_custom_target(liboqs-ext
            COMMAND lipo -create
                "${OQS_INSTALL_LOCATION}/arm64/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}"
                "${OQS_INSTALL_LOCATION}/x86_64/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}"
                -output "${_oqs_universal_lib}"
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${OQS_INSTALL_LOCATION}/arm64/include"
                "${OQS_INSTALL_LOCATION}/include"
            DEPENDS liboqs-ext-arm64 liboqs-ext-x86_64
            BYPRODUCTS "${_oqs_universal_lib}"
            COMMENT "Merging liboqs arm64 + x86_64 into universal static library"
            VERBATIM
            )

else()
    # --- Single-architecture or non-macOS build ---
    ExternalProject_Add(liboqs-ext
            GIT_REPOSITORY
                https://github.com/open-quantum-safe/liboqs
            GIT_TAG
                0.15.0
            CMAKE_ARGS
                ${_liboqs_cmake_args}
                "-DCMAKE_INSTALL_PREFIX=${OQS_INSTALL_LOCATION}"
            BUILD_BYPRODUCTS
                "${OQS_INSTALL_LOCATION}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}"
            )
endif()

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
