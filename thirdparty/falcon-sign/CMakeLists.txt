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

if(NOT FALCON_SIGN_LIBRARY)
    message(STATUS "Skip building library 'falcon-sign' - option FALCON_SIGN_LIBRARY is OFF.")
endif()

# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
find_program(MAKE_EXE NAMES make)

include(ExternalProject)
ExternalProject_Add(falcon-sign-ext
        URL
            https://falcon-sign.info/falcon-20190918.tar.gz
        URL_HASH SHA256=229fca9b3116ca3ff1f0952227419fc8b2ce11ce0be74a6e92a3837bacda19a2
        BUILD_IN_SOURCE TRUE
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ${MAKE_EXE}
        INSTALL_COMMAND ""
        )

# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
set(FALCON_SIGN_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/falcon-sign-ext-prefix/src/falcon-sign-ext")

add_library(falcon-sign OBJECT IMPORTED GLOBAL)

add_dependencies(falcon-sign falcon-sign-ext)

set_property(TARGET falcon-sign
        PROPERTY IMPORTED_OBJECTS
            "${FALCON_SIGN_LOCATION}/codec.o"
            "${FALCON_SIGN_LOCATION}/common.o"
            "${FALCON_SIGN_LOCATION}/falcon.o"
            "${FALCON_SIGN_LOCATION}/fft.o"
            "${FALCON_SIGN_LOCATION}/fpr.o"
            "${FALCON_SIGN_LOCATION}/keygen.o"
            "${FALCON_SIGN_LOCATION}/rng.o"
            "${FALCON_SIGN_LOCATION}/shake.o"
            "${FALCON_SIGN_LOCATION}/sign.o"
            "${FALCON_SIGN_LOCATION}/vrfy.o"
        )

file(MAKE_DIRECTORY "${FALCON_SIGN_LOCATION}")
set_property(TARGET falcon-sign
        PROPERTY INTERFACE_INCLUDE_DIRECTORIES
            "${FALCON_SIGN_LOCATION}"
        )
