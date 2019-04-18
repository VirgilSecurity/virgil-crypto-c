#   Copyright (C) 2015-2019 Virgil Security Inc.
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

project(virgil_crypto_ratchet_java VERSION ${virgil_crypto_java_VERSION} LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------
if(NOT VIRGIL_LIB_RATCHET)
    message(STATUS "Skip building the Java wrapper for library Ratchet, which is not built.")
    return()
endif()


# ---------------------------------------------------------------------------
#   Create Java extension library
# ---------------------------------------------------------------------------
add_library(ratchet_java SHARED "")
set_target_properties(ratchet_java PROPERTIES
        C_STANDARD 99
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vscr_ratchet_java
        )

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(ratchet_java PROPERTIES SUFFIX ".so")
endif()

target_sources(ratchet_java
        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/jni/RatchetJNI.h"
            "${CMAKE_CURRENT_LIST_DIR}/jni/RatchetJNI.c"
        )

target_link_libraries(ratchet_java
    PUBLIC
        vsc::ratchet
    PRIVATE
        jni vsc::ratchet
    )

# ---------------------------------------------------------------------------
#   Install
# ---------------------------------------------------------------------------
if(VIRGIL_INSTALL_WRAP_LIBS)
    install(TARGETS ratchet_java
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
            )
endif()
