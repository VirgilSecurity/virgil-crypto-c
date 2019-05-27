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

project(virgil_crypto_foundation_wasm VERSION ${virgil_crypto_VERSION} LANGUAGES C)


# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------
if(NOT VIRGIL_LIB_FOUNDATION)
    message(STATUS "Skip building the WebAssembly wrapper for library Foundation, which is not built.")
    return()
endif()


# ---------------------------------------------------------------------------
#   Create WebAssembly library
# ---------------------------------------------------------------------------
add_custom_target(foundation_wasm ALL
        COMMAND "${CMAKE_C_COMPILER}"
                -s EXPORTED_FUNCTIONS="@${CMAKE_CURRENT_LIST_DIR}/exported_functions.json"
                -s MODULARIZE=1
                -s EXPORT_NAME=FoundationModule
                "$<$<CONFIG:Release>:--llvm-lto;1;-Os;--closure;1;-s;USE_CLOSURE_COMPILER=1>"
                $<$<CONFIG:Debug>:--emrun>
                $<TARGET_FILE:common>
                $<TARGET_FILE:foundation>
                $<TARGET_FILE:mbedcrypto>
                $<TARGET_FILE:ed25519>
                -o libfoundation.js
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CMAKE_CURRENT_LIST_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}"
        COMMAND_EXPAND_LISTS
        DEPENDS foundation
        COMMENT "Create WASM+JS for the library foundation."
        )

# ---------------------------------------------------------------------------
#   Produce additional info suitable for debug
# ---------------------------------------------------------------------------
find_host_program(WASM2WAT wasm2wat)
if(WASM2WAT)
    add_custom_target(foundation_wat ALL
            COMMAND "${WASM2WAT}" libfoundation.wasm -o libfoundation.wat
            DEPENDS foundation_wasm
            COMMENT "Create WAT for the library foundation."
            )
endif()
