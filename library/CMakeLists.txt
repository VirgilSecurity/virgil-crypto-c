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

project(virgil-crypto-c VERSION 0.1.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# MbedTLS
#
if(NOT TARGET mbed::crypto)
    message(FATAL_ERROR "Require library MbedTLS defined as a target mbed::crypto")
endif()

# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Define sources
#
add_library(vsf "")
target_sources(vsf
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_assert.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hash.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hash_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hash_stream.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_kdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_kdf1.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_library.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_memory.h"
		"${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha256.h"
		"${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha384.h"
		"${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha512.h"

        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_api_private.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hash_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hash_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hash_stream_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_impl_private.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_kdf1_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_kdf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha224_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha256_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha384_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha512_impl.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_api_private.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_assert.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_stream.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_stream_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_impl_private.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_library.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_memory.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha224.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha224_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha224_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha224_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha256.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha256_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha256_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha256_internal.h"
		"${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha384.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha384_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha384_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha384_internal.h"
		"${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha512.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha512_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha512_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_sha512_internal.h"
        )

#
# Define include headers
#
target_include_directories(vsf
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/private>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
        )

#
# Link to dependencies
#
target_link_libraries(vsf PUBLIC mbed::crypto)


#
# Define specific compilation and linkage flags.
#
set_target_properties(vsf PROPERTIES
        C_STANDARD "99"
        DEBUG_POSTFIX "_d"
        )


if(TARGET enable_profiling)
    target_link_libraries(vsf PUBLIC $<$<CONFIG:Debug>:enable_profiling>)
else()
    message("To enable library profiling create target 'enable_profiling'.")
endif()


if(TARGET enable_pedantic)
    target_link_libraries(vsf PRIVATE enable_pedantic)
else()
    message("To compile library in pedantic mode create target 'enable_pedantic'.")
endif()
