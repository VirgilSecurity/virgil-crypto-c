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

project(virgil-crypto-foundation VERSION 0.1.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# MbedTLS
#
if(NOT TARGET mbed::crypto)
    message(FATAL_ERROR "Required library MbedTLS is not found - looking for target 'mbed::crypto'.")
endif()

# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Define sources
#
add_library(vsc_foundation "")
target_sources(vsc_foundation
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_aes256_gcm.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_assert.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_cipher.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_cipher_auth.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_cipher_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_decrypt.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_encrypt.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_error.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_ex_kdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hash.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hash_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hash_stream.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hkdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac256.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac384.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac512.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_hmac_stream.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_kdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_kdf1.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_kdf2.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_library.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_memory.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_sha224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_sha256.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_sha384.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/vscf_sha512.h"

        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_aes256_gcm_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_api_private.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_cipher_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_cipher_auth_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_cipher_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_decrypt_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_encrypt_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_ex_kdf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hash_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hash_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hash_stream_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hkdf_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac_stream_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac224_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac256_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac384_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_hmac512_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_impl_private.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_kdf1_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_kdf2_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_kdf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_sha224_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_sha256_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_sha384_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private/vscf_sha512_impl.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_aes256_gcm.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_aes256_gcm_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_aes256_gcm_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_aes256_gcm_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_api_private.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_assert.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_cipher.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_cipher_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_cipher_auth.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_cipher_auth_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_cipher_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_cipher_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_decrypt.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_decrypt_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_encrypt.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_encrypt_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_error.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash_stream.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash_stream_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hkdf.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hkdf_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hkdf_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hkdf_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac224.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac224_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac224_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac224_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac256.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac256_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac256_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac256_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac384.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac384_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac384_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac384_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac512.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac512_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac512_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac512_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac_stream.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_hmac_stream_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_impl_private.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf1.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf1_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf1_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf1_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf2.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf2_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf2_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf2_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_library.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_memory.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha224.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha224_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha224_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha224_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha256.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha256_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha256_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha256_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha384.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha384_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha384_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha384_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha512.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha512_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha512_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vscf_sha512_internal.h"
        )

#
# Define include headers
#
target_include_directories(vsc_foundation
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/foundation/private>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
        )

#
# Link to dependencies
#
target_link_libraries(vsc_foundation PUBLIC mbed::crypto)


#
# Define specific compilation and linkage flags.
#
set_target_properties(vsc_foundation PROPERTIES
        C_STANDARD "99"
        DEBUG_POSTFIX "_d"
        )


get_target_property(SOURCES vsc_foundation SOURCES)
foreach(src ${SOURCES})
    get_filename_component(file_name "${src}" NAME)
    get_filename_component(file_ext "${src}" EXT)

    if(file_ext STREQUAL ".c")
            set_property(SOURCE "${src}" APPEND_STRING PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${file_name}\"")
    endif()
endforeach()


if(TARGET enable_profiling)
    target_link_libraries(vsc_foundation PUBLIC $<$<CONFIG:Debug>:enable_profiling>)
else()
    message("To enable library profiling create target 'enable_profiling'.")
endif()


if(TARGET enable_pedantic)
    target_link_libraries(vsc_foundation PRIVATE enable_pedantic)
else()
    message("To compile library in pedantic mode create target 'enable_pedantic'.")
endif()

#
# Add library alias
#
add_library(vsc::foundation ALIAS vsc_foundation)

#
# Format code
#
if(COMMAND add_clangformat)
    add_clangformat(vsc_foundation)
endif()
