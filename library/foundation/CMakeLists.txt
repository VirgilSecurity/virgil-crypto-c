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
add_library(vsf "")
target_sources(vsf
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_aes256_gcm.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_assert.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_cipher.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_cipher_auth.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_cipher_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_decrypt.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_encrypt.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_error.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_ex_kdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hash.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hash_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hash_stream.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hkdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac256.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac384.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac512.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_hmac_stream.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_kdf.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_kdf1.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_kdf2.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_library.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_memory.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha256.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha384.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/vsf_sha512.h"

        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_aes256_gcm_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_api_private.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_cipher_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_cipher_auth_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_cipher_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_decrypt_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_encrypt_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_ex_kdf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hash_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hash_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hash_stream_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hkdf_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac_info_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac_stream_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac224_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac256_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac384_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_hmac512_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_impl_private.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_kdf1_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_kdf2_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_kdf_api.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha224_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha256_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha384_impl.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/private/vsf_sha512_impl.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_aes256_gcm.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_aes256_gcm_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_aes256_gcm_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_aes256_gcm_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_api_private.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_assert.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_cipher.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_cipher_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_cipher_auth.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_cipher_auth_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_cipher_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_cipher_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_decrypt.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_decrypt_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_encrypt.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_encrypt_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_error.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_stream.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hash_stream_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hkdf.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hkdf_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hkdf_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hkdf_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac224.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac224_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac224_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac224_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac256.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac256_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac256_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac256_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac384.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac384_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac384_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac384_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac512.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac512_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac512_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac512_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac_info.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac_info_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac_stream.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_hmac_stream_api.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_impl_private.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf1_internal.h"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf2.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf2_impl.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf2_internal.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/vsf_kdf2_internal.h"
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


get_target_property(SOURCES vsf SOURCES)
foreach(src ${SOURCES})
    get_filename_component(file_name "${src}" NAME)
    get_filename_component(file_ext "${src}" EXT)

    if(file_ext STREQUAL ".c")
            set_property(SOURCE "${src}" APPEND_STRING PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${file_name}\"")
    endif()
endforeach()


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

#
# Add library alias
#
add_library(vsc::foundation ALIAS vsf)

#
# Format code
#
if(COMMAND add_clangformat)
    add_clangformat(vsf)
endif()
