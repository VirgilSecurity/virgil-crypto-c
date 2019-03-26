#   @license
#   -------------------------------------------------------------------------
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
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#   -------------------------------------------------------------------------

#   @warning
#   -------------------------------------------------------------------------
#   This file is fully generated by script 'cmake_files_codegen.gsl'.
#   It can be changed temporary for debug purposes only.
#   -------------------------------------------------------------------------
#   @end


include_guard()

if(NOT TARGET foundation)
    message(FATAL_ERROR "Expected target 'foundation' to be defined first.")
endif()

configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_platform.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/include/virgil/crypto/foundation/vscf_platform.h"
        )

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_assert.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_library.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_memory.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_BINARY_DIR}/include/virgil/crypto/foundation/vscf_platform.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_api.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_impl.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_alg.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_alg_info.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_hash.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_kdf.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_key.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_mac.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_private_key.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_public_key.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_sign_hash.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_verify_hash.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_hmac.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_kdf2.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_private_key.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_public_key.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_sha256.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_sha384.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_sha512.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_error.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_status.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

set_property(
    SOURCE "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_alg_id.h"
    PROPERTY MACOSX_PACKAGE_LOCATION "Headers"
)

target_sources(foundation
    PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_assert.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_library.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_memory.h"
            "${CMAKE_CURRENT_BINARY_DIR}/include/virgil/crypto/foundation/vscf_platform.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_api.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_api_private.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_impl.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_impl_private.h"
            "$<$<BOOL:${VSCF_ALG}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_alg.h>"
            "$<$<BOOL:${VSCF_ALG}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_alg_api.h>"
            "$<$<BOOL:${VSCF_ALG_INFO}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_alg_info.h>"
            "$<$<BOOL:${VSCF_ALG_INFO}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_alg_info_api.h>"
            "$<$<BOOL:${VSCF_HASH}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_hash.h>"
            "$<$<BOOL:${VSCF_HASH}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_hash_api.h>"
            "$<$<BOOL:${VSCF_KDF}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_kdf.h>"
            "$<$<BOOL:${VSCF_KDF}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_kdf_api.h>"
            "$<$<BOOL:${VSCF_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_key.h>"
            "$<$<BOOL:${VSCF_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_key_api.h>"
            "$<$<BOOL:${VSCF_MAC}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_mac.h>"
            "$<$<BOOL:${VSCF_MAC}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_mac_api.h>"
            "$<$<BOOL:${VSCF_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_private_key.h>"
            "$<$<BOOL:${VSCF_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_private_key_api.h>"
            "$<$<BOOL:${VSCF_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_public_key.h>"
            "$<$<BOOL:${VSCF_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_public_key_api.h>"
            "$<$<BOOL:${VSCF_SIGN_HASH}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_sign_hash.h>"
            "$<$<BOOL:${VSCF_SIGN_HASH}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_sign_hash_api.h>"
            "$<$<BOOL:${VSCF_VERIFY_HASH}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_verify_hash.h>"
            "$<$<BOOL:${VSCF_VERIFY_HASH}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_verify_hash_api.h>"
            "$<$<BOOL:${VSCF_IOTELIC_HMAC}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_hmac.h>"
            "$<$<BOOL:${VSCF_IOTELIC_HMAC}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_hmac_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_HMAC}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_hmac_defs.h>"
            "$<$<BOOL:${VSCF_IOTELIC_KDF2}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_kdf2.h>"
            "$<$<BOOL:${VSCF_IOTELIC_KDF2}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_kdf2_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_KDF2}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_kdf2_defs.h>"
            "$<$<BOOL:${VSCF_IOTELIC_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_private_key.h>"
            "$<$<BOOL:${VSCF_IOTELIC_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_private_key_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_private_key_defs.h>"
            "$<$<BOOL:${VSCF_IOTELIC_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_public_key.h>"
            "$<$<BOOL:${VSCF_IOTELIC_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_public_key_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_public_key_defs.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA256}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_sha256.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA256}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha256_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA256}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_sha256_defs.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA384}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_sha384.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA384}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha384_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA384}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_sha384_defs.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA512}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_iotelic_sha512.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA512}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha512_internal.h>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA512}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private/vscf_iotelic_sha512_defs.h>"
            "$<$<BOOL:${VSCF_ERROR}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_error.h>"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_status.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/vscf_alg_id.h"

            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_assert.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_library.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_memory.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_api.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_api_private.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_impl.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_impl_private.c"
            "$<$<BOOL:${VSCF_ALG}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_alg.c>"
            "$<$<BOOL:${VSCF_ALG}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_alg_api.c>"
            "$<$<BOOL:${VSCF_ALG_INFO}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_alg_info.c>"
            "$<$<BOOL:${VSCF_ALG_INFO}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_alg_info_api.c>"
            "$<$<BOOL:${VSCF_HASH}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash.c>"
            "$<$<BOOL:${VSCF_HASH}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_hash_api.c>"
            "$<$<BOOL:${VSCF_KDF}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf.c>"
            "$<$<BOOL:${VSCF_KDF}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_kdf_api.c>"
            "$<$<BOOL:${VSCF_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_key.c>"
            "$<$<BOOL:${VSCF_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_key_api.c>"
            "$<$<BOOL:${VSCF_MAC}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_mac.c>"
            "$<$<BOOL:${VSCF_MAC}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_mac_api.c>"
            "$<$<BOOL:${VSCF_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_private_key.c>"
            "$<$<BOOL:${VSCF_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_private_key_api.c>"
            "$<$<BOOL:${VSCF_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_public_key.c>"
            "$<$<BOOL:${VSCF_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_public_key_api.c>"
            "$<$<BOOL:${VSCF_SIGN_HASH}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_sign_hash.c>"
            "$<$<BOOL:${VSCF_SIGN_HASH}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_sign_hash_api.c>"
            "$<$<BOOL:${VSCF_VERIFY_HASH}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_verify_hash.c>"
            "$<$<BOOL:${VSCF_VERIFY_HASH}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_verify_hash_api.c>"
            "$<$<BOOL:${VSCF_IOTELIC_HMAC}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_hmac.c>"
            "$<$<BOOL:${VSCF_IOTELIC_HMAC}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_hmac_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_HMAC}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_hmac_defs.c>"
            "$<$<BOOL:${VSCF_IOTELIC_KDF2}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_kdf2.c>"
            "$<$<BOOL:${VSCF_IOTELIC_KDF2}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_kdf2_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_KDF2}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_kdf2_defs.c>"
            "$<$<BOOL:${VSCF_IOTELIC_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_private_key.c>"
            "$<$<BOOL:${VSCF_IOTELIC_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_private_key_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_PRIVATE_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_private_key_defs.c>"
            "$<$<BOOL:${VSCF_IOTELIC_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_public_key.c>"
            "$<$<BOOL:${VSCF_IOTELIC_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_public_key_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_PUBLIC_KEY}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_public_key_defs.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA256}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha256.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA256}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha256_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA256}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha256_defs.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA384}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha384.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA384}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha384_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA384}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha384_defs.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA512}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha512.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA512}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha512_internal.c>"
            "$<$<BOOL:${VSCF_IOTELIC_SHA512}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_iotelic_sha512_defs.c>"
            "$<$<BOOL:${VSCF_ERROR}>:${CMAKE_CURRENT_LIST_DIR}/src/vscf_error.c>"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_status.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/vscf_alg_id.c"
        )

target_include_directories(foundation
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/virgil/crypto/foundation/private>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/virgil/crypto/foundation>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/virgil/crypto/foundation/private>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )
