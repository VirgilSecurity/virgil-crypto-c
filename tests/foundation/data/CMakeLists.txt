#   Copyright (C) 2015-2022 Virgil Security, Inc.
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

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(test_data_foundation VERSION ${virgil_crypto_c_foundation_tests_VERSION} LANGUAGES C)

add_library(test_data_foundation "")
target_sources(test_data_foundation
        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_aes256_gcm.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_aes256_cbc.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_asn1.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hkdf.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hmac.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_kdf1.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_kdf2.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_rsa.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_ed25519.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_curve25519.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha224.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha256.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha384.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha512.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_ctr_drbg.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_entropy_accumulator.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_base64.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_pem.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_alg_info_der.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_message_info_der.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_pkcs5_pbkdf2.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_pkcs5_pbes2.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_ecies_envelope.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_ecies.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_recipient_cipher.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_signer_verifier.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_key_provider.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_deterministic_key.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_secp256r1.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_brainkey_server.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_brainkey_client.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_simple_swu.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_group_session.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_message_info.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_falcon.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_round5.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_compound_key.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hybrid_key.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_post_quantum.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_padding_cipher.h"

        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_aes256_gcm.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_aes256_cbc.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_asn1.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hkdf.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hmac.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_kdf1.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_kdf2.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_rsa.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_ed25519.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_curve25519.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha224.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha256.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha384.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha512.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_ctr_drbg.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_entropy_accumulator.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_base64.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_pem.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_alg_info_der.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_message_info_der.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_pkcs5_pbkdf2.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_pkcs5_pbes2.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_ecies_envelope.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_ecies.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_recipient_cipher.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_signer_verifier.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_key_provider.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_deterministic_key.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_secp256r1.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_brainkey_server.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_brainkey_client.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_simple_swu.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_group_session.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_message_info.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_falcon.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_round5.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_compound_key.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hybrid_key.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_post_quantum.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_padding_cipher.c"
        )

target_include_directories(test_data_foundation
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        )

target_link_libraries(test_data_foundation PUBLIC vsc::common)
