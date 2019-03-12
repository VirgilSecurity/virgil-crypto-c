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

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(virgil_crypto_c_foundation_tests VERSION ${virgil_crypto_c_tests_VERSION} LANGUAGES C)

add_subdirectory(data)

macro(_add_test test)
    add_executable(${test} ${test}.c)
    target_add_filename_definitions(${test})
    target_compile_definitions(${test} PRIVATE "ENABLE_HEAVY_TESTS=$<BOOL:${ENABLE_HEAVY_TESTS}>")
    target_link_libraries(${test} unity test_utils test_data_foundation vsc::foundation)
    set_target_properties(${test} PROPERTIES C_STANDARD "99")
    add_test (NAME ${test} COMMAND ${test})

    if(COMMAND add_clangformat)
        add_clangformat(${test})
    endif()
endmacro()

_add_test (test_hkdf)
_add_test (test_kdf1)
_add_test (test_kdf2)
_add_test (test_sha224)
_add_test (test_sha256)
_add_test (test_sha384)
_add_test (test_sha512)
_add_test (test_hmac)
_add_test (test_aes256_gcm)
_add_test (test_aes256_cbc)
_add_test (test_asn1rd)
_add_test (test_asn1wr)
_add_test (test_rsa_public_key)
_add_test (test_rsa_private_key)
_add_test (test_ctr_drbg)
_add_test (test_entropy_accumulator)
_add_test (test_pkcs8_der_serializer)
_add_test (test_pkcs8_der_deserializer)
_add_test (test_base64)
_add_test (test_pem)
_add_test (test_pkcs8_serializer)
_add_test (test_pkcs8_deserializer)
_add_test (test_ed25519_private_key)
_add_test (test_ed25519_public_key)
_add_test (test_alg_info_der_serializer)
_add_test (test_alg_info_der_deserializer)
_add_test (test_message_info_der_serializer)
_add_test (test_pkcs5_pbkdf2)
_add_test (test_pkcs5_pbes2)
_add_test (test_ecies_envelope)
_add_test (test_ecies)
_add_test (test_recipient_cipher)
_add_test (test_key_provider)
_add_test (test_signer)
_add_test (test_verifier)
_add_test (test_x25519_private_key)
_add_test (test_x25519_public_key)
