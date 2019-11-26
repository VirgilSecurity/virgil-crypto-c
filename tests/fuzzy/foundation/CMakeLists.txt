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

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # not using regular Clang or AppleClang

    message(FATAL_ERROR "Expected LLVM clang to use for fuzzy testing")
endif()

macro(_add_test test)
    add_executable(${test}  ${CMAKE_CURRENT_LIST_DIR}/src/${test}.c)
    set_target_properties(${test} PROPERTIES C_STANDARD "99")
    set_target_properties(${test} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${test})
    add_test(NAME ${test} COMMAND ${test})

    target_add_filename_definitions(${test})
    target_link_libraries(${test}
            PRIVATE
                fuzzer_flags_helper
                test_data_foundation
                vsc::foundation
            )

    if(COMMAND add_clangformat)
        add_clangformat(${test})
    endif()
endmacro()

_add_test(fuzzy_test__key_provider__import_public_key)
_add_test(fuzzy_test__key_provider__import_private_key)
_add_test(fuzzy_test__key_asn1_deserializer__deserialize_public_key)
_add_test(fuzzy_test__key_asn1_deserializer__deserialize_private_key)
_add_test(fuzzy_test__alg_info_der_deserializer__alg_info_der_deserialize)
_add_test(fuzzy_test__recipient_cipher__ed25519_decrypt_message)

