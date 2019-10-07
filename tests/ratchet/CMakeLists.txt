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

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(virgil_crypto_c_ratchet_tests VERSION ${virgil_crypto_c_tests_VERSION} LANGUAGES C)

add_subdirectory(data)

macro(_add_test test)
    add_executable(${test} ${test}.c unreliable_msg_producer.c msg_channel.c test_utils_ratchet.c)
    target_add_filename_definitions(${test})
    target_link_libraries(${test} test_utils test_data_ratchet vsc::ratchet)
    set_target_properties(${test} PROPERTIES C_STANDARD "99")
    add_test (NAME ${test} COMMAND ${test})

    if(COMMAND add_clangformat AND ENABLE_CLANGFORMAT)
        add_clangformat(${test})
    endif()

    enable_target_pedantic(${test})
endmacro()

_add_test (test_ratchet_message)
_add_test (test_ratchet_session_integration)
_add_test (test_ratchet_session_serialization)
_add_test (test_ratchet_key_utils)
_add_test (test_ratchet_cipher)
_add_test (test_ratchet_x3dh)
_add_test (test_ratchet_skipped_messages)
_add_test (test_ratchet_keys)
_add_test (test_ratchet_group_message)
_add_test (test_ratchet_group_session_integration)
_add_test (test_ratchet_group_session_integration_serialization)
_add_test (test_ratchet_group_session_change_members)
