#   Copyright (C) 2015-2020 Virgil Security, Inc.
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

project(virgil_crypto_integration_tests VERSION ${virgil_crypto_c_tests_VERSION} LANGUAGES C)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/test_env")


macro(_add_test test)
    add_executable(${test} ${test}.c)
    target_sources(${test} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/test_sdk_utils.h")
    target_add_filename_definitions(${test})
    target_link_libraries(${test} test_utils test_env)
    set_target_properties(${test} PROPERTIES C_STANDARD "99")
    add_test (NAME ${test} COMMAND ${test})
    enable_target_pedantic(${test})
    set_tests_properties(${test} PROPERTIES LABELS "integration")

    if(TARGET vsc::core_sdk)
        target_link_libraries(${test} test_data_core_sdk vsc::core_sdk)
    endif()


    if(TARGET vsc::keyknox_sdk)
        target_link_libraries(${test} vsc::keyknox_sdk)
    endif()

    if(TARGET vsc::comm_kit)
        target_link_libraries(${test} vsc::comm_kit)
        target_sources(${test} PRIVATE
                "${CMAKE_CURRENT_LIST_DIR}/test_comm_kit_utils.h"
                "${CMAKE_CURRENT_LIST_DIR}/test_comm_kit_utils.c"
        )
    endif()


    if(COMMAND add_clangformat AND ENABLE_CLANGFORMAT)
        add_clangformat(${test})
    endif()
endmacro()


if(TARGET vsc::core_sdk)
    _add_test(test_virgil_http_client)
    _add_test(test_cards_service)
endif()



if(TARGET vsc::keyknox_sdk)
    _add_test(test_keyknox_service)
endif()


if(TARGET vsc::comm_kit)
    _add_test(test_comm_kit_messenger)
    _add_test(test_comm_kit_messenger_cloud_fs)
endif()
