#   Copyright (C) 2015-2021 Virgil Security, Inc.
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

project(test_env VERSION 0.0.1 LANGUAGES C)

set(VIRGIL_INTEGRATION_ENV "PROD" CACHE STRING "Environment for inetgration tests {prod, stg, dev}.")
string(TOLOWER "${VIRGIL_INTEGRATION_ENV}" VIRGIL_INTEGRATION_ENV_LOWER)


set(VIRGIL_INTEGRATION_ENV_FILE "${CMAKE_CURRENT_LIST_DIR}/../env.json")
if(NOT EXISTS "${VIRGIL_INTEGRATION_ENV_FILE}")
    message(FATAL_ERROR "Can not find env file: ${VIRGIL_INTEGRATION_ENV_FILE}")
endif()


if(NOT TARGET vsc::foundation)
    message(FATAL_ERROR "Required library 'common' is not found - looking for target 'vsc::common'.")
    message(FATAL_ERROR "Required library 'foundation' is not found - looking for target 'vsc::foundation'.")
endif()


add_library(test_env test_env.h test_env.c)
target_link_libraries(test_env PUBLIC vsc::common vsc::foundation vsc::core_sdk)
target_compile_definitions(test_env
        PRIVATE
            VIRGIL_INTEGRATION_ENV="${VIRGIL_INTEGRATION_ENV_LOWER}"
            VIRGIL_INTEGRATION_ENV_FILE="${VIRGIL_INTEGRATION_ENV_FILE}"
            VIRGIL_INTEGRATION_ENV_FILE_PWD="${VIRGIL_INTEGRATION_ENV_FILE_PWD}"
        )

set_target_properties(test_env PROPERTIES C_STANDARD "99")

target_include_directories(test_env
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
        )

if(COMMAND add_clangformat AND ENABLE_CLANGFORMAT)
    add_clangformat(test_env)
endif()
