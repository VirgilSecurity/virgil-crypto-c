#
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
#

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(virgil_crypto_foundation_php VERSION ${virgil_crypto_php_VERSION} LANGUAGES C)

#---------------------------------------------------------------------------
#   Check dependencies
#---------------------------------------------------------------------------
if(NOT VIRGIL_LIB_FOUNDATION)
    message(STATUS "Skip building the PHP wrapper for library 'foundation', which is not built.")
    return()
endif()

#---------------------------------------------------------------------------
#   Create PHP extension library
#---------------------------------------------------------------------------
add_library(foundation_php SHARED "")
set_target_properties(foundation_php PROPERTIES
        C_STANDARD 99
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vscf_foundation_php
        PREFIX ""
        )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(foundation_php PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(foundation_php PROPERTIES SUFFIX ".so")
endif()

target_sources(foundation_php
        PRIVATE
            $<BUILD_INTERFACE:vscf_foundation_php.c>
        )

target_include_directories(foundation_php
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
        )

target_link_libraries(foundation_php
    PUBLIC
        vsc::foundation
    PRIVATE
        phplib
        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:-undefined dynamic_lookup>"
    )

#---------------------------------------------------------------------------
#   Test
#---------------------------------------------------------------------------
if(ENABLE_TESTING)
    add_custom_target(test_composer_foundation_php ALL
            COMMAND "${COMPOSER_EXECUTABLE}" install
            COMMENT "Running composer install..."
            WORKING_DIRECTORY ${VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR}
            )

    add_test(
            NAME test_foundation_php
            COMMAND "${PHP_EXECUTABLE}"
                    -d "extension=$<TARGET_FILE:foundation_php>"
                    -d safe_mode=Off
                    "${VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR}/vendor/bin/phpunit"
                        --bootstrap
                            "${VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR}/vendor/autoload.php"
                        --include-path
                            "${VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR}/src"
                            "${VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR}/tests/Foundation"
            )
endif()

#---------------------------------------------------------------------------
#   Install
#---------------------------------------------------------------------------
if(VIRGIL_INSTALL_WRAP_LIBS)
    install(TARGETS foundation_php
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
            )
endif()

if(VIRGIL_INSTALL_WRAP_SRCS)
    install(
            DIRECTORY
                "${VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR}/src/"
            DESTINATION
                "${VIRGIL_INSTALL_PHP_SRCDIR}/Foundation"
            FILES_MATCHING PATTERN
                "*.php"
            )
endif()

