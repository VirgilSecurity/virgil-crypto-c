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

project(virgil_crypto_pythia_php VERSION ${virgil_crypto_php_VERSION} LANGUAGES C)


# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------
if(NOT VIRGIL_LIB_PYTHIA)
    message(STATUS "Skip building the PHP wrapper for library Pythia, which is not built.")
    return()
endif()


# ---------------------------------------------------------------------------
#   Create PHP extension library
# ---------------------------------------------------------------------------
add_library(pythia_php SHARED "")
set_target_properties(pythia_php PROPERTIES
        C_STANDARD 99
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME vscp_pythia_php
        PREFIX ""
        VERSION ${virgil_crypto_pythia_php_VERSION}
        SOVERSION ${virgil_crypto_pythia_php_VERSION_MAJOR}
        )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(phe_php PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(phe_php PROPERTIES SUFFIX ".so")
endif()

target_sources(pythia_php
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/extension/vscp_pythia_php.c>
        )

target_link_libraries(pythia_php
    PUBLIC
        vsc::pythia
    PRIVATE
        phplib
        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:-undefined dynamic_lookup>"
    )

# ---------------------------------------------------------------------------
#   Test
# ---------------------------------------------------------------------------
if(ENABLE_TESTING AND VIRGIL_PHP_TESTING AND PHP_EXECUTABLE AND PHPUNIT_EXECUTABLE)
    add_test(
            NAME test_pythia_php
            COMMAND "${PHP_EXECUTABLE}" -d "extension=$<TARGET_FILE:pythia_php>" -d safe_mode=Off "${PHPUNIT_EXECUTABLE}"
                    --include-path "${CMAKE_CURRENT_LIST_DIR}/src" "${CMAKE_CURRENT_LIST_DIR}/tests/PythiaTest.php"
            )
endif()

# ---------------------------------------------------------------------------
#   Install
# ---------------------------------------------------------------------------
if(VIRGIL_INSTALL_WRAP_LIBS)
    install(TARGETS pythia_php
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
            )
endif()

if(VIRGIL_INSTALL_WRAP_SRCS)
    install(
            DIRECTORY
                "${CMAKE_CURRENT_LIST_DIR}/src"
            DESTINATION
                "${VIRGIL_INSTALL_PHP_SRCDIR}/pythia"
            FILES_MATCHING PATTERN
                "*.php"
            )
endif()
