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

project(virgil_crypto_php VERSION 0.5.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   PHP wrapper build options
# ---------------------------------------------------------------------------
set(PHP_VERSION "" CACHE STRING "Required exact PHP version. Keep empty to find currently available version.")

if(VIRGIL_INSTALL_WRAP_STANDALONE)
    get_filename_component(PHP_DESTINATION "${VIRGIL_INSTALL_WRAP_PREFIX}/php" ABSOLUTE)
else()
    set(PHP_DESTINATION "${VIRGIL_INSTALL_WRAP_PREFIX}")
endif()

# ---------------------------------------------------------------------------
#   Find PHP module and create target 'php' from it
# ---------------------------------------------------------------------------
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if(PHP_VERSION)
    find_package(PHP ${PHP_VERSION} EXACT REQUIRED)
else()
    find_package(PHP REQUIRED)
endif()

if(NOT PHP_FOUND)
    message(FATAL_ERROR "PHP headers and libraries needed for compiling extensions is not found.")
endif()

if(PHP_LIBRARIES)
    add_library(phplib STATIC IMPORTED)
    set_target_properties(phplib PROPERTIES IMPORTED_IMPLIB "${PHP_LIBRARIES}")
else()
    add_library(phplib INTERFACE IMPORTED)
endif()

target_include_directories(phplib SYSTEM INTERFACE "${PHP_INCLUDE_DIRS}")

if(PHP_DEFINITIONS)
    target_compile_definitions(phplib INTERFACE ${PHP_DEFINITIONS})
endif()

if(PHP_EXECUTABLE)
    message(STATUS "Found PHP (cli): ${PHP_EXECUTABLE} (found version: ${PHP_VERSION})")
else()
    message(WARNING "PHP (cli) is not found - PHP tests will be disabled!")
endif()

if(PHPUNIT_EXECUTABLE)
    message(STATUS "Found PHPUnit: ${PHPUNIT_EXECUTABLE} (found version: ${PHPUNIT_VERSION})")
else()
    message(WARNING "PHPUnit is not found - PHP tests will be disabled!")
endif()


# ---------------------------------------------------------------------------
#   Add per project extension build
# ---------------------------------------------------------------------------
add_subdirectory(pythia)
add_subdirectory(phe)
