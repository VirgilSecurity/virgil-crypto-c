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

project(virgil_crypto_php VERSION ${virgil_crypto_VERSION} LANGUAGES C)

set(VIRGIL_CRYPTO_WRAPPER_PROJECT_DIR "${CMAKE_CURRENT_LIST_DIR}/VirgilCryptoWrapper")

# ---------------------------------------------------------------------------
#   PHP wrapper build and install options
# ---------------------------------------------------------------------------
set(PHP_VERSION "" CACHE STRING "Required exact PHP version. Keep empty to find currently available version.")
set(VIRGIL_INSTALL_PHP_SRCDIR "phpsrc" CACHE STRING "Directory name where PHP sources will be installed")


# ---------------------------------------------------------------------------
#   Find PHP module and create target 'php' from it
# ---------------------------------------------------------------------------
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if(PHP_VERSION)
    find_package(PHP ${PHP_VERSION} EXACT REQUIRED COMPONENTS Runtime Devel)
else()
    find_package(PHP REQUIRED COMPONENTS Runtime Devel)
endif()

if(NOT PHP_FOUND)
    message(FATAL_ERROR "PHP headers and libraries needed for compiling extensions is not found.")
endif()

if(PHP_LIBRARIES)
    add_library(phplib STATIC IMPORTED)
    set_target_properties(phplib PROPERTIES IMPORTED_LOCATION "${PHP_LIBRARIES}")
else()
    add_library(phplib INTERFACE IMPORTED)
endif()

target_include_directories(phplib SYSTEM INTERFACE "${PHP_INCLUDE_DIRS}")

if(PHP_DEFINITIONS)
    target_compile_definitions(phplib INTERFACE ${PHP_DEFINITIONS} ZEND_DEBUG=0)
endif()

if(ENABLE_TESTING AND NOT COMPOSER_EXECUTABLE)
    set(COMPOSER_VERSION "1.9.1")
    set(COMPOSER_DOWNLOADED "${CMAKE_CURRENT_BINARY_DIR}/tmp/composer")

    file(
        DOWNLOAD
            https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar "${COMPOSER_DOWNLOADED}"
        SHOW_PROGRESS
    )

    file(SHA256 "${COMPOSER_DOWNLOADED}" COMPOSER_DOWNLOADED_HASH)
    if(NOT "${COMPOSER_DOWNLOADED_HASH}" STREQUAL "1f210b9037fcf82670d75892dfc44400f13fe9ada7af9e787f93e50e3b764111")
        message(FATAL_ERROR "Download 'composer.phar' file hash mismatch")
    endif()

    file(
        COPY "${COMPOSER_DOWNLOADED}" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
    )

    set(COMPOSER_EXECUTABLE "${CMAKE_CURRENT_BINARY_DIR}/composer" CACHE STRING "Path to the PHP composer" FORCE)
endif()

if(COMPOSER_EXECUTABLE)
    message(" Found Composer: ${COMPOSER_EXECUTABLE} (found version \"${COMPOSER_VERSION}\")")
endif()

# ---------------------------------------------------------------------------
#   Add per project extension build
# ---------------------------------------------------------------------------
add_subdirectory(VirgilCryptoWrapper/extensions/foundation)
add_subdirectory(VirgilCryptoWrapper/extensions/phe)
add_subdirectory(VirgilCryptoWrapper/extensions/pythia)
