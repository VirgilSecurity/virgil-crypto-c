#   Copyright (c) 2015-2017 Virgil Security Inc.
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


# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
set(PHP_CPP_INSTALL_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/php-cpp)
set(PHP_CPP_BUILD_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/php-cpp-ext-prefix/src/php-cpp-ext)


# ---------------------------------------------------------------------------
#   Load library as an external project
# ---------------------------------------------------------------------------
include(ExternalProject)

if(UNIX)
    find_program(MAKE_COMMAND NAMES make)
    if(NOT MAKE_COMMAND)
        message(FATAL_ERROR "Utility program 'make' is not found in the system.")
    endif()

    ExternalProject_Add(php-cpp-ext
            GIT_REPOSITORY
                https://github.com/CopernicaMarketingSoftware/PHP-CPP
            GIT_TAG
                v2.1.2
            CONFIGURE_COMMAND ""
            BUILD_COMMAND "${MAKE_COMMAND}"
            BUILD_IN_SOURCE YES
            INSTALL_COMMAND ""
            INSTALL_COMMAND
                "${CMAKE_COMMAND}" -E copy
                        "${PHP_CPP_BUILD_LOCATION}/phpcpp.h" "${PHP_CPP_INSTALL_LOCATION}/include"
            )
else()
    message(FATAL_ERROR "TODO: Add Windows build for third-party library php-cpp.")
endif()


ExternalProject_Add_Step(php-cpp-ext install-internal-headers
        COMMAND
            "${CMAKE_COMMAND}" -E copy_directory
                    "${PHP_CPP_BUILD_LOCATION}/include" "${PHP_CPP_INSTALL_LOCATION}/include/phpcpp"
        COMMENT
            "Performing additional install step for 'php-cpp-ext'"
        DEPENDEES
            install
        )

ExternalProject_Add_Step(php-cpp-ext install-static-library
        COMMAND
            "${CMAKE_COMMAND}" -E copy
                    "${PHP_CPP_BUILD_LOCATION}/${CMAKE_STATIC_LIBRARY_PREFIX}phpcpp${CMAKE_STATIC_LIBRARY_SUFFIX}.2.1.1"
                    "${PHP_CPP_INSTALL_LOCATION}/"
        COMMENT
            "Performing additional install step for 'php-cpp-ext'"
        DEPENDEES
            install
        )

ExternalProject_Add_Step(php-cpp-ext install-shared-library
        COMMAND
            "${CMAKE_COMMAND}" -E copy
                    "${PHP_CPP_BUILD_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}phpcpp.so.2.1.1"
                    "${PHP_CPP_INSTALL_LOCATION}/"
        COMMENT
            "Performing additional install step for 'php-cpp-ext'"
        DEPENDEES
            install
        )


# ---------------------------------------------------------------------------
#   Import library as a target
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${PHP_CPP_INSTALL_LOCATION}/include)

add_library(php-cpp SHARED IMPORTED GLOBAL)
add_library(php-cpp-static STATIC IMPORTED GLOBAL)

add_dependencies(php-cpp php-cpp-ext)
add_dependencies(php-cpp-static php-cpp-ext)

set_target_properties(php-cpp
        PROPERTIES
        IMPORTED_LOCATION
            "${PHP_CPP_INSTALL_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}phpcpp.so.2.1.1"

        INTERFACE_INCLUDE_DIRECTORIES
            "${PHP_CPP_INSTALL_LOCATION}/include"
        )

set_target_properties(php-cpp-static
        PROPERTIES
        IMPORTED_LOCATION
            "${PHP_CPP_INSTALL_LOCATION}/${CMAKE_STATIC_LIBRARY_PREFIX}phpcpp${CMAKE_STATIC_LIBRARY_SUFFIX}.2.1.1"

        INTERFACE_INCLUDE_DIRECTORIES
            "${PHP_CPP_INSTALL_LOCATION}/include"
        )


install(
        PROGRAMS "${PHP_CPP_INSTALL_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}phpcpp.so.2.1.1"
        DESTINATION "${PHP_DESTINATION}"
        RENAME ${CMAKE_SHARED_LIBRARY_PREFIX}phpcpp.so.2.1
        )
