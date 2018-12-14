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

project(virgil_crypto_csharp VERSION 0.5.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   CSharp wrapper build options
# ---------------------------------------------------------------------------
set(CSHARP_VERSION "" CACHE STRING "Required exact PHP version. Keep empty to find currently available version.")

if(VIRGIL_INSTALL_WRAP_STANDALONE)
    get_filename_component(CSHARP_DESTINATION "${VIRGIL_INSTALL_WRAP_PREFIX}/csharp" ABSOLUTE)
else()
    set(CSHARP_DESTINATION "${VIRGIL_INSTALL_WRAP_PREFIX}")
endif()

# ---------------------------------------------------------------------------
#   Find CSHARP module and create target 'CSHARP' from it
# ---------------------------------------------------------------------------
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if(CSHARP_VERSION)
    find_package(CSHARP ${CSHARP_VERSION} EXACT REQUIRED)
else()
    find_package(CSHARP REQUIRED)
endif()

if(NOT CSHARP_COMPILER)
    message(FATAL_ERROR "C# is not found.")
endif()

if(NOT NUGET_EXECUTABLE)
	message("nuget is not found. CSharp xUnit tests will be disabled!")
endif()

if(NOT DOTNET_EXECUTABLE)
	message(WARNING "dotnet is not found. CSharp xUnit tests will be disabled!")
endif()
# ---------------------------------------------------------------------------
#   Add per project extension build
# ---------------------------------------------------------------------------
add_subdirectory(pythia)
