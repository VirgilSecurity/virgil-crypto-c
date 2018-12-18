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

include (${CSHARP_USE_FILE})
cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(virgil_crypto_pythia_csharp VERSION ${virgil_crypto_csharp_VERSION} LANGUAGES C)


#
# Check dependencies
#
if(NOT VIRGIL_LIB_PYTHIA)
    message(STATUS "Skip building the CSharp wrapper for library Pythia, which is not built.")
    return()
endif()

add_library(example SHARED "")

set_target_properties(example PROPERTIES
        C_STANDARD 99
        DEBUG_POSTFIX "_d"
        OUTPUT_NAME example
        PREFIX "lib"
        SUFFIX ".dylib"
        )

target_sources(example
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/example.c>
        )


csharp_add_library(example_cs "${CMAKE_CURRENT_SOURCE_DIR}/example.cs")

if(ENABLE_TESTING AND VIRGIL_CSHARP_TESTING AND DOTNET_EXECUTABLE AND NUGET_EXECUTABLE)
	set(test_project_name "NetCoreXUnitTest")
	set(test_solution "${test_project_name}.sln")

	configure_file(
		    "${CMAKE_CURRENT_SOURCE_DIR}/${test_project_name}.csproj"
		    "${CMAKE_CURRENT_BINARY_DIR}/${test_project_name}.csproj"
	)
	configure_file(
	        "${CMAKE_CURRENT_SOURCE_DIR}/${test_solution}"
	        "${CMAKE_CURRENT_BINARY_DIR}/${test_solution}"
	)
	configure_file(
	        "${CMAKE_CURRENT_SOURCE_DIR}/ExampleUnitTest.cs"
	        "${CMAKE_CURRENT_BINARY_DIR}/ExampleUnitTest.cs"
	)
	execute_process(
			COMMAND ${NUGET_EXECUTABLE} restore "${test_solution}"
			WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
	)
    add_test(
		    NAME test_pythia_csharp
		    COMMAND ${DOTNET_EXECUTABLE} test
	)
endif()
