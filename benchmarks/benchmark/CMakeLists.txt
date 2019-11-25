#
# Copyright (C) 2015-2019 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

include(ExternalProject)
ExternalProject_Add(benchmark-ext
        GIT_REPOSITORY
            https://github.com/google/benchmark.git
        GIT_TAG
            v1.5.0
        CMAKE_ARGS
            "-DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/benchmark"
            "-DCMAKE_BUILD_TYPE=Release"
            "-DBENCHMARK_ENABLE_INSTALL=ON"
            "-DBENCHMARK_ENABLE_GTEST_TESTS=OFF"
            "-DBENCHMARK_ENABLE_TESTING=OFF"
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/benchmark/include)

add_library(benchmark::benchmark IMPORTED STATIC GLOBAL)
add_dependencies(benchmark::benchmark benchmark-ext)
set_target_properties(benchmark::benchmark
        PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES
            ${CMAKE_CURRENT_BINARY_DIR}/benchmark/include
        IMPORTED_LOCATION
            ${CMAKE_CURRENT_BINARY_DIR}/benchmark/lib/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark${CMAKE_STATIC_LIBRARY_SUFFIX}
        )

add_library(benchmark::benchmark_main IMPORTED STATIC GLOBAL)
set_target_properties(benchmark::benchmark_main
        PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES
            ${CMAKE_CURRENT_BINARY_DIR}/benchmark/include
        INTERFACE_LINK_LIBRARIES
            benchmark::benchmark
        IMPORTED_LOCATION
            ${CMAKE_CURRENT_BINARY_DIR}/benchmark/lib/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark_main${CMAKE_STATIC_LIBRARY_SUFFIX}
        )

set_property(TARGET benchmark::benchmark_main
        PROPERTY
        INTERFACE_LINK_LIBRARIES
            benchmark::benchmark
            $<$<BOOL:${WIN32}>:shlwapi>
        )
