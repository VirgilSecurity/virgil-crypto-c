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

project(benchmark_framework)

include(ExternalProject)
ExternalProject_Add(benchmark
        GIT_REPOSITORY
            https://github.com/google/benchmark.git
        INSTALL_DIR
            "${CMAKE_BINARY_DIR}"
        CMAKE_ARGS
            "-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark"
            "-DCMAKE_BUILD_TYPE=Release"
            "-DBENCHMARK_ENABLE_GTEST_TESTS=OFF"
            "-DBENCHMARK_ENABLE_TESTING=OFF"
)

add_library(benchmark_framework IMPORTED STATIC GLOBAL)
add_dependencies(benchmark_framework benchmark)

target_link_libraries(benchmark_framework
        INTERFACE
        ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark/lib/libbenchmark${CMAKE_STATIC_LIBRARY_SUFFIX})

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark/include)

set_target_properties(benchmark_framework PROPERTIES
        IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark/lib/libbenchmark${CMAKE_STATIC_LIBRARY_SUFFIX}
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}benchmark/include)