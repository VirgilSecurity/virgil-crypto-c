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

cmake_minimum_required(VERSION 3.15)
project(virgil_crypto_c_foundation_benchmarks VERSION ${virgil_crypto_c_benchmarks_VERSION} LANGUAGES CXX)

add_subdirectory(data)

add_executable(bench)
set_target_properties(bench PROPERTIES CXX_STANDARD 11)
target_link_libraries(bench benchmark_data_foundation vsc::foundation benchmark::benchmark_main)

macro(_add_benchmark benchmark)
    target_sources(bench PRIVATE ${benchmark}.cpp)
    add_executable(${benchmark} ${benchmark}.cpp)
    target_link_libraries(${benchmark} benchmark_data_foundation vsc::foundation benchmark::benchmark_main)
    set_target_properties(${benchmark} PROPERTIES CXX_STANDARD 11)

    if(COMMAND add_clangformat AND ENABLE_CLANGFORMAT)
        add_clangformat(${benchmark})
    endif()
endmacro()

_add_benchmark(benchmark_refcnt)
_add_benchmark(benchmark_key)
_add_benchmark(benchmark_hash)
_add_benchmark(benchmark_recipient_cipher)
_add_benchmark(benchmark_signer_verifier)
