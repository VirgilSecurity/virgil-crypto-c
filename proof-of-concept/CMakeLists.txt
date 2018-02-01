# Copyright (C) 2015-2018 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
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

cmake_minimum_required(VERSION 3.8)

project(vsf VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

file(GLOB VSF_SRC
        "src/generated/*.h"
        "src/generated/*.c"
        )

file(GLOB VSF_INCLUDE
        "include/virgil/*.h"
        )

add_library(vsf ${VSF_SRC} ${VSF_INCLUDE})

target_include_directories (vsf
    PUBLIC
    $<BUILD_INTERFACE:${vsf_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${vsf_SOURCE_DIR}/include/virgil>
    $<BUILD_INTERFACE:${vsf_SOURCE_DIR}/src/generated>
    $<BUILD_INTERFACE:${vsf_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

include (virgil_depends)

virgil_depends (
    PACKAGE_NAME "MbedTLS"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs_ext/mbedtls"
    CMAKE_ARGS "${CMAKE_ARGS}" "${MBEDTLS_CMAKE_ARGS}"
)
virgil_find_package (MbedTLS 2.2)

target_link_libraries(vsf PUBLIC mbedtls::mbedcrypto)

add_executable(main src/main.c)
target_link_libraries(main vsf)
