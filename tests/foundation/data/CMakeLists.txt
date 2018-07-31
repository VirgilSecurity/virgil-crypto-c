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

project(test_data VERSION 0.1.0 LANGUAGES C)

add_library(test_data "")
target_sources(test_data
        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_aes256_gcm.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_asn1.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hkdf.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_kdf1.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_kdf2.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha224.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha256.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha384.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha512.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hmac224.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hmac256.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hmac384.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_hmac512.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/test_data_types.h"

        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_aes256_gcm.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_asn1.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hkdf.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hmac224.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hmac256.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hmac384.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_hmac512.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_kdf1.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_kdf2.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha224.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha256.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha384.c"
            "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha512.c"
        )

target_include_directories(test_data
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        )
