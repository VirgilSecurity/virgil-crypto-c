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

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(iotelic VERSION 1.0.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Check dependencies
# ---------------------------------------------------------------------------

#
# Options
#
include("${CMAKE_CURRENT_LIST_DIR}/features.cmake")

# ---------------------------------------------------------------------------
#   Define library
# ---------------------------------------------------------------------------

#
# Define sources
#
add_library(iotelic STATIC "")

target_sources(iotelic
        PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/src/iotelic_sp_interface.c"
        )

set(SP_DIR  ${CMAKE_CURRENT_LIST_DIR}/../../../../../sp)
set(AP_DIR  ${CMAKE_CURRENT_LIST_DIR}/../../../../../ap)

target_include_directories(iotelic
        PUBLIC
        "$<BUILD_INTERFACE:${SP_DIR}/bsp/include>"
        "$<BUILD_INTERFACE:${SP_DIR}/bsp/driver>"
        "$<BUILD_INTERFACE:${SP_DIR}/crypto/inc>"

        "$<BUILD_INTERFACE:${AP_DIR}/inc>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/app>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/bsp>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/gpio>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/compiler/gcc>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/dbglog>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/io_lib>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/os_shim>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/pib>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/pkt>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/plc_lib>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/uart>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/upgrade>"
        "$<BUILD_INTERFACE:${AP_DIR}/inc/utils>"

        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
        )
