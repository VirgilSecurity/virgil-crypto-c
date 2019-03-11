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
add_library(iotelic INTERFACE)

#
# Define include headers
#
set (INC_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../../ap/inc)
target_include_directories(iotelic
        INTERFACE
        "$<BUILD_INTERFACE:>${INC_DIR}"
        "$<BUILD_INTERFACE:>${INC_DIR}/app"
        "$<BUILD_INTERFACE:>${INC_DIR}/bsp"
        "$<BUILD_INTERFACE:>${INC_DIR}/gpio"
        "$<BUILD_INTERFACE:>${INC_DIR}/compiler/gcc"
        "$<BUILD_INTERFACE:>${INC_DIR}/dbglog"
        "$<BUILD_INTERFACE:>${INC_DIR}/io_lib"
        "$<BUILD_INTERFACE:>${INC_DIR}/os_shim"
        "$<BUILD_INTERFACE:>${INC_DIR}/pib"
        "$<BUILD_INTERFACE:>${INC_DIR}/pkt"
        "$<BUILD_INTERFACE:>${INC_DIR}/plc_lib"
        "$<BUILD_INTERFACE:>${INC_DIR}/uart"
        "$<BUILD_INTERFACE:>${INC_DIR}/upgrade"
        "$<BUILD_INTERFACE:>${INC_DIR}/utils"
        "$<INSTALL_INTERFACE:${INSTALL_CMAKE_DIR}>"
        )