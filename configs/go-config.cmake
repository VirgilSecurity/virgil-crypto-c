#   Copyright (C) 2015-2021 Virgil Security, Inc.
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


set(CMAKE_INSTALL_LIBDIR lib CACHE STRING "")
set(VIRGIL_WRAP_GO ON CACHE BOOL "")
set(VIRGIL_C_TESTING OFF CACHE BOOL "")
set(VIRGIL_LIB_RATCHET OFF CACHE BOOL "")
set(VIRGIL_LIB_PYTHIA ON CACHE BOOL "")
set(VIRGIL_INSTALL_GO_SRCDIR gosrc CACHE STRING "")
set(VIRGIL_INSTALL_WRAP_SRCS ON CACHE BOOL "")
set(VIRGIL_INSTALL_WRAP_LIBS ON CACHE BOOL "")
set(VIRGIL_INSTALL_WRAP_DEPS ON CACHE BOOL "")
set(VIRGIL_INSTALL_DEPS_HDRS OFF CACHE BOOL "")
set(VIRGIL_INSTALL_DEPS_LIBS ON CACHE BOOL "")
set(VIRGIL_INSTALL_DEPS_CMAKE OFF CACHE BOOL "")
set(VIRGIL_INSTALL_HDRS ON CACHE BOOL "")
set(VIRGIL_INSTALL_LIBS ON CACHE BOOL "")
set(VIRGIL_INSTALL_CMAKE OFF CACHE BOOL "")
set(VIRGIL_PACKAGE_LANGUAGE go CACHE STRING "")
