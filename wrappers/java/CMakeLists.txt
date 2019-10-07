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

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(virgil_crypto_java VERSION ${virgil_crypto_VERSION} LANGUAGES C)


# ---------------------------------------------------------------------------
#   Find Java module and create imported target 'java' from it
# ---------------------------------------------------------------------------


#
# Find Java JNI
#
if(ANDROID)
    find_path(JNI_INCLUDE_DIRS jni.h HINTS "${ANDROID_SYSROOT}/usr/include")
else()
    find_host_package(JNI REQUIRED)
endif()

if(NOT JNI_INCLUDE_DIRS)
    message(FATAL_ERROR "JNI headers required for compiling Java wrapper is not found in the system.")
endif()

add_library(jni INTERFACE IMPORTED)
target_include_directories(jni SYSTEM INTERFACE "${JNI_INCLUDE_DIRS}")

# ---------------------------------------------------------------------------
#   Add per project extension build
# ---------------------------------------------------------------------------
add_subdirectory(foundation)
add_subdirectory(phe)
add_subdirectory(pythia)
add_subdirectory(ratchet)
