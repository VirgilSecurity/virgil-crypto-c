#   Copyright (C) 2015-2022 Virgil Security, Inc.
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


# ---------------------------------------------------------------------------
#   Include once.
# ---------------------------------------------------------------------------
if(${CMAKE_VERSION} VERSION_LESS "3.10")
    if(__TRANSITIVE_ARGS_INCLUDED__)
      return()
    endif()

    set(__TRANSITIVE_ARGS_INCLUDED__ TRUE)
else()
    include_guard()
endif()

# ---------------------------------------------------------------------------
#   Helpers.
# ---------------------------------------------------------------------------
include("${CMAKE_CURRENT_LIST_DIR}/TransitiveArgs.cmake")


# ---------------------------------------------------------------------------
#   Make CMAKE_TOOLCHAIN_FILE path absolute.
# ---------------------------------------------------------------------------
function(TRANSITIVE_MAKE_ABSOLUTE_TOOLCHAIN_FILE_PATH)
    if(DEFINED CMAKE_TOOLCHAIN_FILE AND NOT IS_ABSOLUTE "${CMAKE_TOOLCHAIN_FILE}")
        get_filename_component(CMAKE_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")
        set(CMAKE_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" CACHE INTERNAL)
    endif()
endfunction()


# ---------------------------------------------------------------------------
#   CMake arguments that is not passed automatically to the function
#   ExternalProject_Add().
# ---------------------------------------------------------------------------
function(TRANSITIVE_COMMON_ARGS_ADD)
    transitive_args_add(
            CMAKE_POSITION_INDEPENDENT_CODE
            CMAKE_INSTALL_LIBDIR
    )
endfunction()


# ---------------------------------------------------------------------------
#   Known APPLE toolchain configuration arguments.
# ---------------------------------------------------------------------------
function(TRANSITIVE_APPLE_ARGS_ADD)
    if(CMAKE_CROSSCOMPILING AND APPLE)
        transitive_args_add(
                APPLE_PLATFORM
                APPLE_BITCODE
                APPLE_EXTENSION
                IOS_DEVICE_FAMILY
                IOS_DEPLOYMENT_TARGET
                WATCHOS_DEPLOYMENT_TARGET
                WATCHOS_DEVICE_FAMILY
                TVOS_DEPLOYMENT_TARGET
                TVOS_DEVICE_FAMILY
                MACOS_DEPLOYMENT_TARGET
                CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT
                CMAKE_APPLE_SDK_ROOT
                CMAKE_OSX_ARCHITECTURES)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        transitive_args_add(CMAKE_OSX_ARCHITECTURES)
    endif ()
endfunction()


# ---------------------------------------------------------------------------
#   Known ANDROID toolchain configuration arguments.
# ---------------------------------------------------------------------------
function(TRANSITIVE_ANDROID_ARGS_ADD)
    if(CMAKE_CROSSCOMPILING AND ANDROID)
        transitive_args_add(
                ANDROID_TOOLCHAIN
                ANDROID_ABI
                ANDROID_PLATFORM
                ANDROID_STL
                ANDROID_PIE
                ANDROID_CPP_FEATURES
                ANDROID_ALLOW_UNDEFINED_SYMBOLS
                ANDROID_ARM_MODE
                ANDROID_ARM_NEON
                ANDROID_DISABLE_NO_EXECUTE
                ANDROID_DISABLE_RELRO
                ANDROID_DISABLE_FORMAT_STRING_CHECKS
                ANDROID_CCACHE)

        transitive_args_add_value(CMAKE_C_FLAGS "${TRANSITIVE_C_FLAGS}")
        transitive_args_add_value(CMAKE_CXX_FLAGS "${TRANSITIVE_CXX_FLAGS}")
        transitive_args_add_value(CMAKE_EXE_LINKER_FLAGS "${TRANSITIVE_EXE_LINKER_FLAGS}")
        transitive_args_add_value(CMAKE_MODULE_LINKER_FLAGS "${TRANSITIVE_MODULE_LINKER_FLAGS}")
        transitive_args_add_value(CMAKE_SHARED_LINKER_FLAGS "${TRANSITIVE_SHARED_LINKER_FLAGS}")
        transitive_args_add_value(CMAKE_STATIC_LINKER_FLAGS "${TRANSITIVE_STATIC_LINKER_FLAGS}")
    endif()
endfunction()


function(TRANSITIVE_TOOLCHAIN_ARGS_ADD)
    transitive_make_absolute_toolchain_file_path()
    transitive_common_args_add()
    transitive_apple_args_add()
    transitive_android_args_add()
endfunction()


transitive_toolchain_args_add()
