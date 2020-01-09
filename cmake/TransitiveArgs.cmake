#   Copyright (C) 2015-2020 Virgil Security, Inc.
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


if(${CMAKE_VERSION} VERSION_LESS "3.10")
    if(__TRANSITIVE_ARGS_INCLUDED__)
      return()
    endif()

    set(__TRANSITIVE_ARGS_INCLUDED__ TRUE)
else()
    include_guard()
endif()


function(TRANSITIVE_ARGS_INIT)
    set(TRANSITIVE_ARGS_FILE "${CMAKE_BINARY_DIR}/transitive-args.cmake" CACHE FILEPATH "")
    set(TRANSITIVE_ARGS "-C${TRANSITIVE_ARGS_FILE}" CACHE STRING "Pass this value to ExternalProject_Add(CMAKE_ARGS ...)")
    set(TRANSITIVE_C_FLAGS "" CACHE STRING "Transitive CMAKE_C_FLAGS")
    set(TRANSITIVE_CXX_FLAGS "" CACHE STRING "Transitive CMAKE_CXX_FLAGS")
    set(TRANSITIVE_EXE_LINKER_FLAGS "" CACHE STRING "Transitive CMAKE_EXE_LINKER_FLAGS")
    set(TRANSITIVE_MODULE_LINKER_FLAGS "" CACHE STRING "Transitive CMAKE_MODULE_LINKER_FLAGS")
    set(TRANSITIVE_SHARED_LINKER_FLAGS "" CACHE STRING "Transitive CMAKE_SHARED_LINKER_FLAGS")
    set(TRANSITIVE_STATIC_LINKER_FLAGS "" CACHE STRING "Transitive CMAKE_STATIC_LINKER_FLAGS")


    if(NOT EXISTS "${TRANSITIVE_ARGS_FILE}")
        file(WRITE "${TRANSITIVE_ARGS_FILE}"
                "set(TRANSITIVE_ARGS_FILE \"${TRANSITIVE_ARGS_FILE}\" CACHE FILEPATH \"\")\n")
    endif()

    file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(CMAKE_C_FLAGS \"${TRANSITIVE_C_FLAGS}\" CACHE INTERNAL \"\")\n")
    file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(CMAKE_CXX_FLAGS \"${TRANSITIVE_CXX_FLAGS}\" CACHE INTERNAL \"\")\n")
    file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(CMAKE_EXE_LINKER_FLAGS \"${TRANSITIVE_EXE_LINKER_FLAGS}\" CACHE INTERNAL \"\")\n")
    file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(CMAKE_MODULE_LINKER_FLAGS \"${TRANSITIVE_MODULE_LINKER_FLAGS}\" CACHE INTERNAL \"\")\n")
    file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(CMAKE_SHARED_LINKER_FLAGS \"${TRANSITIVE_SHARED_LINKER_FLAGS}\" CACHE INTERNAL \"\")\n")
    file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(CMAKE_STATIC_LINKER_FLAGS \"${TRANSITIVE_STATIC_LINKER_FLAGS}\" CACHE INTERNAL \"\")\n")
endfunction()


function(TRANSITIVE_ARGS_ADD)
    if(NOT TRANSITIVE_ARGS_FILE)
        message(FATAL_ERROR "[INTERNAL] TransitiveArgs.cmake: variable TRANSITIVE_ARGS_FILE is not defined")
    endif ()

    if(NOT EXISTS "${TRANSITIVE_ARGS_FILE}")
        message(FATAL_ERROR "[INTERNAL] TransitiveArgs.cmake: file '${TRANSITIVE_ARGS_FILE}' does not exists")
    endif ()

    file(STRINGS "${TRANSITIVE_ARGS_FILE}" file_content)

    foreach(var ${ARGN})
        if(${var} AND NOT file_content MATCHES "${var}")
            file(APPEND "${TRANSITIVE_ARGS_FILE}" "set(${var} \"${${var}}\" CACHE INTERNAL \"\")\n")
        endif()
    endforeach()
endfunction()


transitive_args_init ()
