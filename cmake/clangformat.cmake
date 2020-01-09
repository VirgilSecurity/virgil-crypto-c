#
# Copyright (C) 2015-2020 Virgil Security, Inc.
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

#
#  Solution taken from https://www.linkedin.com/pulse/simple-elegant-wrong-how-integrate-clang-format-friends-brendan-drew/
#

include_guard()

find_program(CLANG_FORMAT_EXECUTABLE clang-format)

function(add_clangformat _targetname)
    if(CLANG_FORMAT_EXECUTABLE)
        if(NOT TARGET ${_targetname})
            message(FATAL_ERROR "add_clangformat should only be called on targets(got " ${_targetname} ")")
        endif()

        # figure out which sources this should be applied to
        get_target_property(_clang_sources ${_targetname} SOURCES)
        get_target_property(_builddir ${_targetname} BINARY_DIR)


        set(_sources "")
        foreach(_source ${_clang_sources})
            # remove cmake generator expressions if exists
            string(REGEX REPLACE "([^:]+:)" "" _source "${_source}")
            string(REGEX REPLACE ">" "" _source "${_source}")

            if(NOT TARGET ${_source})
                get_filename_component(_source_file ${_source} NAME)
                get_source_file_property(_clang_loc "${_source}" LOCATION)

                set(_format_file ${_targetname}_${_source_file}.format)

                add_custom_command(OUTPUT ${_format_file}
                        DEPENDS ${_source}
                        COMMENT "Clang-Format ${_source}"
                        COMMAND ${CLANG_FORMAT_EXECUTABLE} -style=file -fallback-style=WebKit -i ${_clang_loc}
                        COMMAND ${CMAKE_COMMAND} -E touch ${_format_file})

                list(APPEND _sources ${_format_file})
            endif()
        endforeach()

        if(_sources)
            add_custom_target(${_targetname}_clangformat
                    SOURCES ${_sources}
                    COMMENT "Clang-Format for target ${_target}")

            add_dependencies(${_targetname} ${_targetname}_clangformat)
        endif()

    endif()
endfunction()
