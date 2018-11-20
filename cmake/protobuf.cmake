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


#
# Add generated sources to a target based on the gievn items.
# Add protobuf sources to a target.
# given target as an Apple Framework
#
# target_protobuf_sources(<target> [source1...])
#
function(target_protobuf_sources target)

    if(NOT ARGN)
        message(FATAL_ERROR "At least one source must be defined")
    endif()

    #
    # Check runtime
    #
    if(TARGET protoc)
        set(PROTOC_EXE protoc)

    elseif(COMMAND find_host_package)
        find_host_program(PROTOC_EXE NAMES protoc${CMAKE_EXECUTABLE_SUFFIX})

    else()
        find_program(PROTOC_EXE NAMES protoc${CMAKE_EXECUTABLE_SUFFIX})
    endif()

    if(NOT PROTOC_EXE)
        message(FATAL_ERROR
                "Protobuf generator 'protoc${CMAKE_EXECUTABLE_SUFFIX}' is not found as a target "
                "and not found as an executable within system"
                )
    endif()

    #
    # Create generation command per proto file
    #
    foreach(proto_file ${ARGN})
        if(NOT EXISTS "${proto_file}")
            message(FATAL_ERROR "Protobuf model file is not found: ${proto_file}")
        endif()

        get_filename_component(proto_file_path "${proto_file}" DIRECTORY)
        get_filename_component(proto_file_name "${proto_file}" NAME_WE)

        if(EXISTS "${proto_file_path}/${proto_file_name}.options")
            set(proto_options_file "${proto_file_path}/${proto_file_name}.options")
        endif()

        add_custom_command(
                OUTPUT
                    ${proto_file_name}.pb.h ${proto_file_name}.pb.c
                COMMAND
                    "${PROTOC_EXE}" --nanopb_out=-f"${proto_options_file}":.
                                    --proto_path="${proto_file_path}" "${proto_file}"
                DEPENDS
                    "${proto_file}" "${proto_options_file}"
                COMMENT "Processing protobuf model: ${proto_file}"
                )

        target_sources(${target}
                PRIVATE
                    "${CMAKE_CURRENT_BINARY_DIR}/${proto_file_name}.pb.h"
                    "${CMAKE_CURRENT_BINARY_DIR}/${proto_file_name}.pb.c"
                )
    endforeach()
endfunction()
