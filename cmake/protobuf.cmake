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


#
# Add generated sources to a target based on the gievn items.
# Add protobuf sources to a target.
# given target as an Apple Framework
#
# target_protobuf_sources(<target> [source1...])
#
function(target_protobuf_sources target)

    set(oneValueArgs PREFIX_DIR)
    set(multiValueArgs SOURCES)

    cmake_parse_arguments(PROTOBUF_SOURCES "" "${oneValueArgs}" "${multiValueArgs}" "${ARGN}")

    if(PROTOBUF_SOURCES_PREFIX_DIR AND NOT PROTOBUF_SOURCES_SOURCES)
        message(FATAL_ERROR "Signature target_protobuf_sources(PREFIX_DIR <dir> SOURCES <names>) require SOURCES")
    endif()

    if(PROTOBUF_SOURCES_SOURCES)
        set(sources "${PROTOBUF_SOURCES_SOURCES}")
    else()
        set(sources "${ARGN}")
    endif()

    if(NOT sources)
        message(FATAL_ERROR "At least one source must be defined")
    endif()

    #
    # Inspect host system
    #
    if(WIN32 AND NOT CYGWIN)
        set(EXECUTABLE_SUFFIX ".exe")
    endif()

    #
    # Check runtime
    #
    if(TARGET protoc)
        set(PROTOC_EXE protoc)

    elseif(COMMAND find_host_package)
        find_host_program(PROTOC_EXE NAMES protoc${EXECUTABLE_SUFFIX})

    else()
        find_program(PROTOC_EXE NAMES protoc${EXECUTABLE_SUFFIX})
    endif()

    if(NOT PROTOC_EXE)
        message(FATAL_ERROR
                "Protobuf generator 'protoc${EXECUTABLE_SUFFIX}' is not found as a target "
                "and not found as an executable within system"
                )
    endif()

    #
    # Check nanopb plug-in.
    #
    if(NOT PROTOC_GEN_NANOPB)
        message(FATAL_ERROR "CMake variable PROTOC_GEN_NANOPB that points to the nanopb plug-in script is not defined.")
    endif()

    #
    # Create generation command per proto file
    #
    foreach(proto_file ${sources})
        if (PROTOBUF_SOURCES_PREFIX_DIR)
            set(proto_file_path "${PROTOBUF_SOURCES_PREFIX_DIR}/${proto_file}")

            get_filename_component(proto_file_out_subdir "${proto_file}" DIRECTORY)
            if (proto_file_out_subdir)
                set(proto_file_out_dir "${CMAKE_CURRENT_BINARY_DIR}/${proto_file_out_subdir}")
            else()
                set(proto_file_out_dir "${CMAKE_CURRENT_BINARY_DIR}")
            endif()
        else()
            set(proto_file_path "${proto_file}")

            set(proto_file_out_dir "${CMAKE_CURRENT_BINARY_DIR}")
        endif()

        if(NOT EXISTS "${proto_file_path}")
            message(FATAL_ERROR "Protobuf model file is not found: ${proto_file_path}")
        endif()

        get_filename_component(proto_file_dir "${proto_file_path}" DIRECTORY)
        get_filename_component(proto_file_name "${proto_file_path}" NAME_WE)


        if(EXISTS "${proto_file_dir}/${proto_file_name}.options")
            set(proto_options_file "${proto_file_name}.options")
            set(proto_options "-f${proto_options_file}")
        else()
            set(proto_options_file "")
            set(proto_options "")
        endif()

        add_custom_command(
                OUTPUT
                    "${proto_file_out_dir}/${proto_file_name}.pb.h"
                    "${proto_file_out_dir}/${proto_file_name}.pb.c"
                COMMAND
                    "${CMAKE_COMMAND}" -E make_directory "${proto_file_out_dir}"
                COMMAND
                    "${PROTOC_EXE}"
                ARGS
                    --plugin=protoc-gen-nanopb="${PROTOC_GEN_NANOPB}"
                                    --nanopb_out=${proto_options}:"${proto_file_out_dir}"
                                    --proto_path=. "${proto_file_name}.proto"
                DEPENDS
                    "${proto_file_path}" "${proto_options_file}" protobuf-nanopb
                COMMENT "Processing protobuf model: ${proto_file_path}"
                WORKING_DIRECTORY "${proto_file_dir}"
                )

        target_sources(${target}
                PRIVATE
                    "${proto_file_out_dir}/${proto_file_name}.pb.h"
                    "${proto_file_out_dir}/${proto_file_name}.pb.c"
                )
    endforeach()
endfunction()
