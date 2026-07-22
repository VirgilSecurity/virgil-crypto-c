#   Copyright (C) 2015-2026 Virgil Security, Inc.
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
# Resolve the protoc compiler and nanopb generator, preferring the values this
# repo exports (VIRGIL_PROTOC / VIRGIL_PROTOC_GEN_NANOPB and the
# nanopb::protoc-gen-nanopb target) so downstream consumers do not need a
# Python virtual environment on PATH. Falls back to $VIRTUAL_ENV and finally the
# system PATH for backward compatibility with virgil's own build.
#
# _virgil_resolve_protobuf_tools(<out_protoc_var> <out_generator_var>)
#
function(_virgil_resolve_protobuf_tools out_protoc out_generator)

    #
    # protoc: exported cache var -> imported 'protoc' target -> system PATH.
    #
    set(_protoc "")
    if(DEFINED VIRGIL_PROTOC AND EXISTS "${VIRGIL_PROTOC}")
        set(_protoc "${VIRGIL_PROTOC}")
    elseif(TARGET protoc)
        get_target_property(_protoc protoc IMPORTED_LOCATION)
    endif()
    if(NOT _protoc)
        find_program(_protoc NAMES protoc NO_CMAKE_FIND_ROOT_PATH)
    endif()
    if(NOT _protoc)
        message(FATAL_ERROR
                "protoc compiler not found. Provide the 'protoc' target, set VIRGIL_PROTOC, "
                "or make 'protoc' discoverable on PATH.")
    endif()

    #
    # nanopb generator: imported target -> exported cache var -> $VIRTUAL_ENV
    # (bin/ on *nix, Scripts/ on Windows) -> system PATH.
    #
    set(_generator "")
    if(TARGET nanopb::protoc-gen-nanopb)
        get_target_property(_generator nanopb::protoc-gen-nanopb IMPORTED_LOCATION)
    endif()
    if(NOT _generator AND DEFINED VIRGIL_PROTOC_GEN_NANOPB AND EXISTS "${VIRGIL_PROTOC_GEN_NANOPB}")
        set(_generator "${VIRGIL_PROTOC_GEN_NANOPB}")
    endif()
    if(NOT _generator)
        # HINTS (virgil's venv) take priority over the system PATH so the pinned
        # nanopb generator wins over any system-installed one.
        find_program(_generator
                NAMES protoc-gen-nanopb protoc-gen-nanopb.bat
                HINTS "$ENV{VIRTUAL_ENV}/bin" "$ENV{VIRTUAL_ENV}/Scripts"
                NO_CMAKE_FIND_ROOT_PATH)
    endif()
    if(NOT _generator)
        message(FATAL_ERROR
                "nanopb generator 'protoc-gen-nanopb' not found. It is exported by virgil-crypto-c "
                "as VIRGIL_PROTOC_GEN_NANOPB / the nanopb::protoc-gen-nanopb target; ensure this "
                "repo was added (FetchContent/add_subdirectory) or set VIRGIL_PROTOC_GEN_NANOPB.")
    endif()

    set(${out_protoc} "${_protoc}" PARENT_SCOPE)
    set(${out_generator} "${_generator}" PARENT_SCOPE)
endfunction()


#
# Generate nanopb C sources from a single .proto file and add them to a target.
# This is the supported public API for downstream consumers reusing virgil's
# nanopb toolchain.
#
# virgil_nanopb_generate(
#     TARGET       <target>            # target to add the generated .pb.{c,h} to
#     PROTO        <file.proto>        # the .proto model (absolute or relative)
#     [OPTIONS     <file.options>]     # nanopb .options file (auto-detected as
#                                      #   <name>.options next to PROTO if omitted)
#     [IMPORT_DIRS <dir>...]           # extra protoc --proto_path entries
# )
#
# The generated <name>.pb.h / <name>.pb.c are written to CMAKE_CURRENT_BINARY_DIR,
# which is also added to the target's private include dirs. Link the target
# against nanopb::protobuf-nanopb for the runtime.
#
function(virgil_nanopb_generate)

    set(_options "")
    set(_one_value_args TARGET PROTO OPTIONS)
    set(_multi_value_args IMPORT_DIRS)
    cmake_parse_arguments(ARG "${_options}" "${_one_value_args}" "${_multi_value_args}" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "virgil_nanopb_generate: TARGET is required")
    endif()
    if(NOT ARG_PROTO)
        message(FATAL_ERROR "virgil_nanopb_generate: PROTO is required")
    endif()
    if(NOT EXISTS "${ARG_PROTO}")
        message(FATAL_ERROR "virgil_nanopb_generate: PROTO file not found: ${ARG_PROTO}")
    endif()

    _virgil_resolve_protobuf_tools(_protoc _generator)

    get_filename_component(_proto_dir  "${ARG_PROTO}" DIRECTORY)
    get_filename_component(_proto_name "${ARG_PROTO}" NAME_WE)

    #
    # nanopb .options: explicit arg wins, otherwise auto-detect <name>.options
    # next to the .proto (preserves the historical target_protobuf_sources behaviour).
    #
    # Passed as a plugin option (--nanopb_opt), NOT spliced into --nanopb_out=<opts>:<dir>:
    # protoc's first-colon split of the combined form collides with a Windows drive-letter
    # colon in an absolute options path (e.g. -fC:/…/foo.options), so a downstream consumer
    # that passes an absolute OPTIONS path fails on Windows. Keeping --nanopb_out a bare
    # directory lets protoc recognise the drive letter, and --nanopb_opt carries -f verbatim.
    #
    set(_opt_arg "")
    set(_options_dep "")
    if(ARG_OPTIONS)
        if(NOT EXISTS "${ARG_OPTIONS}")
            message(FATAL_ERROR "virgil_nanopb_generate: OPTIONS file not found: ${ARG_OPTIONS}")
        endif()
        set(_opt_arg "--nanopb_opt=-f${ARG_OPTIONS}")
        set(_options_dep "${ARG_OPTIONS}")
    elseif(EXISTS "${_proto_dir}/${_proto_name}.options")
        set(_opt_arg "--nanopb_opt=-f${_proto_name}.options")
        set(_options_dep "${_proto_dir}/${_proto_name}.options")
    endif()

    #
    # protoc import paths: the .proto directory plus any caller-provided dirs.
    #
    set(_proto_path_args "--proto_path=.")
    foreach(_dir ${ARG_IMPORT_DIRS})
        list(APPEND _proto_path_args "--proto_path=${_dir}")
    endforeach()

    set(_out_h "${CMAKE_CURRENT_BINARY_DIR}/${_proto_name}.pb.h")
    set(_out_c "${CMAKE_CURRENT_BINARY_DIR}/${_proto_name}.pb.c")

    #
    # Depend on the nanopb runtime target when present so its ExternalProject
    # (which also produces protoc) is built before generation runs.
    #
    set(_runtime_dep "")
    if(TARGET protobuf-nanopb)
        set(_runtime_dep protobuf-nanopb)
    endif()

    add_custom_command(
            OUTPUT "${_out_h}" "${_out_c}"
            COMMAND "${_protoc}"
                "--plugin=protoc-gen-nanopb=${_generator}"
                ${_opt_arg}
                "--nanopb_out=${CMAKE_CURRENT_BINARY_DIR}"
                ${_proto_path_args}
                "${_proto_name}.proto"
            DEPENDS "${ARG_PROTO}" ${_options_dep} ${_runtime_dep}
            COMMENT "nanopb: generating ${_proto_name}.pb.{c,h} from ${ARG_PROTO}"
            WORKING_DIRECTORY "${_proto_dir}"
            VERBATIM
            )

    target_sources(${ARG_TARGET} PRIVATE "${_out_h}" "${_out_c}")
    target_include_directories(${ARG_TARGET} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()


#
# Add generated nanopb sources to a target (backward-compatible wrapper around
# virgil_nanopb_generate). Each source's <name>.options is auto-detected.
#
# target_protobuf_sources(<target> [source1.proto ...])
#
function(target_protobuf_sources target)

    if(NOT ARGN)
        message(FATAL_ERROR "At least one source must be defined")
    endif()

    foreach(proto_file ${ARGN})
        virgil_nanopb_generate(TARGET ${target} PROTO "${proto_file}")
    endforeach()
endfunction()
