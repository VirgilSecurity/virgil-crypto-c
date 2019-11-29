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

# ===========================================================================
#   This script patch all falcon source files by
#       - add "falcon_" prefix to all "shake256_*()" functions.
#   It is required to avoid symbol collision with the "round5" library, that
#   contains SHAKE256 implementation on its own.
# ===========================================================================

if(NOT SOURCE_DIR)
    message(FATAL_ERROR "Expected variable SOURCE_DIR")
endif()

if(NOT EXISTS "${SOURCE_DIR}")
    message(FATAL_ERROR "Variable SOURCE_DIR contains not existent path: ${SOURCE_DIR}")
endif()

file(GLOB SOURCES RELATIVE "${SOURCE_DIR}" "*.h" "*.c")
foreach(src IN LISTS SOURCES)
    set(src_file "${SOURCE_DIR}/${src}")
    file(READ "${src_file}" file_content)
    string(REGEX REPLACE "([^a-zA-Z_]|^)(shake256_[a-zA-Z0-9_]+)" "\\1falcon_\\2" file_new_content "${file_content}")
    file(WRITE "${src_file}" "${file_new_content}")
endforeach()
