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


# ---------------------------------------------------------------------------
#   Round5 contains global variables that is not declared as "extern".
#   This leads to an invalid linkage on the Windows platforms.
# ---------------------------------------------------------------------------

if(NOT SOURCE_FILE)
    message(FATAL_ERROR "Expected variable SOURCE_FILE")
endif()

if(NOT EXISTS "${SOURCE_FILE}")
    message(FATAL_ERROR "Variable SOURCE_FILE contains not existent path: ${SOURCE_FILE}")
endif()

file(STRINGS "${SOURCE_FILE}" file_lines NEWLINE_CONSUME)
file(WRITE "${SOURCE_FILE}.tmp" "")
foreach(line IN LISTS file_lines)
    string(REGEX REPLACE "(const uint32_t r5_parameter_sets)" "extern \\1" line "${line}")
    string(REGEX REPLACE "(const char [*]r5_parameter_set_names)" "extern \\1" line "${line}")
    string(REGEX REPLACE "extern extern" "extern" line "${line}")
    file(APPEND "${SOURCE_FILE}.tmp" "${line}")
endforeach()

execute_process(
        COMMAND
            ${CMAKE_COMMAND} -E copy_if_different "${SOURCE_FILE}.tmp" "${SOURCE_FILE}"
        )
