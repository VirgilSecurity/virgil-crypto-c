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


# ---------------------------------------------------------------------------
#   Round5 use "restrict" C99 keyword, but MSVC does not support it.
# ---------------------------------------------------------------------------

if(NOT SOURCE_FILE)
    message(FATAL_ERROR "Expected variable SOURCE_FILE")
endif()

if(NOT EXISTS "${SOURCE_FILE}")
    message(FATAL_ERROR "Variable SOURCE_FILE contains not existent path: ${SOURCE_FILE}")
endif()

set(PATCH_STR "
#if defined(_MSC_VER) && _MSC_VER >= 1400
#   ifndef restrict
#       define restrict __restrict
#   else
#       define restrict
#   endif
#endif

")

file(READ "${SOURCE_FILE}" file_content)
string(REGEX MATCH "define restrict __restrict" ALREADY_PATCHED "${file_content}")
if(NOT ALREADY_PATCHED)
    string(REGEX REPLACE
        "#ifdef __cplusplus(\r?\n?)extern"
        "${PATCH_STR}#ifdef __cplusplus\\1extern" file_content "${file_content}"
        )
    file(WRITE "${SOURCE_FILE}" "${file_content}")
endif()
