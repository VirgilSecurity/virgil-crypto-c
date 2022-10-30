#!/bin/bash
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

# Abort if something went wrong
set -e

function abspath() {
  (
    if [ -d "$1" ]; then
        cd "$1" && pwd -P
    else
        echo "$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
    fi
  )
}

# sed_replace <from> <to> <file>
function sed_replace {
    if [ "$(uname -s)" == "Darwin" ]; then
        sed -i "" -E "s/$1/$2/g" "$3"
    else
        sed -i"" -r "s/$1/$2/g" "$3"
    fi
}

SCRIPT_DIR=$(dirname "$(abspath "${BASH_SOURCE[0]}")")
ROOT_DIR=$(abspath "${SCRIPT_DIR}/..")
BINARIES_DIR="${ROOT_DIR}/binaries"

# Update xcframeworks binaries
for xcframework in $(find "${ROOT_DIR}/build_apple/VSCFrameworks" -name "*.xcframework.zip"); do
    echo "Processing: ${xcframework}"

    digest=$(shasum -a 256 "${xcframework}" | awk '{ print $1 }')

    filename=$(basename -- "${xcframework}")
    short_name="${filename%.*.*}"
    short_name="${short_name:3}"

    echo "Updating SPM hash digest for '${filename}' to '${digest}'"
    sed_replace "(let +vsc${short_name}Checksum.+)" "let vsc${short_name}Checksum = \"${digest}\"" "${ROOT_DIR}/Package.swift"
done
