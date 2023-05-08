#!/bin/bash
#   Copyright (C) 2015-2023 Virgil Security, Inc.
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

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
source "${SCRIPT_DIR}/helpers.sh"


# ###########################################################################
#   Variables.
# ###########################################################################
ROOT_DIR=$(abspath "${SCRIPT_DIR}/..")

# ###########################################################################
#   Parse arguments.
# ###########################################################################
if [ -z "$1" ]; then
    show_error "USAGE ./copy_wasm_binaries <from> <to>"
fi

if [ -z "$2" ]; then
    show_error "USAGE ./copy_wasm_binaries <from> <to>"
fi

FROM_DIR=$(abspath "$1")
TO_DIR=$(abspath "$2")
DIST_DIR="${FROM_DIR}/wrappers/wasm/dist"

# ###########################################################################
show_info "From dir: ${DIST_DIR}"
show_info "To dir: ${TO_DIR}"

mkdir -p "${TO_DIR}"

FILES_TO_COPY=($(find "${DIST_DIR}" -name "*.js" -o -name "*.wasm"))
if [ ${#FILES_TO_COPY[@]} -eq 0 ]; then
    show_error "Nothing to copy, JS files were not found within ${DIST_DIR}"
fi

for file in ${FILES_TO_COPY[@]}; do
    lib_name=$(basename "$(dirname "${file}")")
    destination="${TO_DIR}/core-${lib_name}"
    show_info "Copy file:\n    from: ${file}\n    to:   ${destination}"
    cp -f "${file}" "${destination}"
done
