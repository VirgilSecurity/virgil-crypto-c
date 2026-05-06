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

# ###########################################################################
#   Constants.
# ###########################################################################
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_RESET='\033[0m'


# ###########################################################################
#   Helper functions.
# ###########################################################################
function show_info {
    echo -e "${COLOR_GREEN}[INFO    ]  $1${COLOR_RESET}"
}

function show_error {
    echo -e "${COLOR_RED}[ERROR]  $1${COLOR_RESET}"

    #   Second parameter is a flag that tells whether abort script or not.
    if [ $# -eq 2 ]; then
        if [ $2 -ne 0 ]; then
            exit 1
        fi
    else
        exit 1
    fi
}

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
