#!/bin/bash
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
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

set -e

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
        sed -i "" -e "s/$1/$2/g" "$3"
    else
        sed -i"" "s/$1/$2/g" "$3"
    fi
}

# ###########################################################################
#   Variables.
# ###########################################################################
SCRIPT_DIR=$(dirname "$(abspath "${BASH_SOURCE[0]}")")
ROOT_DIR=$(abspath "${SCRIPT_DIR}/..")

# ###########################################################################
#   Parse arguments.
# ###########################################################################
if [ -z "$1" ]; then
    show_error "Version string is not defined as a first positional argument."
fi

VERSION_FULL="$1"

VERSION_ARR=( ${VERSION_FULL//-/ } )
VERSION="${VERSION_ARR[0]}"
VERSION_LABEL="${VERSION_ARR[1]}"

VERSION_ARR=( ${VERSION//./ } )
VERSION_MAJOR="${VERSION_ARR[0]}"
VERSION_MINOR="${VERSION_ARR[1]}"
VERSION_PATCH="${VERSION_ARR[2]}"

# ###########################################################################
show_info "New version is: ${VERSION_FULL}"


# ###########################################################################
show_info "Change verion within VERSION file."
echo "${VERSION_FULL}" > "${ROOT_DIR}/VERSION"

# ###########################################################################
show_info "Change verion within CMakeLists.txt file."
sed_replace "VERSION *[0-9]*\.[0-9]*\.[0-9]" "VERSION ${VERSION}" "${ROOT_DIR}/CMakeLists.txt"
sed_replace "\(VIRGIL_CRYPTO_VERSION_LABEL\) *\"[a-zA-Z0-9_]*\"" "\1 \"${VERSION_LABEL}\"" "${ROOT_DIR}/CMakeLists.txt"


# ###########################################################################
show_info "Change verion within XML project files."

XML_PROJECT_FILES=$(find "${ROOT_DIR}/codegen/models" -name "project_*.xml" | tr '\n' ' ')

for project_file in ${XML_PROJECT_FILES}; do
    project_version_from="version major=\"[0-9]*\".*minor=\"[0-9]*\".*patch=\"[0-9]*\""
    project_version_to="version major=\"${VERSION_MAJOR}\" minor=\"${VERSION_MINOR}\" patch=\"${VERSION_PATCH}\""

    sed_replace "${project_version_from}" "${project_version_to}" "${project_file}"
done

# ###########################################################################
show_info "Change verion within C header files."

C_HEADER_FILES=$(find "${ROOT_DIR}/library" -name "*_library.h" | tr '\n' ' ')

for header_file in ${C_HEADER_FILES}; do
    sed_replace "\(#define *[A-Z]\{3,4\}_VERSION_MAJOR\).*$" "\1 ${VERSION_MAJOR}" "${header_file}"
    sed_replace "\(#define *[A-Z]\{3,4\}_VERSION_MINOR\).*$" "\1 ${VERSION_MINOR}" "${header_file}"
    sed_replace "\(#define *[A-Z]\{3,4\}_VERSION_PATCH\).*$" "\1 ${VERSION_PATCH}" "${header_file}"
done

# ###########################################################################
show_info "Change verion within PHP wrapper files."

PHP_SOURCE_FILES=$(find "${ROOT_DIR}/wrappers/php" -name "vsc*.c" | tr '\n' ' ')

for source_file in ${PHP_SOURCE_FILES}; do
    sed_replace "\([A-Z_]*_PHP_VERSION\[\] *= *\)\"[0-9]*.[0-9]*.[0-9]*\".*$" "\1\"${VERSION}\";" "${source_file}"
done

# ###########################################################################
show_info "Change verion within Java project files."
pushd ${ROOT_DIR}/wrappers/java >/dev/null
if [ -z "${VERSION_LABEL}" ]; then
    ./mvnw versions:set -DnewVersion="${VERSION}" >/dev/null
else
    ./mvnw versions:set -DnewVersion="${VERSION}-SNAPSHOT" >/dev/null
fi
popd >/dev/null

# ###########################################################################
show_info "Change verion within Android project files."

if [ -z "${VERSION_LABEL}" ]; then
    sed_replace "version \".*\"" "version \"${VERSION}\"" "${ROOT_DIR}/wrappers/java/android/build.gradle"
else
    sed_replace "version \".*\"" "version \"${VERSION}-SNAPSHOT\"" "${ROOT_DIR}/wrappers/java/android/build.gradle"
fi
