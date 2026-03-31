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
show_info "Change version within VERSION file."
echo "${VERSION_FULL}" > "${ROOT_DIR}/VERSION"

# ###########################################################################
show_info "Change version within CMakeLists.txt file."
sed_replace "VERSION *[0-9]*\.[0-9]*\.[0-9]" "VERSION ${VERSION}" "${ROOT_DIR}/CMakeLists.txt"
sed_replace "(VIRGIL_CRYPTO_VERSION_LABEL) *\"[a-zA-Z0-9.]*\"" "\1 \"${VERSION_LABEL}\"" "${ROOT_DIR}/CMakeLists.txt"


# ###########################################################################
show_info "Change version within XML in the main.xml."

main_xml_file="${ROOT_DIR}/codegen/main.xml"

main_version_from="version major=\"[0-9]*\".*minor=\"[0-9]*\".*patch=\"[0-9]*\"(.*label=\".*\")?"
if [ -z "${VERSION_LABEL}" ]; then
    main_version_to="version major=\"${VERSION_MAJOR}\" minor=\"${VERSION_MINOR}\" patch=\"${VERSION_PATCH}\""
else
    main_version_to="version major=\"${VERSION_MAJOR}\" minor=\"${VERSION_MINOR}\" patch=\"${VERSION_PATCH}\" label=\"${VERSION_LABEL}\""
fi

sed_replace "${main_version_from}" "${main_version_to}" "${main_xml_file}"


# ###########################################################################
show_info "Change version within XML project files."

XML_PROJECT_FILES=$(find "${ROOT_DIR}/codegen/models" -name "project_*.xml" | tr '\n' ' ')

for project_file in ${XML_PROJECT_FILES}; do
    project_version_from="version major=\"[0-9]*\".*minor=\"[0-9]*\".*patch=\"[0-9]*\""
    project_version_to="version major=\"${VERSION_MAJOR}\" minor=\"${VERSION_MINOR}\" patch=\"${VERSION_PATCH}\""

    sed_replace "${project_version_from}" "${project_version_to}" "${project_file}"
done

# ###########################################################################
show_info "Change version within C header files."

C_HEADER_FILES=$(find "${ROOT_DIR}/library" -name "*_library.h" | tr '\n' ' ')

for header_file in ${C_HEADER_FILES}; do
    sed_replace "(#define *[A-Z]{3,4}_VERSION_MAJOR).*$" "\1 ${VERSION_MAJOR}" "${header_file}"
    sed_replace "(#define *[A-Z]{3,4}_VERSION_MINOR).*$" "\1 ${VERSION_MINOR}" "${header_file}"
    sed_replace "(#define *[A-Z]{3,4}_VERSION_PATCH).*$" "\1 ${VERSION_PATCH}" "${header_file}"
done

# ###########################################################################
show_info "Change version within PHP wrapper files."

PHP_SOURCE_FILES=$(find "${ROOT_DIR}/wrappers/php" -name "vsc*.c" | tr '\n' ' ')

for source_file in ${PHP_SOURCE_FILES}; do
    sed_replace "([A-Z_]*_PHP_VERSION\[\] *= *)\"[0-9]*.[0-9]*.[0-9]*\".*$" "\1\"${VERSION}\";" "${source_file}"
done

# ###########################################################################
show_info "Change version within Python wrapper files."

# Build PEP 440 version: strip hyphen, map alpha->a, beta->b, strip dots in label
if [ -z "${VERSION_LABEL}" ]; then
    VERSION_PEP440="${VERSION}"
else
    # Normalize: strip dots within label (e.g. dev.1 -> dev1)
    PEP440_LABEL="${VERSION_LABEL//./}"
    # Map long pre-release names to PEP 440 abbreviations
    PEP440_LABEL="${PEP440_LABEL/alpha/a}"
    PEP440_LABEL="${PEP440_LABEL/beta/b}"
    # dev releases use a dot separator in PEP 440 (e.g. 0.17.2.dev1)
    if [[ $PEP440_LABEL == dev* ]]; then
        VERSION_PEP440="${VERSION}.${PEP440_LABEL}"
    else
        VERSION_PEP440="${VERSION}${PEP440_LABEL}"
    fi
fi

sed_replace "__version__ = \".*\"" "__version__ = \"${VERSION_PEP440}\"" "${ROOT_DIR}/wrappers/python/virgil_crypto_lib/__init__.py"

if [ ! -z "${VERSION_LABEL}" ]; then
    if [[ $VERSION_LABEL == *"alpha"* ]]; then
        sed_replace "\"Development Status :: .*\"" "\"Development Status :: 3 - Alpha\"" "${ROOT_DIR}/wrappers/python/pyproject.toml"
    elif [[ $VERSION_LABEL == *"beta"* ]] || [[ $VERSION_LABEL == *"rc"* ]]; then
        sed_replace "\"Development Status :: .*\"" "\"Development Status :: 4 - Beta\"" "${ROOT_DIR}/wrappers/python/pyproject.toml"
    else
        sed_replace "\"Development Status :: .*\"" "\"Development Status :: 2 - Pre-Alpha\"" "${ROOT_DIR}/wrappers/python/pyproject.toml"
    fi
else
    sed_replace "\"Development Status :: .*\"" "\"Development Status :: 5 - Production\/Stable\"" "${ROOT_DIR}/wrappers/python/pyproject.toml"
fi

# ###########################################################################
show_info "Change version within Java project files."
pushd ${ROOT_DIR}/wrappers/java >/dev/null
./mvnw versions:set -DnewVersion="${VERSION_FULL}" >/dev/null
popd >/dev/null

# ###########################################################################
show_info "Change version within Android project files."
sed_replace "version \".*\"" "version \"${VERSION_FULL}\"" "${ROOT_DIR}/wrappers/java/android/build.gradle"

# ###########################################################################
show_info "Change version within JS package.json file."
sed_replace "(\"version\")[^,]+([,]?)" "\1: \"${VERSION}\"\2" "${ROOT_DIR}/wrappers/wasm/package.json"

# ###########################################################################
show_info "Add version within Carthage spec files."
for PROJ in VSCCommon VSCFoundation VSCPythia VSCRatchet; do
cat <<EOF > "${ROOT_DIR}/carthage-specs/${PROJ}.json"
{
    "${VERSION_FULL}": "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v${VERSION_FULL}/${PROJ}.xcframework.zip"
}
EOF
done

# ###########################################################################
show_info "Change version within Package.swift"
sed_replace "(let +version.+)" "let version = \"${VERSION_FULL}\"" "${ROOT_DIR}/Package.swift"
