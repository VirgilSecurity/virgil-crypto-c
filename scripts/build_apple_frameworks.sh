#!/bin/bash
#   Copyright (C) 2015-2021 Virgil Security, Inc.
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

# Color constants
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_RESET='\033[0m'

function show_info {
    echo -e "${COLOR_GREEN}[INFO] $@${COLOR_RESET}"
}

function show_error {
    echo -e "${COLOR_RED}[ERROR] $@${COLOR_RESET}"
    exit 1
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

function make_xcarchive {
    # Define name of the framework
    if [ ! -z "$1" ]; then
        FRAMEWORK_NAME="$1"
    else
        show_error "Error. Framework name is not defined."
    fi

    # Define input directory
    if [ ! -z "$2" ]; then
        INDIR="$2"
    else
        show_error "Error. Input directory is not defined."
    fi

    # Define output directory
    if [ ! -z "$3" ]; then
        OUTDIR="$3"
    else
        show_error "Error. Output directory is not defined."
    fi

    # Create output dir
    mkdir -p "$OUTDIR"

    # Remove output xcframework if exists
    OUTPUT_FRAMEWORK="${OUTDIR}/${FRAMEWORK_NAME}.xcframework"
    rm -fr "${OUTPUT_FRAMEWORK}"

    # Find all frameworks with a given name
    FRAMEWORKS=$(find "${INDIR}" -name "${FRAMEWORK_NAME}.framework" | tr '\n' ' ')

    if [ -z "${FRAMEWORKS}" ]; then
        show_error "Frameworks named'${FRAMEWORK_NAME}.framework'" \
                "are not found within directory: ${INDIR}."
    fi

    # Get frameworks binary
    FRAMEWORKS_XCODEBUILD_ARGS=""
    for framework in ${FRAMEWORKS}; do
        FRAMEWORKS_XCODEBUILD_ARGS+="-framework ${framework} "
    done
    echo "${FRAMEWORKS_XCODEBUILD_ARGS}"

    # Create XCFramework
    xcodebuild -create-xcframework ${FRAMEWORKS_XCODEBUILD_ARGS} -output "${OUTDIR}/${FRAMEWORK_NAME}.xcframework"
}

command -v cmake >/dev/null 2>&1 || show_error "Required utility CMake is not found."


SCRIPT_DIR=$(dirname "$(abspath "${BASH_SOURCE[0]}")")
ROOT_DIR=$(abspath "${SCRIPT_DIR}/..")
SRC_DIR="${ROOT_DIR}"
BUILD_DIR="${ROOT_DIR}/build_apple"
if [ -d "$1" ]; then
    DESTINATION_DIR="$1"
else
    DESTINATION_DIR="${BUILD_DIR}/VSCFrameworks"
fi
IOS_DESTINATION_DIR="${DESTINATION_DIR}/iOS"
MACOS_DESTINATION_DIR="${DESTINATION_DIR}/macOS"
TVOS_DESTINATION_DIR="${DESTINATION_DIR}/tvOS"
WATCHOS_DESTINATION_DIR="${DESTINATION_DIR}/watchOS"
XCFRAMEWORKS_DESTINATION_DIR="${DESTINATION_DIR}/VSCCrypto-XCFrameworks"

rm -fr "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
mkdir -p "${DESTINATION_DIR}"
mkdir -p "${IOS_DESTINATION_DIR}"
mkdir -p "${MACOS_DESTINATION_DIR}"
mkdir -p "${TVOS_DESTINATION_DIR}"
mkdir -p "${WATCHOS_DESTINATION_DIR}"

CMAKE_ARGS=""
CMAKE_ARGS+=" -DCMAKE_BUILD_TYPE=Release"
CMAKE_ARGS+=" -DBUILD_SHARED_LIBS=YES"
CMAKE_ARGS+=" -DPB_NO_PACKED_STRUCTS=YES"
CMAKE_ARGS+=" -DVIRGIL_LIB_RATCHET=YES"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_HDRS=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_CMAKE=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_DEPS_HDRS=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_DEPS_LIBS=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_DEPS_CMAKE=NO"
CMAKE_ARGS+=" -DCMAKE_TOOLCHAIN_FILE='${ROOT_DIR}/cmake/apple.cmake'"


function build_ios {
    show_info "Build C Frameworks for iOS..."

    local BUILD_DIR="${1}/build"
    local FRAMEWORKS_DIR=$2

    rm -fr "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=IOS \
                        -DRELIC_USE_PTHREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=dev \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/dev"
    cmake --build "${BUILD_DIR}/dev" --target install -- -j8

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=IOS_SIM \
                        -DRELIC_USE_PTHREAD=OFF \
                        -DCMAKE_INSTALL_LIBDIR=sim \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/sim"
    cmake --build "${BUILD_DIR}/sim" --target install -- -j8

    show_info "Installed iOS C Frameworks to ${FRAMEWORKS_DIR}"
}

function build_tvos {
    show_info "Build C Frameworks for tvOS..."

    local BUILD_DIR="${1}/build"
    local FRAMEWORKS_DIR=$2

    rm -fr "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=TVOS \
                        -DRELIC_USE_PTHREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=dev \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/dev"
    cmake --build "${BUILD_DIR}/dev" --target install -- -j8

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=TVOS_SIM \
                        -DRELIC_USE_PTHREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=sim \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/sim"
    cmake --build "${BUILD_DIR}/sim" --target install -- -j8

    show_info "Installed tvOS C Frameworks to ${FRAMEWORKS_DIR}"
}

function build_watchos {
    show_info "Build C Frameworks for watchOS..."

    local BUILD_DIR="${1}/build"
    local FRAMEWORKS_DIR=$2

    rm -fr "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=WATCHOS \
                        -DRELIC_USE_PTHREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=dev \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/dev"
    cmake --build "${BUILD_DIR}/dev" --target install -- -j8

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=WATCHOS_SIM \
                        -DRELIC_USE_PTHREAD=OFF \
                        -DCMAKE_INSTALL_LIBDIR=sim \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/sim"
    cmake --build "${BUILD_DIR}/sim" --target install -- -j8

    show_info "Installed watchOS C Frameworks for to ${FRAMEWORKS_DIR}"
}

function build_macosx {
    show_info "Build C Frameworks for macOS..."

    local BUILD_DIR="${1}/build"
    local FRAMEWORKS_DIR=$2

    rm -fr "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    cmake ${CMAKE_ARGS} -DCMAKE_INSTALL_PREFIX="${FRAMEWORKS_DIR}" \
                        -DAPPLE_PLATFORM=MACOS \
                        -DRELIC_USE_PTHREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=dev \
                        -H"${SRC_DIR}" -B"${BUILD_DIR}/dev"
    cmake --build "${BUILD_DIR}/dev" --target install -- -j8

    show_info "Installed macOS C Frameworks to ${FRAMEWORKS_DIR}"
}

build_ios "${BUILD_DIR}/iOS" "${IOS_DESTINATION_DIR}"
build_tvos "${BUILD_DIR}/tvOS" "${TVOS_DESTINATION_DIR}"
build_watchos "${BUILD_DIR}/watchOS" "${WATCHOS_DESTINATION_DIR}"
build_macosx "${BUILD_DIR}/macOS" "${MACOS_DESTINATION_DIR}"

make_xcarchive VSCCommon "${DESTINATION_DIR}" "${XCFRAMEWORKS_DESTINATION_DIR}"
make_xcarchive VSCFoundation "${DESTINATION_DIR}" "${XCFRAMEWORKS_DESTINATION_DIR}"
make_xcarchive VSCPythia "${DESTINATION_DIR}" "${XCFRAMEWORKS_DESTINATION_DIR}"
make_xcarchive VSCRatchet "${DESTINATION_DIR}" "${XCFRAMEWORKS_DESTINATION_DIR}"


PREPARE_RELEASE="YES"

if [ $PREPARE_RELEASE == "YES" ]; then
    # ZIP xcfameworks separately
    pushd "${XCFRAMEWORKS_DESTINATION_DIR}"
        # Find all xcframeworks to zip
        XCFRAMEWORKS=$(find . -name "*.xcframework" | xargs basename -a | tr '\n' ' ')

        # ZIP xcfameworks
        for xcframework in ${XCFRAMEWORKS}; do
            zip --symlinks -r "${xcframework}.zip" "${xcframework}"
            mv "${xcframework}.zip" "${DESTINATION_DIR}"
        done
    popd

    # ZIP xcfameworks all-in-one
    cp -p -R "${ROOT_DIR}/LICENSE" "${XCFRAMEWORKS_DESTINATION_DIR}"

    pushd "${DESTINATION_DIR}"
        zip --symlinks -r VSCCrypto.xcframework.zip "VSCCrypto-XCFrameworks"
    popd
fi
