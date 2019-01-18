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

# Abort if something went wrong
set -e

function show_info {
    echo -e "[INFO ] $@"
}

function show_error {
    echo -e "[ERROR] $@" >&2
    echo "Aborting."
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

function make_fat_framework {
    # Define name of the fat library
    if [ ! -z "$1" ]; then
        FRAMEWORK_NAME="$1"
    else
        show_error "Error. Framework name is not defined."
    fi

    # Define install directory
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

    # Remove output framework if exists
    OUTPUT_FRAMEWORK="${OUTDIR}/${FRAMEWORK_NAME}.framework"
    rm -fr "${OUTPUT_FRAMEWORK}"

    # Find all frameworks with given name
    FRAMEWORKS=$(find "${INDIR}" -name "${FRAMEWORK_NAME}.framework" | tr '\n' ' ')

    if [ -z "${FRAMEWORKS}" ]; then
        show_error "Frameworks named'${FRAMEWORK_NAME}.framework'" \
                "are not found within directory: ${INDIR}."
    fi

    # Get frameworks binary
    FRAMEWORKS_BIN=""
    for framework in ${FRAMEWORKS}; do
        FRAMEWORKS_BIN+=$(find "${framework}" -type f -perm +111 -name "${FRAMEWORK_NAME}")
        FRAMEWORKS_BIN+=" "
    done

    # Copy first framework to the output and remove it's binary and *.swiftmodule
    rsync --recursive --links "$(echo "${FRAMEWORKS}" | awk '{print $1}')/" "${OUTPUT_FRAMEWORK}"
    OUTPUT_FRAMEWORK_BIN=$(find "${OUTPUT_FRAMEWORK}" -type f -perm +111 -name "${FRAMEWORK_NAME}")
    OUTPUT_FRAMEWORK_SWIFTMODULE_DIR="${OUTPUT_FRAMEWORK}/Modules/${FRAMEWORK_NAME}.swiftmodule"
    rm "${OUTPUT_FRAMEWORK_BIN}"

    if [ -d "${OUTPUT_FRAMEWORK_SWIFTMODULE_DIR}/" ]; then
        rm -fr -- "${OUTPUT_FRAMEWORK_SWIFTMODULE_DIR}"
    fi

    # Merge found framework binaries to the output framework
    lipo -create ${FRAMEWORKS_BIN} -o ${OUTPUT_FRAMEWORK_BIN}

    # Copy *.swiftmodule/*
    for framework in ${FRAMEWORKS}; do
        SWIFTMODULE_DIR="${framework}/Modules/${FRAMEWORK_NAME}.swiftmodule"

        if [ -d "${SWIFTMODULE_DIR}/" ]; then
            rsync --recursive --links "${SWIFTMODULE_DIR}/" "${OUTPUT_FRAMEWORK_SWIFTMODULE_DIR}/"
        fi
    done
}


function build_framework {

    local FRAMEWORK_NAME=$1

    local BUILD_DIR="${BUILD_DIR}/Universal"
    local PREBUILT_DIR="${PROJECT_DIR}/Binaries"

    for PLATFORM in iOS watchOS tvOS macOS; do
        show_info "Build ${FRAMEWORK_NAME} framework for ${PLATFORM}"

        SDK=
        SDK_SIM=

        case ${PLATFORM} in
            iOS )
                SDK=iphoneos
                SDK_SIM=iphonesimulator
                ;;
            watchOS )
                SDK=watchos
                SDK_SIM=watchsimulator
                ;;
            tvOS )
                SDK=appletvos
                SDK_SIM=appletvsimulator
                ;;
            macOS )
                SDK=macosx
                ;;
        esac

        if [ ! -z "${SDK}" ]; then
            xcodebuild -target ${FRAMEWORK_NAME}_${PLATFORM} ONLY_ACTIVE_ARCH=NO -configuration Release -sdk ${SDK} BUILD_DIR="${BUILD_DIR}/${PLATFORM}" BUILD_ROOT="${BUILD_ROOT}/${PLATFORM}" clean build
        fi

        if [ ! -z "${SDK_SIM}" ]; then
            xcodebuild -target ${FRAMEWORK_NAME}_${PLATFORM} -configuration Release -sdk ${SDK_SIM} ONLY_ACTIVE_ARCH=NO BUILD_DIR="${BUILD_DIR}/${PLATFORM}" BUILD_ROOT="${BUILD_ROOT}/${PLATFORM}" clean build
        fi

        make_fat_framework "${FRAMEWORK_NAME}" "${BUILD_DIR}/${PLATFORM}" "${PREBUILT_DIR}/${PLATFORM}"
    done
}

build_framework VirgilCryptoCommon
build_framework VirgilCryptoFoundation
build_framework VirgilCryptoRatchet
build_framework VirgilCryptoPythia
