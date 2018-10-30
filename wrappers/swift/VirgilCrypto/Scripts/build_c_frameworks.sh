#!/bin/bash
#   Copyright (C) 2015-2018 Virgil Security Inc.
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

    # Copy first framework to the output and remove it's binary
    rsync --recursive --links "$(echo "${FRAMEWORKS}" | awk '{print $1}')/" "${OUTPUT_FRAMEWORK}"
    OUTPUT_FRAMEWORK_BIN=$(find "${OUTPUT_FRAMEWORK}" -type f -perm +111 -name "${FRAMEWORK_NAME}")
    rm "${OUTPUT_FRAMEWORK_BIN}"

    # Merge found framework binaries to the output framework
    lipo -create ${FRAMEWORKS_BIN} -o ${OUTPUT_FRAMEWORK_BIN}
}


command -v cmake >/dev/null 2>&1 || show_error "Required utility CMake is not found."

ROOT_DIR=$(abspath "${PROJECT_DIR}/../../..")
SRC_DIR="${ROOT_DIR}"
INSTALL_DIR="${BUILD_DIR}/VSCFrameworks/install"
BUILD_DIR="${BUILD_DIR}/VSCFrameworks/build"
PREBUILT_DIR="${PROJECT_DIR}/Binaries"
IOS_PREBUILT_DIR="${PREBUILT_DIR}/iOS"
MACOS_PREBUILT_DIR="${PREBUILT_DIR}/macOS"
TVOS_PREBUILT_DIR="${PREBUILT_DIR}/tvOS"
WATCHOS_PREBUILT_DIR="${PREBUILT_DIR}/watchOS"

mkdir -p "${INSTALL_DIR}"
mkdir -p "${BUILD_DIR}"
mkdir -p "${PREBUILT_DIR}"
mkdir -p "${IOS_PREBUILT_DIR}"
mkdir -p "${MACOS_PREBUILT_DIR}"
mkdir -p "${TVOS_PREBUILT_DIR}"
mkdir -p "${WATCHOS_PREBUILT_DIR}"

show_info "Go to the build directory and cleanup."

cd "${INSTALL_DIR}" && rm -fr -- *
cd "${BUILD_DIR}" && rm -fr -- *

CMAKE_ARGS=""
CMAKE_ARGS+=" -DCMAKE_INSTALL_PREFIX='${INSTALL_DIR}'"
CMAKE_ARGS+=" -DBUILD_SHARED_LIBS=YES"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_HDRS=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_CMAKE=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_DEPS_HDRS=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_DEPS_LIBS=NO"
CMAKE_ARGS+=" -DVIRGIL_INSTALL_DEPS_CMAKE=NO"
CMAKE_ARGS+=" -DCMAKE_TOOLCHAIN_FILE='${ROOT_DIR}/cmake/apple.cmake'"

function build_ios {
    show_info "Build C Frameworks for iOS..."

    if [ -d "${IOS_PREBUILT_DIR}/VSCCommon.framework" ] && \
            [ -d "${IOS_PREBUILT_DIR}/VSCFoundation.framework" ] && \
            [ -d "${IOS_PREBUILT_DIR}/VSCPythia.framework" ] && \
            [ -d "${IOS_PREBUILT_DIR}/VSCRatchet.framework" ]; then

        show_info "Requested binaries is found in the '${IOS_PREBUILT_DIR}' folder."
        return 0
    fi

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=IOS \
                        -DVSCP_MULTI_THREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=lib/dev "${SRC_DIR}"
    make -j8 install

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=IOS_SIM \
                        -DVSCP_MULTI_THREAD=OFF \
                        -DCMAKE_INSTALL_LIBDIR=lib/sim "${SRC_DIR}"
    make -j8 install

    make_fat_framework VSCCommon "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCFoundation "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCPythia "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCRatchet "${INSTALL_DIR}" "${INSTALL_DIR}"

    rm -fr -- "${INSTALL_DIR}/lib"
    cp -fa "${INSTALL_DIR}/." "${IOS_PREBUILT_DIR}/"
}

function build_tvos {
    show_info "Build C Frameworks for tvOS..."

    if [ -d "${TVOS_PREBUILT_DIR}/VSCCommon.framework" ] && \
            [ -d "${TVOS_PREBUILT_DIR}/VSCFoundation.framework" ] && \
            [ -d "${TVOS_PREBUILT_DIR}/VSCPythia.framework" ] && \
            [ -d "${TVOS_PREBUILT_DIR}/VSCRatchet.framework" ]; then

        show_info "Requested binaries is found in the '${TVOS_PREBUILT_DIR}' folder."
        return 0
    fi

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=TVOS \
                        -DVSCP_MULTI_THREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=lib/dev "${SRC_DIR}"
    make -j8 install

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=TVOS_SIM \
                        -DVSCP_MULTI_THREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=lib/sim "${SRC_DIR}"
    make -j8 install

    make_fat_framework VSCCommon "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCFoundation "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCPythia "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCRatchet "${INSTALL_DIR}" "${INSTALL_DIR}"

    rm -fr -- "${INSTALL_DIR}/lib"
    cp -fa "${INSTALL_DIR}/." "${TVOS_PREBUILT_DIR}/"
}

function build_watchos {
    show_info "Build C Frameworks for watchOS..."

    if [ -d "${WATCHOS_PREBUILT_DIR}/VSCCommon.framework" ] && \
            [ -d "${WATCHOS_PREBUILT_DIR}/VSCFoundation.framework" ] && \
            [ -d "${WATCHOS_PREBUILT_DIR}/VSCPythia.framework" ] && \
            [ -d "${WATCHOS_PREBUILT_DIR}/VSCRatchet.framework" ]; then

        show_info "Requested binaries is found in the '${WATCHOS_PREBUILT_DIR}' folder."
        return 0
    fi

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=WATCHOS \
                        -DVSCP_MULTI_THREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=lib/dev "${SRC_DIR}"
    make -j8 install

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=WATCHOS_SIM \
                        -DVSCP_MULTI_THREAD=OFF \
                        -DCMAKE_INSTALL_LIBDIR=lib/sim "${SRC_DIR}"
    make -j8 install

    make_fat_framework VSCCommon "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCFoundation "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCPythia "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCRatchet "${INSTALL_DIR}" "${INSTALL_DIR}"

    rm -fr -- "${INSTALL_DIR}/lib"
    cp -fa "${INSTALL_DIR}/." "${WATCHOS_PREBUILT_DIR}/"
}

function build_macosx {
    show_info "Build C Frameworks for macOS..."

    if [ -d "${MACOS_PREBUILT_DIR}/VSCCommon.framework" ] && \
            [ -d "${MACOS_PREBUILT_DIR}/VSCFoundation.framework" ] && \
            [ -d "${MACOS_PREBUILT_DIR}/VSCPythia.framework" ] && \
            [ -d "${MACOS_PREBUILT_DIR}/VSCRatchet.framework" ]; then

        show_info "Requested binaries is found in the '${MACOS_PREBUILT_DIR}' folder."
        return 0
    fi

    rm -fr -- *
    cmake ${CMAKE_ARGS} -DAPPLE_PLATFORM=MACOS \
                        -DVSCP_MULTI_THREAD=ON \
                        -DCMAKE_INSTALL_LIBDIR=lib/dev "${SRC_DIR}"
    make -j8 install

    make_fat_framework VSCCommon "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCFoundation "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCPythia "${INSTALL_DIR}" "${INSTALL_DIR}"
    make_fat_framework VSCRatchet "${INSTALL_DIR}" "${INSTALL_DIR}"

    rm -fr -- "${INSTALL_DIR}/lib"
    cp -fa "${INSTALL_DIR}/." "${MACOS_PREBUILT_DIR}/"
}

case "${PLATFORM_NAME}" in
    "iphoneos")
    build_ios
    ;;
    "iphonesimulator")
    build_ios
    ;;
    "appletv")
    build_tvos
    ;;
    "appletvsimulator")
    build_tvos
    ;;
    "watch")
    build_watchos
    ;;
    "watchsimulator")
    build_watchos
    ;;
    "macosx")
    build_macosx
    ;;
    *)
    show_error "Unsupported platform: ${PLATFORM_NAME}"
    ;;
esac
