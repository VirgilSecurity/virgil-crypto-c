#
# Copyright (C) 2015-2021 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

# This little macro lets you set any XCode specific property
macro(set_xcode_property TARGET XCODE_PROPERTY XCODE_VALUE)
    set_property(TARGET ${TARGET} PROPERTY XCODE_ATTRIBUTE_${XCODE_PROPERTY} ${XCODE_VALUE})
endmacro(set_xcode_property)


# This function uses this toolchain variables to configure
# given target as an Apple Framework
#
# target_apple_framework(<target>
#                        [NAME name]
#                        [VERSION version]
#                        [MODULE_MAP filepath]
#                        [IDENTIFIER identifier]
#                        [DEVELOPMENT_TEAM team]
#                        [CODE_SIGN_IDENTITY identity]
#                        [CODE_SIGN])
#
# Required target properties:
#   - VERSION
#   - SOVERSION
#   - PUBLIC_HEADER
function(target_apple_framework target)
    #
    # Parse arguments
    #
    set(_option_value CODE_SIGN)
    set(_one_value NAME VERSION MODULE_MAP IDENTIFIER DEVELOPMENT_TEAM CODE_SIGN_IDENTITY)
    cmake_parse_arguments(FRAMEWORK "${_option_value}" "${_one_value}" "" ${ARGN})

    if(FRAMEWORK_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unexpected argument: ${FRAMEWORK_UNPARSED_ARGUMENTS}")
    endif()

    if(NOT FRAMEWORK_NAME)
        message(FATAL_ERROR "Required argument is not given: FRAMEWORK_NAME")
    endif()

    if(NOT FRAMEWORK_IDENTIFIER)
        message(FATAL_ERROR "Required argument is not given: FRAMEWORK_IDENTIFIER")
    endif()

    if(NOT FRAMEWORK_VERSION)
        set(FRAMEWORK_VERSION "A")
    endif()

    #
    # Configure Info.plist
    #
    get_target_property(BUNDLE_VERSION ${target} VERSION)
    get_target_property(BUNDLE_SOVERSION ${target} SOVERSION)

    if(NOT BUNDLE_VERSION)
        set(BUNDLE_VERSION "${PROJECT_VERSION}")
    endif()

    if(NOT BUNDLE_SOVERSION)
        set(BUNDLE_SOVERSION "${PROJECT_VERSION_MAJOR}")
    endif()

    if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/Info.plist.in")
        configure_file(
            "${CMAKE_CURRENT_LIST_DIR}/Info.plist.in"
            "${CMAKE_CURRENT_BINARY_DIR}/Info.plist"
        )
    else()
        set(INFO_PLIST_FILE "${CMAKE_CURRENT_BINARY_DIR}/Info.plist")
        file(WRITE "${INFO_PLIST_FILE}" "")
        file(APPEND "${INFO_PLIST_FILE}" "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        file(APPEND "${INFO_PLIST_FILE}" "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
        file(APPEND "${INFO_PLIST_FILE}" "<plist version=\"1.0\">\n")
        file(APPEND "${INFO_PLIST_FILE}" "<dict>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleDevelopmentRegion</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>en</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleExecutable</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>${FRAMEWORK_NAME}</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleIdentifier</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>${FRAMEWORK_IDENTIFIER}</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleInfoDictionaryVersion</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>6.0</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundlePackageType</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>FMWK</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleSignature</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>????</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleVersion</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>${BUNDLE_SOVERSION}</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CFBundleShortVersionString</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>${BUNDLE_VERSION}</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>CSResourcesFileMapped</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <true/>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <key>MinimumOSVersion</key>\n")
        file(APPEND "${INFO_PLIST_FILE}" "    <string>${APPLE_DEPLOYMENT_TARGET}</string>\n")
        file(APPEND "${INFO_PLIST_FILE}" "</dict>\n")
        file(APPEND "${INFO_PLIST_FILE}" "</plist>\n")
        file(APPEND "${INFO_PLIST_FILE}" "")
    endif()

    set_target_properties(${target} PROPERTIES
        MACOSX_FRAMEWORK_INFO_PLIST "${CMAKE_CURRENT_BINARY_DIR}/Info.plist"
    )

    #
    # Set common framework attributes
    #
    set_target_properties(${target} PROPERTIES
        FRAMEWORK TRUE
        FRAMEWORK_VERSION ${FRAMEWORK_VERSION}
        OUTPUT_NAME "${FRAMEWORK_NAME}"
        MACOSX_FRAMEWORK_IDENTIFIER ${FRAMEWORK_IDENTIFIER}
        MACOSX_FRAMEWORK_INFO_PLIST "${CMAKE_CURRENT_BINARY_DIR}/Info.plist"
    )

    set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS "-all_load")

    #
    # Set module.modulemap
    #
    if(NOT FRAMEWORK_MODULE_MAP AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/module.modulemap")
        set(FRAMEWORK_MODULE_MAP "${CMAKE_CURRENT_LIST_DIR}/module.modulemap")
    endif()

    if(FRAMEWORK_MODULE_MAP)
        target_sources (${target} PRIVATE "${FRAMEWORK_MODULE_MAP}")

        set_property(
            SOURCE "${FRAMEWORK_MODULE_MAP}"
            PROPERTY MACOSX_PACKAGE_LOCATION "Modules"
        )

        if (APPLE_PLATFORM STREQUAL "MACOS")
            add_custom_command(
                TARGET ${target}
                POST_BUILD
                COMMAND cmake -E create_symlink "Versions/Current/Modules" "$<TARGET_BUNDLE_DIR:${target}>/Modules"
            )
        endif()
    endif ()


    #
    # Set Xcode attributes:
    #   - XCODE_ATTRIBUTE_{APPLE_PLATFORM}_DEPLOYMENT_TARGET
    #   - XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY
    #
    if(APPLE_PLATFORM MATCHES "IOS")
        set_xcode_property(${target} IPHONEOS_DEPLOYMENT_TARGET "${IOS_DEPLOYMENT_TARGET}")

    elseif(APPLE_PLATFORM MATCHES "WATCHOS")
        set_xcode_property(${target} WATCHOS_DEPLOYMENT_TARGET "${WATCHOS_DEPLOYMENT_TARGET}")

    elseif(APPLE_PLATFORM MATCHES "TVOS")
        set_xcode_property(${target} TVOS_DEPLOYMENT_TARGET "${TVOS_DEPLOYMENT_TARGET}")

    elseif(APPLE_PLATFORM MATCHES "MACOS")
        set_xcode_property(${target} MACOSX_DEPLOYMENT_TARGET "${MACOS_DEPLOYMENT_TARGET}")

    endif()

    set_xcode_property(${target} TARGETED_DEVICE_FAMILY "${APPLE_DEVICE_FAMILY}")

    if (FRAMEWORK_CODE_SIGN)
        set_xcode_property(${target} DEVELOPMENT_TEAM "${FRAMEWORK_DEVELOPMENT_TEAM}")
        set_xcode_property(${target} CODE_SIGN_IDENTITY "${FRAMEWORK_CODE_SIGN_IDENTITY}")
    endif()

    #
    # Sign framework
    #
    if(FRAMEWORK_CODE_SIGN AND NOT CMAKE_GENERATOR STREQUAL "Xcode")
        if(NOT FRAMEWORK_CODE_SIGN_IDENTITY)
            # Ad-Hoc codesign
            set(NO_CODE_SIGN_IDENTITY "-")
        endif()

        add_custom_target(sign-${target} ALL
            COMMAND /usr/bin/codesign
                    --force $<TARGET_FILE_DIR:${target}>
                    --sign "${FRAMEWORK_CODE_SIGN_IDENTITY}" "${NO_CODE_SIGN_IDENTITY}"
            DEPENDS ${target}
            COMMENT "Sign the framework with identity: ${FRAMEWORK_CODE_SIGN_IDENTITY} ${NO_CODE_SIGN_IDENTITY}"
        )
    endif()
endfunction(target_apple_framework)
