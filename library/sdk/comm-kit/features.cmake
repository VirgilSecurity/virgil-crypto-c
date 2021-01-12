#   @license
#   -------------------------------------------------------------------------
#   Copyright (C) 2015-2020 Virgil Security, Inc.
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
#   -------------------------------------------------------------------------

#   @warning
#   -------------------------------------------------------------------------
#   This file is fully generated by script 'cmake_files_codegen.gsl'.
#   It can be changed temporary for debug purposes only.
#   -------------------------------------------------------------------------
#   @end


include_guard()

option(VSSQ_LIBRARY "Enable build of the 'comm kit' library" ON)
option(VSSQ_MULTI_THREADING "Enable multi-threading safety for CommKit." ON)
option(VSSQ_ERROR "Enable class 'error'." ON)
option(VSSQ_ERROR_MESSAGE "Enable class 'error message'." ON)
option(VSSQ_EJABBERD_JWT "Enable class 'ejabberd jwt'." ON)
option(VSSQ_MESSENGER "Enable class 'messenger'." ON)
option(VSSQ_MESSENGER_AUTH "Enable class 'messenger auth'." ON)
option(VSSQ_MESSENGER_CREDS "Enable class 'messenger creds'." ON)
option(VSSQ_MESSENGER_CONFIG "Enable class 'messenger config'." ON)
option(VSSQ_MESSENGER_CONTACTS "Enable class 'messenger contacts'." ON)
option(VSSQ_MESSENGER_USER "Enable class 'messenger user'." ON)
option(VSSQ_MESSENGER_USER_LIST "Enable class 'messenger user list'." ON)
option(VSSQ_MESSENGER_GROUP "Enable class 'messenger group'." ON)
option(VSSQ_MESSENGER_GROUP_EPOCH "Enable class 'messenger group epoch'." ON)
option(VSSQ_MESSENGER_GROUP_EPOCH_LIST "Enable class 'messenger group epoch list'." ON)
option(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE "Enable class 'messenger group epoch keyknox storage'." ON)
option(VSSQ_MESSENGER_FILE_CIPHER "Enable class 'messenger file cipher'." ON)
option(VSSQ_MESSENGER_CLOUD_FS "Enable class 'messenger cloud fs'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE "Enable class 'messenger cloud fs created file'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_FOLDER "Enable class 'messenger cloud fs folder'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO "Enable class 'messenger cloud fs folder info'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST "Enable class 'messenger cloud fs folder info list'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_FILE_INFO "Enable class 'messenger cloud fs file info'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST "Enable class 'messenger cloud fs file info list'." ON)
option(VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO "Enable class 'messenger cloud fs file download info'." ON)
option(VSSQ_CONTACT_UTILS "Enable class 'contact utils'." ON)
mark_as_advanced(
        VSSQ_LIBRARY
        VSSQ_MULTI_THREADING
        VSSQ_ERROR
        VSSQ_ERROR_MESSAGE
        VSSQ_EJABBERD_JWT
        VSSQ_MESSENGER
        VSSQ_MESSENGER_AUTH
        VSSQ_MESSENGER_CREDS
        VSSQ_MESSENGER_CONFIG
        VSSQ_MESSENGER_CONTACTS
        VSSQ_MESSENGER_USER
        VSSQ_MESSENGER_USER_LIST
        VSSQ_MESSENGER_GROUP
        VSSQ_MESSENGER_GROUP_EPOCH
        VSSQ_MESSENGER_GROUP_EPOCH_LIST
        VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE
        VSSQ_MESSENGER_FILE_CIPHER
        VSSQ_MESSENGER_CLOUD_FS
        VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE
        VSSQ_MESSENGER_CLOUD_FS_FOLDER
        VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO
        VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST
        VSSQ_MESSENGER_CLOUD_FS_FILE_INFO
        VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST
        VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO
        VSSQ_CONTACT_UTILS
        )

if(VSSQ_EJABBERD_JWT AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSQ_EJABBERD_JWT depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_EJABBERD_JWT AND NOT VSSC_BASE64_URL)
    message("-- error --")
    message("--")
    message("Feature VSSQ_EJABBERD_JWT depends on the feature:")
    message("     VSSC_BASE64_URL - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_EJABBERD_JWT AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_EJABBERD_JWT depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSC_STR_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSC_STR_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSCF_PADDING_PARAMS)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSCF_PADDING_PARAMS - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSCF_RANDOM_PADDING)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSCF_RANDOM_PADDING - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSCF_RECIPIENT_CIPHER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSCF_RECIPIENT_CIPHER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSSC_CARD_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSSC_CARD_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSSC_CARD_MANAGER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSSC_CARD_MANAGER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSSQ_MESSENGER_GROUP)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSSQ_MESSENGER_GROUP - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER AND NOT VSSQ_MESSENGER_USER_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER depends on the feature:")
    message("     VSSQ_MESSENGER_USER_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSC_DATA)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSC_DATA - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSC_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSC_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSC_STR_MUTABLE)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSC_STR_MUTABLE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSC_STR_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSC_STR_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSC_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSC_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_SHA256)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_SHA256 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_KEY_MATERIAL_RNG)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_KEY_MATERIAL_RNG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_RANDOM)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_RANDOM - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_PRIVATE_KEY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_PRIVATE_KEY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_KEY_PROVIDER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_KEY_PROVIDER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_RECIPIENT_CIPHER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_RECIPIENT_CIPHER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_SIGNER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_SIGNER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_BASE64)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_BASE64 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_BASE64)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_BASE64 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCF_BINARY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCF_BINARY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSCP_PYTHIA)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSCP_PYTHIA - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_VIRGIL_HTTP_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_VIRGIL_HTTP_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_CARD_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_CARD_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_CARD_MANAGER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_CARD_MANAGER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_RAW_CARD)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_RAW_CARD - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSK_KEYKNOX_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSK_KEYKNOX_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSP_PYTHIA_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSP_PYTHIA_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSQ_MESSENGER_CREDS)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSQ_MESSENGER_CREDS - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSQ_MESSENGER_USER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSQ_MESSENGER_USER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_AUTH AND NOT VSSQ_CONTACT_UTILS)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_AUTH depends on the feature:")
    message("     VSSQ_CONTACT_UTILS - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CREDS AND NOT VSCF_KEY_PROVIDER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CREDS depends on the feature:")
    message("     VSCF_KEY_PROVIDER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CREDS AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CREDS depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CREDS AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CREDS depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSC_DATA)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSC_DATA - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSC_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSC_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSC_STR_MUTABLE)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSC_STR_MUTABLE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSC_STR_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSC_STR_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSC_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSC_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_SHA256)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_SHA256 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_KEY_MATERIAL_RNG)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_KEY_MATERIAL_RNG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_RANDOM)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_RANDOM - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_PRIVATE_KEY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_PRIVATE_KEY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_KEY_PROVIDER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_KEY_PROVIDER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_RECIPIENT_CIPHER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_RECIPIENT_CIPHER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_SIGNER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_SIGNER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_BASE64)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_BASE64 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_BASE64)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_BASE64 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCF_BINARY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCF_BINARY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSCP_PYTHIA)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSCP_PYTHIA - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_VIRGIL_HTTP_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_VIRGIL_HTTP_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_CARD_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_CARD_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_CARD_MANAGER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_CARD_MANAGER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_RAW_CARD)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_RAW_CARD - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSK_KEYKNOX_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSK_KEYKNOX_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSP_PYTHIA_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSP_PYTHIA_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSQ_MESSENGER_CREDS)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSQ_MESSENGER_CREDS - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSQ_MESSENGER_USER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSQ_MESSENGER_USER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CONTACTS AND NOT VSSQ_CONTACT_UTILS)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CONTACTS depends on the feature:")
    message("     VSSQ_CONTACT_UTILS - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP AND NOT VSC_STR_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP depends on the feature:")
    message("     VSC_STR_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP AND NOT VSCF_GROUP_SESSION)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP depends on the feature:")
    message("     VSCF_GROUP_SESSION - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP AND NOT VSCF_GROUP_SESSION_TICKET)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP depends on the feature:")
    message("     VSCF_GROUP_SESSION_TICKET - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP AND NOT VSSC_STRING_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP depends on the feature:")
    message("     VSSC_STRING_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP AND NOT VSSQ_MESSENGER_GROUP_EPOCH_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP depends on the feature:")
    message("     VSSQ_MESSENGER_GROUP_EPOCH_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH AND NOT VSSC_JSON_ARRAY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH depends on the feature:")
    message("     VSSC_JSON_ARRAY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH AND NOT VSSC_JSON_ARRAY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH depends on the feature:")
    message("     VSSC_JSON_ARRAY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSSQ_MESSENGER_GROUP_EPOCH_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSSQ_MESSENGER_GROUP_EPOCH_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSCF_BINARY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSCF_BINARY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSCF_KEY_PROVIDER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSCF_KEY_PROVIDER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSCF_RECIPIENT_CIPHER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSCF_RECIPIENT_CIPHER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSSC_VIRGIL_HTTP_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSSC_VIRGIL_HTTP_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE AND NOT VSSK_KEYKNOX_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE depends on the feature:")
    message("     VSSK_KEYKNOX_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_FILE_CIPHER AND NOT VSCF_PRIVATE_KEY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_FILE_CIPHER depends on the feature:")
    message("     VSCF_PRIVATE_KEY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_FILE_CIPHER AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_FILE_CIPHER depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_FILE_CIPHER AND NOT VSC_STR)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_FILE_CIPHER depends on the feature:")
    message("     VSC_STR - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_FILE_CIPHER AND NOT VSSQ_ERROR)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_FILE_CIPHER depends on the feature:")
    message("     VSSQ_ERROR - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSC_STR_MUTABLE)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSC_STR_MUTABLE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSSC_VIRGIL_HTTP_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSSC_VIRGIL_HTTP_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_MESSENGER_CLOUD_FS AND NOT VSSQ_MESSENGER_CLOUD_FS_FOLDER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_MESSENGER_CLOUD_FS depends on the feature:")
    message("     VSSQ_MESSENGER_CLOUD_FS_FOLDER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSC_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSC_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSCF_SHA256)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSCF_SHA256 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSCF_SHA256)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSCF_SHA256 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSCF_BINARY)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSCF_BINARY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSSC_STRING_MAP)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSSC_STRING_MAP - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSSC_STRING_MAP)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSSC_STRING_MAP - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSQ_CONTACT_UTILS AND NOT VSSC_STRING_MAP_BUCKET)
    message("-- error --")
    message("--")
    message("Feature VSSQ_CONTACT_UTILS depends on the feature:")
    message("     VSSC_STRING_MAP_BUCKET - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()
