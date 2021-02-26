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

if(NOT TARGET comm_kit)
    message(FATAL_ERROR "Expected target 'comm_kit' to be defined first.")
endif()

target_compile_definitions(comm_kit
        PUBLIC
            $<BUILD_INTERFACE:VSSQ_INTERNAL_BUILD>
            "VSSQ_SHARED_LIBRARY=$<BOOL:${BUILD_SHARED_LIBS}>"
            "VSSQ_LIBRARY=$<BOOL:${VSSQ_LIBRARY}>"
            "VSSQ_MULTI_THREADING=$<BOOL:${VSSQ_MULTI_THREADING}>"
            "VSSQ_ERROR=$<BOOL:${VSSQ_ERROR}>"
            "VSSQ_ERROR_MESSAGE=$<BOOL:${VSSQ_ERROR_MESSAGE}>"
            "VSSQ_EJABBERD_JWT=$<BOOL:${VSSQ_EJABBERD_JWT}>"
            "VSSQ_MESSENGER=$<BOOL:${VSSQ_MESSENGER}>"
            "VSSQ_MESSENGER_AUTH=$<BOOL:${VSSQ_MESSENGER_AUTH}>"
            "VSSQ_MESSENGER_CREDS=$<BOOL:${VSSQ_MESSENGER_CREDS}>"
            "VSSQ_MESSENGER_CONFIG=$<BOOL:${VSSQ_MESSENGER_CONFIG}>"
            "VSSQ_MESSENGER_CONTACTS=$<BOOL:${VSSQ_MESSENGER_CONTACTS}>"
            "VSSQ_MESSENGER_USER=$<BOOL:${VSSQ_MESSENGER_USER}>"
            "VSSQ_MESSENGER_USER_LIST=$<BOOL:${VSSQ_MESSENGER_USER_LIST}>"
            "VSSQ_MESSENGER_GROUP=$<BOOL:${VSSQ_MESSENGER_GROUP}>"
            "VSSQ_MESSENGER_GROUP_EPOCH=$<BOOL:${VSSQ_MESSENGER_GROUP_EPOCH}>"
            "VSSQ_MESSENGER_GROUP_EPOCH_LIST=$<BOOL:${VSSQ_MESSENGER_GROUP_EPOCH_LIST}>"
            "VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE=$<BOOL:${VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE}>"
            "VSSQ_MESSENGER_FILE_CIPHER=$<BOOL:${VSSQ_MESSENGER_FILE_CIPHER}>"
            "VSSQ_MESSENGER_CLOUD_FS=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS}>"
            "VSSQ_MESSENGER_CLOUD_FS_CLIENT=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_CLIENT}>"
            "VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE}>"
            "VSSQ_MESSENGER_CLOUD_FS_FOLDER=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_FOLDER}>"
            "VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO}>"
            "VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST}>"
            "VSSQ_MESSENGER_CLOUD_FS_FILE_INFO=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_FILE_INFO}>"
            "VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST}>"
            "VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO}>"
            "VSSQ_MESSENGER_CLOUD_FS_CIPHER=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_CIPHER}>"
            "VSSQ_MESSENGER_CLOUD_FS_ACCESS=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_ACCESS}>"
            "VSSQ_MESSENGER_CLOUD_FS_ACCESS_LIST=$<BOOL:${VSSQ_MESSENGER_CLOUD_FS_ACCESS_LIST}>"
            "VSSQ_CLOUD_FILE_SYSTEM_PB=$<BOOL:${VSSQ_CLOUD_FILE_SYSTEM_PB}>"
            "VSSQ_CONTACT_UTILS=$<BOOL:${VSSQ_CONTACT_UTILS}>"
        )
