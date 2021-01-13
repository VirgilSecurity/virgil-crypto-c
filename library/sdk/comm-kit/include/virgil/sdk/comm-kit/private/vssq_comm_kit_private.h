//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This is an umbrella header that includes library private headers.
// --------------------------------------------------------------------------

#ifndef VSSQ_COMM_KIT_PRIVATE_H_INCLUDED
#define VSSQ_COMM_KIT_PRIVATE_H_INCLUDED

#include "vssq_platform.h"
#include "vssq_atomic.h"
#include "vssq_messenger_cloud_fs_created_file_private.h"
#include "vssq_messenger_cloud_fs_file_info_list_private.h"
#include "vssq_messenger_cloud_fs_folder_info_list_private.h"
#include "vssq_messenger_cloud_fs_folder_private.h"
#include "vssq_messenger_creds_private.h"
#include "vssq_messenger_group_epoch_list_private.h"
#include "vssq_messenger_group_private.h"
#include "vssq_messenger_user_list_private.h"
#include "vssq_messenger_user_private.h"

#if VSSQ_EJABBERD_JWT
#   include "vssq_ejabberd_jwt_defs.h"
#endif

#if VSSQ_MESSENGER
#   include "vssq_messenger_defs.h"
#endif

#if VSSQ_MESSENGER_AUTH
#   include "vssq_messenger_auth_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS
#   include "vssq_messenger_cloud_fs_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_CIPHER
#   include "vssq_messenger_cloud_fs_cipher_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE
#   include "vssq_messenger_cloud_fs_created_file_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO
#   include "vssq_messenger_cloud_fs_file_download_info_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_FILE_INFO
#   include "vssq_messenger_cloud_fs_file_info_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST
#   include "vssq_messenger_cloud_fs_file_info_list_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_FOLDER
#   include "vssq_messenger_cloud_fs_folder_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO
#   include "vssq_messenger_cloud_fs_folder_info_defs.h"
#endif

#if VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST
#   include "vssq_messenger_cloud_fs_folder_info_list_defs.h"
#endif

#if VSSQ_MESSENGER_CONFIG
#   include "vssq_messenger_config_defs.h"
#endif

#if VSSQ_MESSENGER_CONTACTS
#   include "vssq_messenger_contacts_defs.h"
#   include "vssq_messenger_contacts.h"
#endif

#if VSSQ_MESSENGER_CREDS
#   include "vssq_messenger_creds_defs.h"
#endif

#if VSSQ_MESSENGER_FILE_CIPHER
#   include "vssq_messenger_file_cipher_defs.h"
#endif

#if VSSQ_MESSENGER_GROUP
#   include "vssq_messenger_group_defs.h"
#endif

#if VSSQ_MESSENGER_GROUP_EPOCH_LIST
#   include "vssq_messenger_group_epoch_list_defs.h"
#endif

#if VSSQ_MESSENGER_USER
#   include "vssq_messenger_user_defs.h"
#endif

#if VSSQ_MESSENGER_USER_LIST
#   include "vssq_messenger_user_list_defs.h"
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_COMM_KIT_PRIVATE_H_INCLUDED
//  @end
