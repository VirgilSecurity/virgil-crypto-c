//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_PRIVATE_H_INCLUDED
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_PRIVATE_H_INCLUDED

#include "vssq_messenger_cloud_fs_folder.h"
#include "vssq_messenger_cloud_fs_folder_info_list.h"
#include "vssq_messenger_cloud_fs_file_info_list.h"
#include "vssq_messenger_cloud_fs_folder_info.h"
#include "vssq_messenger_cloud_fs_access_list.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_init_with_disown(vssq_messenger_cloud_fs_folder_t *self, size_t total_folder_count,
        size_t total_file_count, vsc_data_t folder_encrypted_key, vsc_data_t folder_public_key,
        vssq_messenger_cloud_fs_folder_info_list_t **folders_ref, vssq_messenger_cloud_fs_file_info_list_t **files_ref,
        vssq_messenger_cloud_fs_folder_info_t **info_ref,
        vssq_messenger_cloud_fs_access_list_t **users_permission_ref);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_new_with_disown(size_t total_folder_count, size_t total_file_count,
        vsc_data_t folder_encrypted_key, vsc_data_t folder_public_key,
        vssq_messenger_cloud_fs_folder_info_list_t **folders_ref, vssq_messenger_cloud_fs_file_info_list_t **files_ref,
        vssq_messenger_cloud_fs_folder_info_t **info_ref,
        vssq_messenger_cloud_fs_access_list_t **users_permission_ref);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_init_root_with_disown(vssq_messenger_cloud_fs_folder_t *self, size_t total_folder_count,
        size_t total_file_count, vssq_messenger_cloud_fs_folder_info_list_t **folders_ref,
        vssq_messenger_cloud_fs_file_info_list_t **files_ref, vssq_messenger_cloud_fs_folder_info_t **info_ref);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_new_root_with_disown(size_t total_folder_count, size_t total_file_count,
        vssq_messenger_cloud_fs_folder_info_list_t **folders_ref, vssq_messenger_cloud_fs_file_info_list_t **files_ref,
        vssq_messenger_cloud_fs_folder_info_t **info_ref);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CLOUD_FS_FOLDER_PRIVATE_H_INCLUDED
//  @end
