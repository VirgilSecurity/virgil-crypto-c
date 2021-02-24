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
//  Handles a list of folder entries
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_H_INCLUDED
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_cloud_fs_folder_info_list.h"
#include "vssq_messenger_cloud_fs_file_info_list.h"
#include "vssq_messenger_cloud_fs_folder_info.h"
#include "vssq_messenger_cloud_fs_user_permission_list.h"

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
//  Handle 'messenger cloud fs folder' context.
//
#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_T_DEFINED
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_T_DEFINED
    typedef struct vssq_messenger_cloud_fs_folder_t vssq_messenger_cloud_fs_folder_t;
#endif // VSSQ_MESSENGER_CLOUD_FS_FOLDER_T_DEFINED

//
//  Return size of 'vssq_messenger_cloud_fs_folder_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_folder_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_init(vssq_messenger_cloud_fs_folder_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_cleanup(vssq_messenger_cloud_fs_folder_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_init_with(vssq_messenger_cloud_fs_folder_t *self, size_t total_folder_count,
        size_t total_file_count, vsc_data_t folder_encrypted_key, vsc_data_t folder_public_key,
        const vssq_messenger_cloud_fs_folder_info_list_t *folders,
        const vssq_messenger_cloud_fs_file_info_list_t *files, const vssq_messenger_cloud_fs_folder_info_t *info,
        const vssq_messenger_cloud_fs_user_permission_list_t *users_permission);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_new_with(size_t total_folder_count, size_t total_file_count,
        vsc_data_t folder_encrypted_key, vsc_data_t folder_public_key,
        const vssq_messenger_cloud_fs_folder_info_list_t *folders,
        const vssq_messenger_cloud_fs_file_info_list_t *files, const vssq_messenger_cloud_fs_folder_info_t *info,
        const vssq_messenger_cloud_fs_user_permission_list_t *users_permission);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_init_root_with(vssq_messenger_cloud_fs_folder_t *self, size_t total_folder_count,
        size_t total_file_count, const vssq_messenger_cloud_fs_folder_info_list_t *folders,
        const vssq_messenger_cloud_fs_file_info_list_t *files, const vssq_messenger_cloud_fs_folder_info_t *info);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_new_root_with(size_t total_folder_count, size_t total_file_count,
        const vssq_messenger_cloud_fs_folder_info_list_t *folders,
        const vssq_messenger_cloud_fs_file_info_list_t *files, const vssq_messenger_cloud_fs_folder_info_t *info);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_delete(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_folder_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_destroy(vssq_messenger_cloud_fs_folder_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_shallow_copy(vssq_messenger_cloud_fs_folder_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_folder_shallow_copy_const(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return true if folder is a root folder.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_is_root(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return total = folder + file count.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_folder_total_entry_count(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return total folder count.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_folder_total_folder_count(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return total file count.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_folder_total_file_count(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return folders.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_folders(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return files.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_file_info_list_t *
vssq_messenger_cloud_fs_folder_files(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return current folder info.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_folder_info(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return encrypted folder private key.
//
VSSQ_PUBLIC vsc_data_t
vssq_messenger_cloud_fs_folder_encrypted_key(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return folder public key.
//
VSSQ_PUBLIC vsc_data_t
vssq_messenger_cloud_fs_folder_public_key(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return true if folder has shared users.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_has_shared_users_permission(const vssq_messenger_cloud_fs_folder_t *self);

//
//  Return users that have permissions to this folder.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_user_permission_list_t *
vssq_messenger_cloud_fs_folder_shared_users_permission(const vssq_messenger_cloud_fs_folder_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CLOUD_FS_FOLDER_H_INCLUDED
//  @end
