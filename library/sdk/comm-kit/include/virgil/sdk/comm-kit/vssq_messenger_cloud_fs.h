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
//  This class provides access to the messenger Cloud File System, that can be used to store and share files.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CLOUD_FS_H_INCLUDED
#define VSSQ_MESSENGER_CLOUD_FS_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_cloud_fs_client.h"
#include "vssq_error.h"
#include "vssq_messenger_cloud_fs_created_file.h"
#include "vssq_messenger_cloud_fs_file_download_info.h"
#include "vssq_status.h"
#include "vssq_messenger_cloud_fs_folder_info.h"
#include "vssq_messenger_cloud_fs_access_list.h"
#include "vssq_messenger_cloud_fs_folder.h"
#include "vssq_messenger_user.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
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
//  Handle 'messenger cloud fs' context.
//
#ifndef VSSQ_MESSENGER_CLOUD_FS_T_DEFINED
#define VSSQ_MESSENGER_CLOUD_FS_T_DEFINED
    typedef struct vssq_messenger_cloud_fs_t vssq_messenger_cloud_fs_t;
#endif // VSSQ_MESSENGER_CLOUD_FS_T_DEFINED

//
//  Return size of 'vssq_messenger_cloud_fs_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_init(vssq_messenger_cloud_fs_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cleanup(vssq_messenger_cloud_fs_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_delete(const vssq_messenger_cloud_fs_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_destroy(vssq_messenger_cloud_fs_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs_shallow_copy(vssq_messenger_cloud_fs_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs_shallow_copy_const(const vssq_messenger_cloud_fs_t *self);

//
//  Setup dependency to the class 'messenger cloud fs client' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_use_client(vssq_messenger_cloud_fs_t *self, vssq_messenger_cloud_fs_client_t *client);

//
//  Setup dependency to the class 'messenger cloud fs client' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_take_client(vssq_messenger_cloud_fs_t *self, vssq_messenger_cloud_fs_client_t *client);

//
//  Release dependency to the class 'messenger cloud fs client'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_release_client(vssq_messenger_cloud_fs_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_use_random(vssq_messenger_cloud_fs_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_take_random(vssq_messenger_cloud_fs_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_release_random(vssq_messenger_cloud_fs_t *self);

//
//  Return the Cloud FS client.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_client_t *
vssq_messenger_cloud_fs_client(const vssq_messenger_cloud_fs_t *self);

//
//  Create a new file within the Cloud FS.
//  Note, if folder id is empty then file created in a root folder.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_created_file_t *
vssq_messenger_cloud_fs_create_file(const vssq_messenger_cloud_fs_t *self, vsc_str_t name, vsc_str_t type, size_t size,
        vsc_data_t file_key, vsc_str_t parent_folder_id, vsc_data_t parent_folder_public_key, vssq_error_t *error);

//
//  Get a file download link.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_file_download_info_t *
vssq_messenger_cloud_fs_get_download_link(const vssq_messenger_cloud_fs_t *self, vsc_str_t id, vssq_error_t *error);

//
//  Delete existing file.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_delete_file(const vssq_messenger_cloud_fs_t *self, vsc_str_t id) VSSQ_NODISCARD;

//
//  Create a new folder within the Cloud FS.
//  Note, if parent folder id is empty then folder created in a root folder.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_create_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t name, vsc_str_t parent_folder_id,
        vsc_data_t parent_folder_public_key, vssq_error_t *error);

//
//  Create a new folder within the Cloud FS that is shared with other users.
//  Note, if parent folder id is empty then folder created in a root folder.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_create_shared_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t name,
        vsc_str_t parent_folder_id, vsc_data_t parent_folder_public_key,
        const vssq_messenger_cloud_fs_access_list_t *users_access, vssq_error_t *error);

//
//  List content of requested folder.
//  Note, if folder id is empty then a root folder will be listed.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_list_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t id, vssq_error_t *error);

//
//  Delete existing folder.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_delete_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t id) VSSQ_NODISCARD;

//
//  Get shared group of users.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_access_list_t *
vssq_messenger_cloud_fs_get_shared_group_users(const vssq_messenger_cloud_fs_t *self, vsc_str_t id,
        vssq_error_t *error);

//
//  Set shared group of users.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_set_shared_group_users(const vssq_messenger_cloud_fs_t *self, vsc_str_t id,
        vsc_data_t entry_key, const vssq_messenger_cloud_fs_access_list_t *users_access) VSSQ_NODISCARD;

//
//  Return true if a user is authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_is_authenticated(const vssq_messenger_cloud_fs_t *self);

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_cloud_fs_user(const vssq_messenger_cloud_fs_t *self);

//
//  Return a private key of current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_cloud_fs_user_private_key(const vssq_messenger_cloud_fs_t *self);

//
//  Return buffer length required to hold "decrypted key" written by the "decrypt key" method.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_decrypted_key_len(const vssq_messenger_cloud_fs_t *self, vsc_data_t encrypted_key);

//
//  Decrypt file/folder key with current user key:
//  Note, issuer is a person who produced an encrypted key.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_decrypt_key(const vssq_messenger_cloud_fs_t *self, vsc_data_t encrypted_key,
        const vssq_messenger_user_t *issuer, vsc_buffer_t *decrypted_key) VSSQ_NODISCARD;

//
//  Decrypt file/folder key with a given parent folder key:
//  Note, issuer is a person who produced an encrypted key.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_decrypt_key_with_parent_folder_key(const vssq_messenger_cloud_fs_t *self,
        vsc_data_t encrypted_key, const vssq_messenger_user_t *issuer, vsc_str_t parent_folder_id,
        vsc_data_t parent_folder_key, vsc_buffer_t *decrypted_key) VSSQ_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CLOUD_FS_H_INCLUDED
//  @end
