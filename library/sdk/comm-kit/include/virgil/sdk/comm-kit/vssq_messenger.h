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
//  Entrypoint to the messenger user management, authentication and encryption.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_H_INCLUDED
#define VSSQ_MESSENGER_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_config.h"
#include "vssq_status.h"
#include "vssq_messenger_creds.h"
#include "vssq_messenger_user.h"
#include "vssq_error.h"
#include "vssq_messenger_auth.h"
#include "vssq_messenger_user_list.h"
#include "vssq_messenger_group.h"
#include "vssq_messenger_cloud_fs.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_json_array.h>
#   include <virgil/sdk/core/vssc_string_list.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_str_buffer.h>
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_string_list.h>
#   include <VSSCore/vssc_json_array.h>
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
//  Handle 'messenger' context.
//
#ifndef VSSQ_MESSENGER_T_DEFINED
#define VSSQ_MESSENGER_T_DEFINED
    typedef struct vssq_messenger_t vssq_messenger_t;
#endif // VSSQ_MESSENGER_T_DEFINED

//
//  Return size of 'vssq_messenger_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_init(vssq_messenger_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cleanup(vssq_messenger_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_t *
vssq_messenger_new(void);

//
//  Perform initialization of pre-allocated context.
//  Initialize messenger with a custom configuration.
//
VSSQ_PUBLIC void
vssq_messenger_init_with_config(vssq_messenger_t *self, const vssq_messenger_config_t *config);

//
//  Allocate class context and perform it's initialization.
//  Initialize messenger with a custom configuration.
//
VSSQ_PUBLIC vssq_messenger_t *
vssq_messenger_new_with_config(const vssq_messenger_config_t *config);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_delete(const vssq_messenger_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_destroy(vssq_messenger_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_t *
vssq_messenger_shallow_copy(vssq_messenger_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_t *
vssq_messenger_shallow_copy_const(const vssq_messenger_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_use_random(vssq_messenger_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_take_random(vssq_messenger_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_release_random(vssq_messenger_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_setup_defaults(vssq_messenger_t *self) VSSQ_NODISCARD;

//
//  Register a new user with a given name.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_register(vssq_messenger_t *self, vsc_str_t username) VSSQ_NODISCARD;

//
//  Authenticate a user with a given credentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_authenticate(vssq_messenger_t *self, const vssq_messenger_creds_t *creds) VSSQ_NODISCARD;

//
//  Return true if a user is authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_is_authenticated(const vssq_messenger_t *self);

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_user(const vssq_messenger_t *self);

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_modifiable(vssq_messenger_t *self);

//
//  Return name of the current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_username(const vssq_messenger_t *self);

//
//  Return user credentials.
//
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_creds(const vssq_messenger_t *self);

//
//  Check whether current credentials were backed up.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_has_backup_creds(const vssq_messenger_t *self, vssq_error_t *error);

//
//  Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_backup_creds(const vssq_messenger_t *self, vsc_str_t pwd) VSSQ_NODISCARD;

//
//  Authenticate user by using backup credentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_authenticate_with_backup_creds(vssq_messenger_t *self, vsc_str_t username, vsc_str_t pwd) VSSQ_NODISCARD;

//
//  Remove credentials backup from the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_remove_creds_backup(const vssq_messenger_t *self) VSSQ_NODISCARD;

//
//  Return authentication module.
//
//  It should be used with great carefulness and responsibility.
//
VSSQ_PUBLIC const vssq_messenger_auth_t *
vssq_messenger_auth(const vssq_messenger_t *self);

//
//  Return founded user or error.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_find_user_with_identity(const vssq_messenger_t *self, vsc_str_t identity, vssq_error_t *error);

//
//  Return founded users or error.
//
VSSQ_PUBLIC vssq_messenger_user_list_t *
vssq_messenger_find_users_with_identities(const vssq_messenger_t *self, const vssc_string_list_t *identities,
        vssq_error_t *error);

//
//  Return founded user or error.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_find_user_with_username(const vssq_messenger_t *self, vsc_str_t username, vssq_error_t *error);

//
//  Return founded users.
//
VSSQ_PUBLIC vssq_messenger_user_list_t *
vssq_messenger_find_users_by_phones(const vssq_messenger_t *self, const vssc_string_list_t *phones,
        vssq_error_t *error);

//
//  Return founded users.
//
VSSQ_PUBLIC vssq_messenger_user_list_t *
vssq_messenger_find_users_by_emails(const vssq_messenger_t *self, const vssc_string_list_t *emails,
        vssq_error_t *error);

//
//  Register user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_add_phone_number(const vssq_messenger_t *self, vsc_str_t phone_number) VSSQ_NODISCARD;

//
//  Confirm user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_confirm_phone_number(const vssq_messenger_t *self, vsc_str_t phone_number,
        vsc_str_t confirmation_code) VSSQ_NODISCARD;

//
//  Delete user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_delete_phone_number(const vssq_messenger_t *self, vsc_str_t phone_number) VSSQ_NODISCARD;

//
//  Register user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_add_email(const vssq_messenger_t *self, vsc_str_t email) VSSQ_NODISCARD;

//
//  Confirm user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_confirm_email(const vssq_messenger_t *self, vsc_str_t email, vsc_str_t confirmation_code) VSSQ_NODISCARD;

//
//  Delete user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_delete_email(const vssq_messenger_t *self, vsc_str_t email) VSSQ_NODISCARD;

//
//  Return a buffer length enough to hold an encrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_encrypted_message_len(const vssq_messenger_t *self, size_t message_len,
        const vssq_messenger_user_t *recipient);

//
//  Encrypt a text message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_encrypt_text(const vssq_messenger_t *self, vsc_str_t text, const vssq_messenger_user_t *recipient,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Encrypt a binary message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_encrypt_data(const vssq_messenger_t *self, vsc_data_t data, const vssq_messenger_user_t *recipient,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Return a buffer length enough to hold a decrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_decrypted_message_len(const vssq_messenger_t *self, size_t encrypted_message_len);

//
//  Decrypt a text message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_decrypt_text(const vssq_messenger_t *self, vsc_data_t encrypted_text,
        const vssq_messenger_user_t *sender, vsc_str_buffer_t *out) VSSQ_NODISCARD;

//
//  Decrypt a binary message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_decrypt_data(const vssq_messenger_t *self, vsc_data_t encrypted_data,
        const vssq_messenger_user_t *sender, vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Create a new group for a group messaging.
//
//  Prerequisites: user should be authenticated.
//  Note, group owner is added to the participants automatically.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_create_group(const vssq_messenger_t *self, vsc_str_t group_id,
        const vssq_messenger_user_list_t *participants, vssq_error_t *error);

//
//  Load an existing group for a group messaging.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_load_group(const vssq_messenger_t *self, vsc_str_t group_id, const vssq_messenger_user_t *owner,
        vssq_error_t *error);

//
//  Load an existing group from a cached JSON value for a group messaging.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_load_group_from_json_str(const vssq_messenger_t *self, vsc_str_t json_str, vssq_error_t *error);

//
//  Load an existing group from a cached JSON value for a group messaging.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_load_group_from_json(const vssq_messenger_t *self, const vssc_json_object_t *json_obj,
        vssq_error_t *error);

//
//  Returns module for working with the CLoud FS.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs(const vssq_messenger_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_H_INCLUDED
//  @end
