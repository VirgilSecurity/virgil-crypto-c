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


//  @description
// --------------------------------------------------------------------------
//  This class provides access to the messenger Cloud File System, that can be used to store and share files.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_cloud_fs.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_cloud_fs_defs.h"

#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/crypto/foundation/vscf_private_key.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_cloud_fs_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_cloud_fs_init_ctx(vssq_messenger_cloud_fs_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_cloud_fs_cleanup_ctx(vssq_messenger_cloud_fs_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_cloud_fs_did_setup_random(vssq_messenger_cloud_fs_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_cloud_fs_did_release_random(vssq_messenger_cloud_fs_t *self);

//
//  Encrypt file/folder key for:
//      - myself;
//      - parent folder key if given;
//      - shared users.
//
static vsc_buffer_t *
vssq_messenger_cloud_fs_encrypt_key(const vssq_messenger_cloud_fs_t *self, vsc_data_t key, vsc_str_t parent_folder_id,
        vsc_data_t parent_folder_public_key, const vssq_messenger_cloud_fs_access_list_t *shared_users,
        vssq_error_t *error);

//
//  Create a new folder within the Cloud FS.
//  Note, if parent folder id is empty then folder created in a root folder.
//  Note, if users are given then the folder will be shared for them.
//
static vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_create_folder_internal(const vssq_messenger_cloud_fs_t *self, vsc_str_t name,
        vsc_str_t parent_folder_id, vsc_data_t parent_folder_public_key,
        const vssq_messenger_cloud_fs_access_list_t *users, vssq_error_t *error);

//
//  Generate a private key and export it and public key to the binary format (DER).
//
static bool
vssq_messenger_cloud_fs_generate_key(const vssq_messenger_cloud_fs_t *self, vsc_buffer_t *private_key_buf,
        vsc_buffer_t *public_key_buf);

//
//  Decrypt file/folder key with a given private key.
//
static vssq_status_t
vssq_messenger_cloud_fs_decrypt_key_internal(const vssq_messenger_cloud_fs_t *self, vsc_data_t encrypted_key,
        const vssq_messenger_user_t *issuer, vsc_str_t key_id, const vscf_impl_t *key,
        vsc_buffer_t *decrypted_key) VSSQ_NODISCARD;

//
//  Return size of 'vssq_messenger_cloud_fs_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_ctx_size(void) {

    return sizeof(vssq_messenger_cloud_fs_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_init(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_cloud_fs_t));

    self->refcnt = 1;

    vssq_messenger_cloud_fs_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cleanup(vssq_messenger_cloud_fs_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_cloud_fs_release_client(self);
    vssq_messenger_cloud_fs_release_random(self);

    vssq_messenger_cloud_fs_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_cloud_fs_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs_new(void) {

    vssq_messenger_cloud_fs_t *self = (vssq_messenger_cloud_fs_t *) vssq_alloc(sizeof (vssq_messenger_cloud_fs_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_cloud_fs_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_delete(const vssq_messenger_cloud_fs_t *self) {

    vssq_messenger_cloud_fs_t *local_self = (vssq_messenger_cloud_fs_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSQ_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSQ_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssq_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssq_messenger_cloud_fs_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_destroy(vssq_messenger_cloud_fs_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_cloud_fs_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_cloud_fs_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs_shallow_copy(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_t *
vssq_messenger_cloud_fs_shallow_copy_const(const vssq_messenger_cloud_fs_t *self) {

    return vssq_messenger_cloud_fs_shallow_copy((vssq_messenger_cloud_fs_t *)self);
}

//
//  Setup dependency to the class 'messenger cloud fs client' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_use_client(vssq_messenger_cloud_fs_t *self, vssq_messenger_cloud_fs_client_t *client) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(client);
    VSSQ_ASSERT(self->client == NULL);

    self->client = vssq_messenger_cloud_fs_client_shallow_copy(client);
}

//
//  Setup dependency to the class 'messenger cloud fs client' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_take_client(vssq_messenger_cloud_fs_t *self, vssq_messenger_cloud_fs_client_t *client) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(client);
    VSSQ_ASSERT(self->client == NULL);

    self->client = client;
}

//
//  Release dependency to the class 'messenger cloud fs client'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_release_client(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_cloud_fs_client_destroy(&self->client);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_use_random(vssq_messenger_cloud_fs_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vssq_messenger_cloud_fs_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_take_random(vssq_messenger_cloud_fs_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vssq_messenger_cloud_fs_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_release_random(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vssq_messenger_cloud_fs_did_release_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_cloud_fs_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_cloud_fs_init_ctx(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    self->key_provider = vscf_key_provider_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_cloud_fs_cleanup_ctx(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_cloud_fs_did_setup_random(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_key_provider_release_random(self->key_provider);
    vscf_key_provider_use_random(self->key_provider, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_cloud_fs_did_release_random(vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_key_provider_release_random(self->key_provider);
}

//
//  Return the Cloud FS client.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_client_t *
vssq_messenger_cloud_fs_client(const vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->client;
}

//
//  Create a new file within the Cloud FS.
//  Note, if folder id is empty then file created in a root folder.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_created_file_t *
vssq_messenger_cloud_fs_create_file(const vssq_messenger_cloud_fs_t *self, vsc_str_t name, vsc_str_t mime_tipe,
        size_t size, vsc_data_t file_key, vsc_str_t parent_folder_id, vsc_data_t parent_folder_public_key,
        vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(name));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(mime_tipe));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(file_key));
    VSSQ_ASSERT(vsc_str_is_valid(parent_folder_id));
    VSSQ_ASSERT(vsc_data_is_valid(parent_folder_public_key));

    vsc_buffer_t *file_encrypted_key = vssq_messenger_cloud_fs_encrypt_key(
            self, file_key, parent_folder_id, parent_folder_public_key, NULL, error);

    if (NULL == file_encrypted_key) {
        return NULL;
    }

    vssq_messenger_cloud_fs_created_file_t *result = vssq_messenger_cloud_fs_client_create_file(
            self->client, name, mime_tipe, size, parent_folder_id, vsc_buffer_data(file_encrypted_key), error);

    vsc_buffer_destroy(&file_encrypted_key);

    return result;
}

//
//  Get a file download link.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_file_download_info_t *
vssq_messenger_cloud_fs_get_download_link(const vssq_messenger_cloud_fs_t *self, vsc_str_t id, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(id));

    return vssq_messenger_cloud_fs_client_get_download_link(self->client, id, error);
}

//
//  Delete existing file.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_delete_file(const vssq_messenger_cloud_fs_t *self, vsc_str_t id) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(id));

    return vssq_messenger_cloud_fs_client_delete_file(self->client, id);
}

//
//  Create a new folder within the Cloud FS.
//  Note, if parent folder id is empty then folder created in a root folder.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_create_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t name, vsc_str_t parent_folder_id,
        vsc_data_t parent_folder_public_key, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(name));
    VSSQ_ASSERT(vsc_str_is_valid(parent_folder_id));
    VSSQ_ASSERT(vsc_data_is_valid(parent_folder_public_key));

    return vssq_messenger_cloud_fs_create_folder_internal(
            self, name, parent_folder_id, parent_folder_public_key, NULL, error);
}

//
//  Create a new folder within the Cloud FS that is shared with other users.
//  Note, if parent folder id is empty then folder created in a root folder.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_create_shared_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t name,
        vsc_str_t parent_folder_id, vsc_data_t parent_folder_public_key,
        const vssq_messenger_cloud_fs_access_list_t *users_access, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(name));
    VSSQ_ASSERT(vsc_str_is_valid(parent_folder_id));
    VSSQ_ASSERT(vsc_data_is_valid(parent_folder_public_key));
    VSSQ_ASSERT_PTR(users_access);
    VSSQ_ASSERT(vssq_messenger_cloud_fs_access_list_has_item(users_access));

    return vssq_messenger_cloud_fs_create_folder_internal(
            self, name, parent_folder_id, parent_folder_public_key, users_access, error);
}

//
//  List content of requested folder.
//  Note, if folder id is empty then a root folder will be listed.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_t *
vssq_messenger_cloud_fs_list_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t id, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid(id));

    return vssq_messenger_cloud_fs_client_list_folder(self->client, id, error);
}

//
//  Delete existing folder.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_delete_folder(const vssq_messenger_cloud_fs_t *self, vsc_str_t id) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(id));

    return vssq_messenger_cloud_fs_client_delete_folder(self->client, id);
}

//
//  Get shared group of users.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_access_list_t *
vssq_messenger_cloud_fs_get_shared_group_users(
        const vssq_messenger_cloud_fs_t *self, vsc_str_t id, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(id));

    return vssq_messenger_cloud_fs_client_get_shared_group_users(self->client, id, error);
}

//
//  Set shared group of users.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_set_shared_group_users(const vssq_messenger_cloud_fs_t *self, vsc_str_t id,
        vsc_data_t encrypted_group_key, const vssq_messenger_user_t *key_issuer,
        const vssq_messenger_cloud_fs_access_list_t *users_access) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(id));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(encrypted_group_key));
    VSSQ_ASSERT_PTR(users_access);

    vssq_error_t error;
    vssq_error_reset(&error);

    vsc_buffer_t *group_key = NULL;
    vsc_buffer_t *new_group_encrypted_key = NULL;

    const size_t group_key_len = vssq_messenger_cloud_fs_decrypted_key_len(self, encrypted_group_key);
    group_key = vsc_buffer_new_with_capacity(group_key_len);
    vsc_buffer_make_secure(group_key);

    error.status = vssq_messenger_cloud_fs_decrypt_key(self, encrypted_group_key, key_issuer, group_key);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    new_group_encrypted_key = vssq_messenger_cloud_fs_encrypt_key(
            self, vsc_buffer_data(group_key), vsc_str_empty(), vsc_data_empty(), users_access, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Share folder.
    //
    error.status = vssq_messenger_cloud_fs_client_set_shared_group_users(
            self->client, id, vsc_buffer_data(new_group_encrypted_key), users_access);

cleanup:
    vsc_buffer_destroy(&group_key);
    vsc_buffer_destroy(&new_group_encrypted_key);

    return vssq_error_status(&error);
}

//
//  Return true if a user is authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_is_authenticated(const vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->client);

    return vssq_messenger_cloud_fs_client_is_authenticated(self->client);
}

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_cloud_fs_user(const vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_cloud_fs_is_authenticated(self));

    return vssq_messenger_cloud_fs_client_user(self->client);
}

//
//  Return a private key of current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_cloud_fs_user_private_key(const vssq_messenger_cloud_fs_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_cloud_fs_is_authenticated(self));

    return vssq_messenger_cloud_fs_client_user_private_key(self->client);
}

//
//  Encrypt file/folder key for:
//      - myself;
//      - parent folder key if given;
//      - shared users.
//
static vsc_buffer_t *
vssq_messenger_cloud_fs_encrypt_key(const vssq_messenger_cloud_fs_t *self, vsc_data_t key, vsc_str_t parent_folder_id,
        vsc_data_t parent_folder_public_key, const vssq_messenger_cloud_fs_access_list_t *shared_users,
        vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(key));
    VSSQ_ASSERT(vsc_str_is_valid(parent_folder_id));
    VSSQ_ASSERT(vsc_data_is_valid(parent_folder_public_key));

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_recipient_cipher_t *cipher = NULL;
    vsc_buffer_t *encrypted_key = NULL;

    //
    //  Init recipient cipher.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);

    //
    //  Encrypt key for a current user.
    //
    const vssq_messenger_user_t *current_user = vssq_messenger_cloud_fs_client_user(self->client);
    const vsc_str_t current_user_identity = vssq_messenger_user_identity(current_user);
    const vscf_impl_t *current_user_public_key = vssq_messenger_user_public_key(current_user);
    const vscf_impl_t *current_user_private_key = vssq_messenger_cloud_fs_client_user_private_key(self->client);

    vscf_recipient_cipher_add_key_recipient(cipher, vsc_str_as_data(current_user_identity), current_user_public_key);

    //
    //  Encrypt key for a parent folder.
    //
    if (!vsc_str_is_empty(parent_folder_id)) {
        VSSQ_ASSERT(!vsc_data_is_empty(parent_folder_public_key));

        vscf_impl_t *folder_public_key =
                vscf_key_provider_import_public_key(self->key_provider, parent_folder_public_key, &foundation_error);

        if (vscf_error_has_error(&foundation_error)) {
            VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_IMPORT_KEY_FAILED);
            goto cleanup;
        }

        vscf_recipient_cipher_add_key_recipient(cipher, vsc_str_as_data(parent_folder_id), folder_public_key);

        vscf_impl_destroy(&folder_public_key);
    }

    //
    //  Encrypt key for shared users.
    //
    for (const vssq_messenger_cloud_fs_access_list_t *access_it = shared_users;
            (access_it != NULL) && vssq_messenger_cloud_fs_access_list_has_item(access_it);
            access_it = vssq_messenger_cloud_fs_access_list_next(access_it)) {

        const vssq_messenger_cloud_fs_access_t *access = vssq_messenger_cloud_fs_access_list_item(access_it);
        VSSQ_ASSERT(vssq_messenger_cloud_fs_access_has_user(access));

        const vssq_messenger_user_t *user = vssq_messenger_cloud_fs_access_user(access);
        VSSQ_ASSERT_PTR(user);

        vsc_str_t identity = vssq_messenger_user_identity(user);
        const vscf_impl_t *public_key = vssq_messenger_user_public_key(user);

        vscf_recipient_cipher_add_key_recipient(cipher, vsc_str_as_data(identity), public_key);
    }

    //
    //  Sign the key.
    //
    foundation_error.status =
            vscf_recipient_cipher_add_signer(cipher, vsc_str_as_data(current_user_identity), current_user_private_key);

    if (vscf_error_has_error(&foundation_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED);
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_start_signed_encryption(cipher, key.len);

    if (vscf_error_has_error(&foundation_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED);
        goto cleanup;
    }

    //
    //  Write a header.
    //
    const size_t message_info_len = vscf_recipient_cipher_message_info_len(cipher);
    const size_t enc_msg_data_len = vscf_recipient_cipher_encryption_out_len(cipher, key.len) +
                                    vscf_recipient_cipher_encryption_out_len(cipher, 0);

    encrypted_key = vsc_buffer_new_with_capacity(message_info_len + enc_msg_data_len);

    vscf_recipient_cipher_pack_message_info(cipher, encrypted_key);

    //
    //  Encrypt the key.
    //
    foundation_error.status = vscf_recipient_cipher_process_encryption(cipher, key, encrypted_key);

    if (vscf_error_has_error(&foundation_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED);
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_finish_encryption(cipher, encrypted_key);

    if (vscf_error_has_error(&foundation_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED);
        goto cleanup;
    }

    //
    //  Write a footer.
    //
    const size_t enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(cipher);
    vsc_buffer_reserve_unused(encrypted_key, enc_msg_info_footer_len);

    foundation_error.status = vscf_recipient_cipher_pack_message_info_footer(cipher, encrypted_key);

    if (vscf_error_has_error(&foundation_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED);
        goto cleanup;
    }

cleanup:
    vscf_recipient_cipher_destroy(&cipher);

    if (vscf_error_has_error(&foundation_error)) {
        vsc_buffer_destroy(&encrypted_key);
    }

    return encrypted_key;
}

//
//  Return buffer length required to hold "decrypted key" written by the "decrypt key" method.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_decrypted_key_len(const vssq_messenger_cloud_fs_t *self, vsc_data_t encrypted_key) {

    VSSQ_ASSERT(self);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(encrypted_key));

    //
    //  TODO: Make it precisely, when vscf_recipient_cipher such ability.
    //  See, vscf_recipient_cipher.c:1069
    //
    return 32 + encrypted_key.len;
}

//
//  Decrypt file/folder key with current user key:
//  Note, issuer is a person who produced an encrypted key.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_decrypt_key(const vssq_messenger_cloud_fs_t *self, vsc_data_t encrypted_key,
        const vssq_messenger_user_t *issuer, vsc_buffer_t *decrypted_key) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(encrypted_key));
    VSSQ_ASSERT(vsc_buffer_is_valid(decrypted_key));
    VSSQ_ASSERT_PTR(issuer);
    VSSQ_ASSERT(vsc_buffer_unused_len(decrypted_key) >= vssq_messenger_cloud_fs_decrypted_key_len(self, encrypted_key));

    const vssq_messenger_user_t *current_user = vssq_messenger_cloud_fs_client_user(self->client);
    const vscf_impl_t *current_user_private_key = vssq_messenger_cloud_fs_client_user_private_key(self->client);
    const vsc_str_t current_user_identity = vssq_messenger_user_identity(current_user);

    return vssq_messenger_cloud_fs_decrypt_key_internal(
            self, encrypted_key, issuer, current_user_identity, current_user_private_key, decrypted_key);
}

//
//  Decrypt file/folder key with a given parent folder key:
//  Note, issuer is a person who produced an encrypted key.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_decrypt_key_with_parent_folder_key(const vssq_messenger_cloud_fs_t *self,
        vsc_data_t encrypted_key, const vssq_messenger_user_t *issuer, vsc_str_t parent_folder_id,
        vsc_data_t parent_folder_key, vsc_buffer_t *decrypted_key) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(vssq_messenger_cloud_fs_is_authenticated(self));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(encrypted_key));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(parent_folder_id));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(parent_folder_key));
    VSSQ_ASSERT(vsc_buffer_is_valid(decrypted_key));
    VSSQ_ASSERT_PTR(issuer);
    VSSQ_ASSERT(vsc_buffer_unused_len(decrypted_key) >= vssq_messenger_cloud_fs_decrypted_key_len(self, encrypted_key));

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_impl_t *parent_folder_private_key =
            vscf_key_provider_import_private_key(self->key_provider, parent_folder_key, &foundation_error);

    if (vscf_error_has_error(&foundation_error)) {
        return vssq_status_CLOUD_FS_FAILED_IMPORT_KEY_FAILED;
    }

    const vssq_status_t decrypt_status = vssq_messenger_cloud_fs_decrypt_key_internal(
            self, encrypted_key, issuer, parent_folder_id, parent_folder_private_key, decrypted_key);

    vscf_impl_destroy(&parent_folder_private_key);

    return decrypt_status;
}

//
//  Create a new folder within the Cloud FS.
//  Note, if parent folder id is empty then folder created in a root folder.
//  Note, if users are given then the folder will be shared for them.
//
static vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_create_folder_internal(const vssq_messenger_cloud_fs_t *self, vsc_str_t name,
        vsc_str_t parent_folder_id, vsc_data_t parent_folder_public_key,
        const vssq_messenger_cloud_fs_access_list_t *users, vssq_error_t *error) {

    vsc_buffer_t *folder_private_key = vsc_buffer_new();
    vsc_buffer_t *folder_public_key = vsc_buffer_new();
    vsc_buffer_t *folder_encrypted_key = NULL;
    vssq_messenger_cloud_fs_folder_info_t *result = NULL;

    if (!vssq_messenger_cloud_fs_generate_key(self, folder_private_key, folder_public_key)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CLOUD_FS_FAILED_GENERATE_KEY_FAILED);
        goto cleanup;
    }

    folder_encrypted_key = vssq_messenger_cloud_fs_encrypt_key(
            self, vsc_buffer_data(folder_private_key), parent_folder_id, parent_folder_public_key, users, error);

    if (NULL == folder_encrypted_key) {
        goto cleanup;
    }

    if (users) {
        result = vssq_messenger_cloud_fs_client_create_shared_folder(self->client, name,
                vsc_buffer_data(folder_encrypted_key), vsc_buffer_data(folder_public_key), parent_folder_id, users,
                error);

    } else {
        result = vssq_messenger_cloud_fs_client_create_folder(self->client, name, vsc_buffer_data(folder_encrypted_key),
                vsc_buffer_data(folder_public_key), parent_folder_id, error);
    }

cleanup:
    vsc_buffer_destroy(&folder_private_key);
    vsc_buffer_destroy(&folder_public_key);
    vsc_buffer_destroy(&folder_encrypted_key);

    return result;
}

//
//  Generate a private key and export it and public key to the binary format (DER).
//
static bool
vssq_messenger_cloud_fs_generate_key(
        const vssq_messenger_cloud_fs_t *self, vsc_buffer_t *private_key_buf, vsc_buffer_t *public_key_buf) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(private_key_buf);
    VSSQ_ASSERT_PTR(public_key_buf);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    //
    //  Generate.
    //
    vscf_impl_t *private_key =
            vscf_key_provider_generate_private_key(self->key_provider, vscf_alg_id_ED25519, &foundation_error);

    if (vscf_error_has_error(&foundation_error)) {
        return false;
    }

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    //
    //  Export private key.
    //
    const size_t private_key_len = vscf_key_provider_exported_private_key_len(self->key_provider, private_key);
    const size_t public_key_len = vscf_key_provider_exported_public_key_len(self->key_provider, public_key);

    vsc_buffer_reserve_unused(public_key_buf, public_key_len);
    vsc_buffer_reserve_unused(private_key_buf, private_key_len);
    vsc_buffer_make_secure(private_key_buf);

    foundation_error.status = vscf_key_provider_export_private_key(self->key_provider, private_key, private_key_buf);

    if (!vscf_error_has_error(&foundation_error)) {
        foundation_error.status = vscf_key_provider_export_public_key(self->key_provider, public_key, public_key_buf);
    }

    return !vscf_error_has_error(&foundation_error);
}

//
//  Decrypt file/folder key with a given private key.
//
static vssq_status_t
vssq_messenger_cloud_fs_decrypt_key_internal(const vssq_messenger_cloud_fs_t *self, vsc_data_t encrypted_key,
        const vssq_messenger_user_t *issuer, vsc_str_t key_id, const vscf_impl_t *key, vsc_buffer_t *decrypted_key) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(encrypted_key));
    VSSQ_ASSERT_PTR(issuer);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(key_id));
    VSSQ_ASSERT_PTR(key);
    VSSQ_ASSERT(vsc_buffer_is_valid(decrypted_key));

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_recipient_cipher_t *cipher = NULL;

    //
    //  Init recipient cipher.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);

    //
    //  Decrypt.
    //
    foundation_error.status =
            vscf_recipient_cipher_start_decryption_with_key(cipher, vsc_str_as_data(key_id), key, vsc_data_empty());

    if (vscf_error_has_error(&foundation_error)) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_WRONG_KEY);
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_process_decryption(cipher, encrypted_key, decrypted_key);

    if (vscf_error_has_error(&foundation_error)) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_WRONG_KEY);
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_finish_decryption(cipher, decrypted_key);

    if (vscf_error_has_error(&foundation_error)) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_WRONG_KEY);
        goto cleanup;
    }

    //
    //  Verify.
    //
    if (!vscf_recipient_cipher_is_data_signed(cipher)) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_INVALID_SIGNATURE);
        goto cleanup;
    }

    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(cipher);

    if (!vscf_signer_info_list_has_item(signer_infos)) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_INVALID_SIGNATURE);
        goto cleanup;
    }

    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);
    const vsc_data_t signer_id = vscf_signer_info_signer_id(signer_info);

    const vscf_impl_t *issuer_public_key = vssq_messenger_user_public_key(issuer);
    const vsc_str_t issuer_identity = vssq_messenger_user_identity(issuer);

    if (!vsc_data_equal(signer_id, vsc_str_as_data(issuer_identity))) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_SIGNER_MISMATCH);
    }

    const bool verified = vscf_recipient_cipher_verify_signer_info(cipher, signer_info, issuer_public_key);
    if (!verified) {
        vssq_error_update(&error, vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_INVALID_SIGNATURE);
        goto cleanup;
    }

cleanup:
    vscf_recipient_cipher_destroy(&cipher);

    return vssq_error_status(&error);
}
