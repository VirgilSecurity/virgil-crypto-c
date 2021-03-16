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
//  Contains information about the group and performs encryption and decryption operations.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_group.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_group_private.h"
#include "vssq_messenger_group_defs.h"
#include "vssq_messenger_group_epoch_list_private.h"
#include "vssq_atomic.h"
#include "vssq_messenger_user_list.h"
#include "vssq_error.h"
#include "vssq_messenger_group_epoch.h"

#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_group_session.h>
#include <virgil/crypto/foundation/vscf_group_session_ticket.h>
#include <virgil/sdk/core/vssc_string_list.h>
#include <virgil/sdk/core/private/vssc_json_object_private.h>
#include <virgil/sdk/core/private/vssc_json_array_private.h>
#include <virgil/crypto/foundation/vscf_status.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_group_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_group_init_ctx(vssq_messenger_group_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_group_cleanup_ctx(vssq_messenger_group_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_group_did_setup_random(vssq_messenger_group_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_group_did_release_random(vssq_messenger_group_t *self);

//
//  This method is called when class 'messenger auth' was setup.
//
static void
vssq_messenger_group_did_setup_auth(vssq_messenger_group_t *self);

//
//  This method is called when class 'messenger auth' was released.
//
static void
vssq_messenger_group_did_release_auth(vssq_messenger_group_t *self);

//
//  Calculate session id based on the group id.
//
static vsc_buffer_t *
vssq_messenger_group_calculate_session_id(vsc_str_t group_id);

//
//  Generate initial epoch for a new group.
//
static vssq_messenger_group_epoch_t *
vssq_messenger_group_generate_initial_epoch(const vssq_messenger_group_t *self, vsc_data_t session_id,
        const vssq_messenger_user_list_t *participants, vssq_error_t *error);

//
//  Map status from the "foundation" library to a status related to the groups.
//
static vssq_status_t
vssq_messenger_group_map_foundation_status(vscf_status_t foundation_status) VSSQ_NODISCARD;

static const char k_json_version_v1_chars[] = "v1";

static const vsc_str_t k_json_version_v1 = {
    k_json_version_v1_chars,
    sizeof(k_json_version_v1_chars) - 1
};

static const char k_json_key_version_chars[] = "version";

static const vsc_str_t k_json_key_version = {
    k_json_key_version_chars,
    sizeof(k_json_key_version_chars) - 1
};

static const char k_json_key_group_id_chars[] = "group_id";

static const vsc_str_t k_json_key_group_id = {
    k_json_key_group_id_chars,
    sizeof(k_json_key_group_id_chars) - 1
};

static const char k_json_key_owner_chars[] = "owner";

static const vsc_str_t k_json_key_owner = {
    k_json_key_owner_chars,
    sizeof(k_json_key_owner_chars) - 1
};

static const char k_json_key_epochs_chars[] = "epochs";

static const vsc_str_t k_json_key_epochs = {
    k_json_key_epochs_chars,
    sizeof(k_json_key_epochs_chars) - 1
};

//
//  Return size of 'vssq_messenger_group_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_ctx_size(void) {

    return sizeof(vssq_messenger_group_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_group_init(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_t));

    self->refcnt = 1;

    vssq_messenger_group_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_group_cleanup(vssq_messenger_group_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_group_release_random(self);
    vssq_messenger_group_release_auth(self);

    vssq_messenger_group_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_group_new(void) {

    vssq_messenger_group_t *self = (vssq_messenger_group_t *) vssq_alloc(sizeof (vssq_messenger_group_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_group_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_group_delete(const vssq_messenger_group_t *self) {

    vssq_messenger_group_t *local_self = (vssq_messenger_group_t *)self;

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

    vssq_messenger_group_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_group_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_group_destroy(vssq_messenger_group_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_group_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_group_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_group_shallow_copy(vssq_messenger_group_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_group_t *
vssq_messenger_group_shallow_copy_const(const vssq_messenger_group_t *self) {

    return vssq_messenger_group_shallow_copy((vssq_messenger_group_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_use_random(vssq_messenger_group_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vssq_messenger_group_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_take_random(vssq_messenger_group_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vssq_messenger_group_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_group_release_random(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vssq_messenger_group_did_release_random(self);
}

//
//  Setup dependency to the class 'messenger auth' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_use_auth(vssq_messenger_group_t *self, vssq_messenger_auth_t *auth) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(auth);
    VSSQ_ASSERT(self->auth == NULL);

    self->auth = vssq_messenger_auth_shallow_copy(auth);

    vssq_messenger_group_did_setup_auth(self);
}

//
//  Setup dependency to the class 'messenger auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_take_auth(vssq_messenger_group_t *self, vssq_messenger_auth_t *auth) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(auth);
    VSSQ_ASSERT(self->auth == NULL);

    self->auth = auth;

    vssq_messenger_group_did_setup_auth(self);
}

//
//  Release dependency to the class 'messenger auth'.
//
VSSQ_PUBLIC void
vssq_messenger_group_release_auth(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_auth_destroy(&self->auth);

    vssq_messenger_group_did_release_auth(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_group_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_group_init_ctx(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    self->epoch_keyknox_storage = vssq_messenger_group_epoch_keyknox_storage_new();
    self->group_session = vscf_group_session_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_group_cleanup_ctx(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_group_epoch_keyknox_storage_destroy(&self->epoch_keyknox_storage);
    vssq_messenger_user_delete(self->owner);
    vssq_messenger_group_epoch_list_destroy(&self->epochs);
    vsc_str_mutable_release(&self->group_id);
    vscf_group_session_destroy(&self->group_session);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_group_did_setup_random(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_group_epoch_keyknox_storage_use_random(self->epoch_keyknox_storage, self->random);
    vscf_group_session_use_rng(self->group_session, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_group_did_release_random(vssq_messenger_group_t *self) {

    vssq_messenger_group_epoch_keyknox_storage_release_random(self->epoch_keyknox_storage);
    vscf_group_session_release_rng(self->group_session);
}

//
//  This method is called when class 'messenger auth' was setup.
//
static void
vssq_messenger_group_did_setup_auth(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_is_authenticated(self->auth));

    vssq_messenger_group_epoch_keyknox_storage_use_auth(self->epoch_keyknox_storage, self->auth);
}

//
//  This method is called when class 'messenger auth' was released.
//
static void
vssq_messenger_group_did_release_auth(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_group_epoch_keyknox_storage_release_auth(self->epoch_keyknox_storage);
}

//
//  Return user info of the group owner.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_group_owner(const vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->owner);

    return self->owner;
}

//
//  Create a new group and register it in the cloud (Keyknox).
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_create(
        vssq_messenger_group_t *self, vsc_str_t group_id, const vssq_messenger_user_list_t *participants) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(group_id));
    VSSQ_ASSERT_PTR(participants);

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Generate initial epoch for a group session.
    //
    vsc_buffer_t *session_id = vssq_messenger_group_calculate_session_id(group_id);

    vssq_messenger_group_epoch_t *initial_epoch =
            vssq_messenger_group_generate_initial_epoch(self, vsc_buffer_data(session_id), participants, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Push the epoch to the cloud.
    //
    error.status = vssq_messenger_group_epoch_keyknox_storage_write(
            self->epoch_keyknox_storage, vsc_buffer_data(session_id), initial_epoch, participants);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Store state.
    //
    VSSQ_ASSERT_NULL(self->owner);
    VSSQ_ASSERT_NULL(self->epochs);
    VSSQ_ASSERT(!vsc_str_mutable_is_valid(self->group_id));

    self->group_id = vsc_str_mutable_from_str(group_id);
    self->owner = vssq_messenger_user_shallow_copy_const(vssq_messenger_auth_user(self->auth));
    const vscf_status_t foundation_status = vscf_group_session_add_epoch(
            self->group_session, vssq_messenger_group_epoch_group_info_message(initial_epoch));
    VSSQ_ASSERT_PROJECT_FOUNDATION_SUCCESS(foundation_status);
    self->epochs = vssq_messenger_group_epoch_list_new();
    vssq_messenger_group_epoch_list_add(self->epochs, &initial_epoch);

cleanup:
    vsc_buffer_destroy(&session_id);
    vssq_messenger_group_epoch_destroy(&initial_epoch);

    return vssq_error_status(&error);
}

//
//  Load an existing group from the cloud (Keyknox).
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load(vssq_messenger_group_t *self, vsc_str_t group_id, const vssq_messenger_user_t *owner) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(group_id));
    VSSQ_ASSERT_PTR(owner);

    VSSQ_ASSERT_NULL(self->owner);
    VSSQ_ASSERT_NULL(self->epochs);
    VSSQ_ASSERT(!vsc_str_mutable_is_valid(self->group_id));

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Pull epochs from the cloud.
    //
    vsc_buffer_t *session_id = vssq_messenger_group_calculate_session_id(group_id);

    self->epochs = vssq_messenger_group_epoch_keyknox_storage_read_all(
            self->epoch_keyknox_storage, vsc_buffer_data(session_id), owner, &error);

    for (const vssq_messenger_group_epoch_list_t *epoch_it = self->epochs;
            (epoch_it != NULL) && vssq_messenger_group_epoch_list_has_item(epoch_it);
            epoch_it = vssq_messenger_group_epoch_list_next(epoch_it)) {

        const vssq_messenger_group_epoch_t *group_epoch = vssq_messenger_group_epoch_list_item(epoch_it);
        const vscf_status_t foundation_status = vscf_group_session_add_epoch(
                self->group_session, vssq_messenger_group_epoch_group_info_message(group_epoch));
        VSSQ_ASSERT_PROJECT_FOUNDATION_SUCCESS(foundation_status);
    }

    //
    //  Store state.
    //
    if (!vssq_error_has_error(&error)) {
        self->group_id = vsc_str_mutable_from_str(group_id);
        self->owner = vssq_messenger_user_shallow_copy_const(owner);
    }

    vsc_buffer_destroy(&session_id);

    return vssq_error_status(&error);
}

//
//  Load an existing group from a cached JSON value for a group messaging.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load_from_json(vssq_messenger_group_t *self, const vssc_json_object_t *json_obj) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT_PTR(json_obj);

    VSSQ_ASSERT_NULL(self->owner);
    VSSQ_ASSERT_NULL(self->epochs);
    VSSQ_ASSERT(!vsc_str_mutable_is_valid(self->group_id));

    vssc_json_object_t *owner_json = NULL;
    vssc_json_array_t *epochs_json = NULL;

    vssq_messenger_user_t *owner = NULL;
    vssq_messenger_group_epoch_list_t *epochs = NULL;


    //
    //  Parse JSON:
    //
    //  {
    //      "version" : "v1",
    //      "group_id" : "STRING",
    //      "owner" : {},
    //      "epochs" : []
    //  }
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_str_t version = vssc_json_object_get_string_value(json_obj, k_json_key_version, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error) || !vsc_str_equal(k_json_version_v1, version)) {
        return vssq_status_IMPORT_GROUP_FAILED_VERSION_MISMATCH;
    }

    vsc_str_t group_id = vssc_json_object_get_string_value(json_obj, k_json_key_group_id, &core_sdk_error);
    if (!vsc_str_is_valid_and_non_empty(group_id)) {
        vssq_error_update(&error, vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    owner_json = vssc_json_object_get_object_value(json_obj, k_json_key_owner, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    owner = vssq_messenger_user_from_json(owner_json, self->random, &error);
    if (vssq_error_has_error(&error)) {
        vssq_error_update(&error, vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    epochs_json = vssc_json_object_get_array_value(json_obj, k_json_key_epochs, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    epochs = vssq_messenger_group_epoch_list_new();

    for (size_t pos = 0; pos < vssc_json_array_count(epochs_json); ++pos) {
        vssc_json_object_t *epoch_json = vssc_json_array_get_object_value(epochs_json, pos, &core_sdk_error);
        if (vssc_error_has_error(&core_sdk_error)) {
            vssq_error_update(&error, vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED);
            goto cleanup;
        }

        vssq_messenger_group_epoch_t *epoch = vssq_messenger_group_epoch_from_json(epoch_json, &error);
        vssc_json_object_destroy(&epoch_json);

        if (vssq_error_has_error(&error)) {
            vssq_error_update(&error, vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED);
            goto cleanup;
        }

        const vscf_status_t foundation_status =
                vscf_group_session_add_epoch(self->group_session, vssq_messenger_group_epoch_group_info_message(epoch));
        VSSQ_ASSERT_PROJECT_FOUNDATION_SUCCESS(foundation_status);

        vssq_messenger_group_epoch_list_add(epochs, &epoch);
    }

    self->group_id = vsc_str_mutable_from_str(group_id);
    self->owner = owner;
    self->epochs = epochs;

    owner = NULL;
    epochs = NULL;

cleanup:
    vssc_json_object_destroy(&owner_json);
    vssc_json_array_destroy(&epochs_json);
    vssq_messenger_user_destroy(&owner);
    vssq_messenger_group_epoch_list_destroy(&epochs);

    return vssq_error_status(&error);
}

//
//  Load an existing group from a cached JSON value for a group messaging.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load_from_json_str(vssq_messenger_group_t *self, vsc_str_t json_str) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(json_str));

    VSSQ_ASSERT_NULL(self->owner);
    VSSQ_ASSERT_NULL(self->epochs);
    VSSQ_ASSERT(!vsc_str_mutable_is_valid(self->group_id));

    vssc_json_object_t *json_obj = vssc_json_object_parse(json_str, NULL);

    if (NULL == json_obj) {
        return vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED;
    }

    const vssq_status_t status = vssq_messenger_group_load_from_json(self, json_obj);

    vssc_json_object_destroy(&json_obj);

    return status;
}

//
//  Return the group as JSON object.
//
//  JSON format:
//  {
//      "version" : "v1",
//      "group_id" : "STRING",
//      "owner" : {},
//      "epochs" : []
//  }
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_group_to_json(const vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->owner);
    VSSQ_ASSERT_PTR(self->epochs);
    VSSQ_ASSERT(vsc_str_mutable_is_valid(self->group_id));

    vssc_json_object_t *json_obj = vssc_json_object_new();
    vssc_json_object_add_string_value(json_obj, k_json_key_version, k_json_version_v1);
    vssc_json_object_add_string_value(json_obj, k_json_key_group_id, vsc_str_mutable_as_str(self->group_id));

    vssc_json_object_t *owner_json = vssq_messenger_user_to_json(self->owner, NULL);
    VSSQ_ASSERT_PTR(owner_json);
    vssc_json_object_add_object_value_disown(json_obj, k_json_key_owner, &owner_json);

    vssc_json_array_t *epochs_json = vssc_json_array_new();
    for (const vssq_messenger_group_epoch_list_t *epochs_it = self->epochs;
            (epochs_it != NULL) && vssq_messenger_group_epoch_list_has_item(epochs_it);
            epochs_it = vssq_messenger_group_epoch_list_next(epochs_it)) {

        const vssq_messenger_group_epoch_t *epoch = vssq_messenger_group_epoch_list_item(epochs_it);

        vssc_json_object_t *epoch_json = vssq_messenger_group_epoch_to_json(epoch);
        VSSQ_ASSERT_PTR(epoch_json);

        vssc_json_array_add_object_value_disown(epochs_json, &epoch_json);
    }
    vssc_json_object_add_array_value_disown(json_obj, k_json_key_epochs, &epochs_json);

    return json_obj;
}

//
//  Delete group.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_remove(vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->owner);
    VSSQ_ASSERT_PTR(self->group_session);

    const bool can_remove = vssq_messenger_group_check_permission_modify(self);
    if (!can_remove) {
        return vssq_status_MODIFY_GROUP_FAILED_PERMISSION_VIOLATION;
    }

    vsc_data_t session_id = vscf_group_session_get_session_id(self->group_session);

    const vssq_status_t status =
            vssq_messenger_group_epoch_keyknox_storage_remove_all(self->epoch_keyknox_storage, session_id);


    return status;
}

//
//  Return a buffer length enough to hold an encrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_encrypted_message_len(const vssq_messenger_group_t *self, size_t plaintext_len) {

    VSSQ_ASSERT_PTR(self);

    return 320 + plaintext_len;
}

//
//  Encrypt a group message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_encrypt_message(const vssq_messenger_group_t *self, vsc_str_t plaintext, vsc_buffer_t *out) {

    VSSQ_ASSERT(vsc_str_is_valid(plaintext));

    return vssq_messenger_group_encrypt_binary_message(self, vsc_str_as_data(plaintext), out);
}

//
//  Encrypt a group message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_encrypt_binary_message(const vssq_messenger_group_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT_PTR(self->group_session);
    VSSQ_ASSERT(vsc_data_is_valid(data));
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_group_encrypted_message_len(self, data.len));

    const vssq_messenger_creds_t *self_creds = vssq_messenger_auth_creds(self->auth);
    const vscf_impl_t *self_private_key = vssq_messenger_creds_private_key(self_creds);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_group_session_message_t *session_message =
            vscf_group_session_encrypt(self->group_session, data, self_private_key, &foundation_error);

    if (vscf_error_has_error(&foundation_error)) {
        const vssq_status_t status = vssq_messenger_group_map_foundation_status(vscf_error_status(&foundation_error));
        return status;
    }

    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vscf_group_session_message_serialize_len(session_message));
    vscf_group_session_message_serialize(session_message, out);

    vscf_group_session_message_destroy(&session_message);

    return vssq_status_SUCCESS;
}

//
//  Return a buffer length enough to hold a decrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_decrypted_message_len(const vssq_messenger_group_t *self, size_t encrypted_len) {

    VSSQ_ASSERT_PTR(self);

    return encrypted_len;
}

//
//  Decrypt a group message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_decrypt_message(const vssq_messenger_group_t *self, vsc_data_t encrypted_message,
        const vssq_messenger_user_t *from_user, vsc_str_buffer_t *out) {

    VSSQ_ASSERT(vsc_str_buffer_is_valid(out));

    return vssq_messenger_group_decrypt_binary_message(self, encrypted_message, from_user, &out->buffer);
}

//
//  Decrypt a group message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_decrypt_binary_message(const vssq_messenger_group_t *self, vsc_data_t encrypted_message,
        const vssq_messenger_user_t *from_user, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT_PTR(from_user);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(encrypted_message));
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_group_decrypted_message_len(self, encrypted_message.len));

    //
    //  Deserialize message.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_group_session_message_t *group_message =
            vscf_group_session_message_deserialize(encrypted_message, &foundation_error);

    if (vscf_error_has_error(&foundation_error)) {
        const vssq_status_t status = vssq_messenger_group_map_foundation_status(vscf_error_status(&foundation_error));
        return status;
    }

    //
    //  Pull correspond epoch to the cache.
    //
    const size_t message_epoch_num = vscf_group_session_message_get_epoch(group_message);
    const vssq_status_t load_epoch_status = vssq_messenger_group_load_epoch_if_needed(self, message_epoch_num);
    if (load_epoch_status != vssq_status_SUCCESS) {
        vscf_group_session_message_destroy(&group_message);
        return load_epoch_status;
    }

    //
    //  Decrypt message.
    //
    const vssc_card_t *sender_card = vssq_messenger_user_card(from_user);
    const vscf_impl_t *sender_public_key = vssc_card_public_key(sender_card);

    foundation_error.status = vscf_group_session_decrypt(self->group_session, group_message, sender_public_key, out);

    vscf_group_session_message_destroy(&group_message);

    const vssq_status_t status = vssq_messenger_group_map_foundation_status(vscf_error_status(&foundation_error));

    return status;
}

//
//  Calculate session id based on the group id.
//
static vsc_buffer_t *
vssq_messenger_group_calculate_session_id(vsc_str_t group_id) {

    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(group_id));

    vsc_buffer_t *session_id = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

    vscf_sha512_hash(vsc_str_as_data(group_id), session_id);

    VSSQ_ASSERT((size_t)vscf_sha512_DIGEST_LEN >= (size_t)vssq_messenger_group_SESSION_ID_LEN);
    vsc_buffer_dec_used(session_id, vscf_sha512_DIGEST_LEN - vssq_messenger_group_SESSION_ID_LEN);

    return session_id;
}

//
//  Generate initial epoch for a new group.
//
static vssq_messenger_group_epoch_t *
vssq_messenger_group_generate_initial_epoch(const vssq_messenger_group_t *self, vsc_data_t session_id,
        const vssq_messenger_user_list_t *participants, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_data_is_valid(session_id));
    VSSQ_ASSERT(vssq_messenger_group_SESSION_ID_LEN == session_id.len);
    VSSQ_ASSERT_PTR(participants);

    //
    //  Generate ticket.
    //
    vscf_group_session_ticket_t *epoch_ticket = vscf_group_session_ticket_new();
    vscf_group_session_ticket_use_rng(epoch_ticket, self->random);
    const vscf_status_t foundation_status = vscf_group_session_ticket_setup_ticket_as_new(epoch_ticket, session_id);

    if (foundation_status != vscf_status_SUCCESS) {
        vscf_group_session_ticket_destroy(&epoch_ticket);
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_CREATE_GROUP_FAILED_CRYPTO_FAILED);
        return NULL;
    }

    //
    //  Get participants identities.
    //
    const vssq_messenger_user_t *owner = vssq_messenger_auth_user(self->auth);
    vssc_string_list_t *participant_identities = vssc_string_list_new();
    vssc_string_list_add(participant_identities, vssc_card_identity(vssq_messenger_user_card(owner)));

    for (const vssq_messenger_user_list_t *user_it = participants;
            (user_it != NULL) && vssq_messenger_user_list_has_item(user_it);
            user_it = vssq_messenger_user_list_next(user_it)) {

        const vssq_messenger_user_t *user = vssq_messenger_user_list_item(user_it);
        vssc_string_list_add(participant_identities, vssc_card_identity(vssq_messenger_user_card(user)));
    }

    const vscf_group_session_message_t *group_info_message = vscf_group_session_ticket_get_ticket_message(epoch_ticket);

    vssq_messenger_group_epoch_t *group_epoch =
            vssq_messenger_group_epoch_new_with_disown(group_info_message, &participant_identities);

    vscf_group_session_ticket_destroy(&epoch_ticket);

    return group_epoch;
}

//
//  Load requested epoch if needed and store it within cache.
//
//  Note, method is thread-safe.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load_epoch_if_needed(const vssq_messenger_group_t *self, size_t epoch_num) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);

    vssq_error_t error;
    vssq_error_reset(&error);

    VSSQ_ATOMIC_CRITICAL_SECTION_DECLARE(load_epoch);
    VSSQ_ATOMIC_CRITICAL_SECTION_BEGIN(load_epoch);

    const vssq_messenger_group_epoch_t *epoch = vssq_messenger_group_epoch_list_find(self->epochs, epoch_num, &error);
    if (epoch) {
        // cache found
        goto cleanup;
    }

    // pull from the cloud
    vsc_data_t session_id = vscf_group_session_get_session_id(self->group_session);
    vssq_messenger_group_epoch_t *group_epoch = vssq_messenger_group_epoch_keyknox_storage_read(
            self->epoch_keyknox_storage, session_id, epoch_num, self->owner, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    const vscf_status_t foundation_status = vscf_group_session_add_epoch(
            self->group_session, vssq_messenger_group_epoch_group_info_message(group_epoch));
    VSSQ_ASSERT_PROJECT_FOUNDATION_SUCCESS(foundation_status);

    vssq_messenger_group_epoch_list_add(self->epochs, &group_epoch);

cleanup:
    VSSQ_ATOMIC_CRITICAL_SECTION_END(load_epoch);

    return error.status;
}

//
//  Map status from the "foundation" library to a status related to the groups.
//
static vssq_status_t
vssq_messenger_group_map_foundation_status(vscf_status_t foundation_status) {

    switch (foundation_status) {
    case vscf_status_SUCCESS:
        return vssq_status_SUCCESS;

    case vscf_status_ERROR_SESSION_ID_DOESNT_MATCH:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_SESSION_ID_DOESNT_MATCH;

    case vscf_status_ERROR_EPOCH_NOT_FOUND:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_EPOCH_NOT_FOUND;

    case vscf_status_ERROR_WRONG_KEY_TYPE:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_WRONG_KEY_TYPE;

    case vscf_status_ERROR_INVALID_SIGNATURE:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_INVALID_SIGNATURE;

    case vscf_status_ERROR_ED25519:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_ED25519_FAILED;

    case vscf_status_ERROR_DUPLICATE_EPOCH:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_DUPLICATE_EPOCH;

    case vscf_status_ERROR_PLAIN_TEXT_TOO_LONG:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_PLAIN_TEXT_TOO_LONG;

    default:
        return vssq_status_PROCESS_GROUP_MESSAGE_FAILED_CRYPTO_FAILED;
    }
}

//
//  Check if current user can modify a group.
//
VSSQ_PUBLIC bool
vssq_messenger_group_check_permission_modify(const vssq_messenger_group_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT_PTR(self->owner);


    const vssq_messenger_user_t *self_user = vssq_messenger_auth_user(self->auth);
    const vssc_card_t *self_card = vssq_messenger_user_card(self_user);
    const vssc_card_t *owner_card = vssq_messenger_user_card(self->owner);

    vsc_str_t self_identity = vssc_card_identity(self_card);
    vsc_str_t owner_identity = vssc_card_identity(owner_card);

    const bool can_modify = vsc_str_equal(self_identity, owner_identity);

    return can_modify;
}
