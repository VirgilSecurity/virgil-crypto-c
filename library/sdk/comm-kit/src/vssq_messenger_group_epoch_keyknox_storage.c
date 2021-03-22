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
//  Provides read/write operations of the Group Epochs to/from remote
//  secure storage (Keyknox).
//
//  Note, a group credentials are unique to the epoch.
//  Note, a group credentials are encrypted for all group participants.
//
//  Keyknox internal structure:
//      {
//          "root" : "group-sessions",
//          "path" : "<session-id>",
//          "key"  : "<epoch>"
//      }
//
//      * <session-id> - HEX(sha512(session-id):0..32)
//      * <epoch>      - integer counter, incrementing epoch means group key rotatation
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_group_epoch_keyknox_storage.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_group_epoch_keyknox_storage_defs.h"

#include <virgil/crypto/foundation/vscf_binary.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/sdk/core/vssc_json_object.h>
#include <virgil/sdk/core/vssc_virgil_http_client.h>
#include <virgil/sdk/keyknox/vssk_keyknox_client.h>
#include <virgil/sdk/keyknox/vssk_keyknox_entry.h>
#include <virgil/crypto/common/vsc_str.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_group_epoch_keyknox_storage_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_group_epoch_keyknox_storage_init_ctx(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_group_epoch_keyknox_storage_cleanup_ctx(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Encrypt a group epoch and put it to the Keyknox entry.
//
static vssk_keyknox_entry_t *
vssq_messenger_group_epoch_keyknox_storage_keyknox_pack_group_epoch(
        const vssq_messenger_group_epoch_keyknox_storage_t *self, vsc_data_t session_id,
        const vssq_messenger_group_epoch_t *group_epoch, const vssq_messenger_user_list_t *participants,
        vssq_error_t *error);

//
//  Extract a group epoch from the Keyknox entry and decrypt it.
//
static vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_keyknox_storage_keyknox_unpack_group_epoch(
        const vssq_messenger_group_epoch_keyknox_storage_t *self, const vssk_keyknox_entry_t *keyknox_entry,
        const vssq_messenger_user_t *owner, vssq_error_t *error);

//
//  Push an encrypted group epoch to the Keyknox.
//
static vssq_status_t
vssq_messenger_group_epoch_keyknox_storage_keyknox_push_entry(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        const vssk_keyknox_entry_t *keyknox_entry) VSSQ_NODISCARD;

//
//  Pull an encrypted group epoch from the Keyknox.
//
static vssk_keyknox_entry_t *
vssq_messenger_group_epoch_keyknox_storage_keyknox_pull_entry(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_str_t session_id, vsc_str_t group_epoch_num, vsc_str_t owner_identity, vssq_error_t *error);

//
//  Keyknox root: group-sessions
//
static const char k_keyknox_root_id_group_sessions_chars[] = "group-sessions";

//
//  Keyknox root: group-sessions
//
static const vsc_str_t k_keyknox_root_id_group_sessions = {
    k_keyknox_root_id_group_sessions_chars,
    sizeof(k_keyknox_root_id_group_sessions_chars) - 1
};

//
//  Return size of 'vssq_messenger_group_epoch_keyknox_storage_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_epoch_keyknox_storage_ctx_size(void) {

    return sizeof(vssq_messenger_group_epoch_keyknox_storage_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_init(vssq_messenger_group_epoch_keyknox_storage_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_epoch_keyknox_storage_t));

    self->refcnt = 1;

    vssq_messenger_group_epoch_keyknox_storage_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_cleanup(vssq_messenger_group_epoch_keyknox_storage_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_group_epoch_keyknox_storage_release_random(self);
    vssq_messenger_group_epoch_keyknox_storage_release_auth(self);

    vssq_messenger_group_epoch_keyknox_storage_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_epoch_keyknox_storage_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_keyknox_storage_t *
vssq_messenger_group_epoch_keyknox_storage_new(void) {

    vssq_messenger_group_epoch_keyknox_storage_t *self = (vssq_messenger_group_epoch_keyknox_storage_t *) vssq_alloc(sizeof (vssq_messenger_group_epoch_keyknox_storage_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_group_epoch_keyknox_storage_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_delete(const vssq_messenger_group_epoch_keyknox_storage_t *self) {

    vssq_messenger_group_epoch_keyknox_storage_t *local_self = (vssq_messenger_group_epoch_keyknox_storage_t *)self;

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

    vssq_messenger_group_epoch_keyknox_storage_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_group_epoch_keyknox_storage_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_destroy(vssq_messenger_group_epoch_keyknox_storage_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_group_epoch_keyknox_storage_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_group_epoch_keyknox_storage_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_keyknox_storage_t *
vssq_messenger_group_epoch_keyknox_storage_shallow_copy(vssq_messenger_group_epoch_keyknox_storage_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_group_epoch_keyknox_storage_t *
vssq_messenger_group_epoch_keyknox_storage_shallow_copy_const(
        const vssq_messenger_group_epoch_keyknox_storage_t *self) {

    return vssq_messenger_group_epoch_keyknox_storage_shallow_copy((vssq_messenger_group_epoch_keyknox_storage_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_use_random(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_take_random(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_release_random(vssq_messenger_group_epoch_keyknox_storage_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the class 'messenger auth' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_use_auth(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vssq_messenger_auth_t *auth) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(auth);
    VSSQ_ASSERT(self->auth == NULL);

    self->auth = vssq_messenger_auth_shallow_copy(auth);
}

//
//  Setup dependency to the class 'messenger auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_take_auth(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vssq_messenger_auth_t *auth) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(auth);
    VSSQ_ASSERT(self->auth == NULL);

    self->auth = auth;
}

//
//  Release dependency to the class 'messenger auth'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_release_auth(vssq_messenger_group_epoch_keyknox_storage_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_auth_destroy(&self->auth);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_group_epoch_keyknox_storage_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_group_epoch_keyknox_storage_init_ctx(vssq_messenger_group_epoch_keyknox_storage_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_group_epoch_keyknox_storage_cleanup_ctx(vssq_messenger_group_epoch_keyknox_storage_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Encrypt given group epoch for all participants and for self and push it to the Keyknox.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_epoch_keyknox_storage_write(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, const vssq_messenger_group_epoch_t *group_epoch,
        const vssq_messenger_user_list_t *participants) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(session_id));
    VSSQ_ASSERT_PTR(group_epoch);
    VSSQ_ASSERT_PTR(participants);

    vssq_error_t error;
    vssq_error_reset(&error);

    vssk_keyknox_entry_t *keyknox_entry = vssq_messenger_group_epoch_keyknox_storage_keyknox_pack_group_epoch(
            self, session_id, group_epoch, participants, &error);

    if (vssq_error_has_error(&error)) {
        return vssq_error_status(&error);
    }

    error.status = vssq_messenger_group_epoch_keyknox_storage_keyknox_push_entry(self, keyknox_entry);

    vssk_keyknox_entry_destroy(&keyknox_entry);

    return vssq_error_status(&error);
}

//
//  Pull requested epoch from the Keyknox, decrypt it and verify owner's signature.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_keyknox_storage_read(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, size_t group_epoch_num, const vssq_messenger_user_t *owner, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(session_id));
    VSSQ_ASSERT_PTR(owner);

    vsc_str_buffer_t *session_id_hex = vsc_str_buffer_new_with_capacity(vscf_binary_to_hex_len(session_id.len));
    vscf_binary_to_hex(session_id, session_id_hex);

    vsc_str_buffer_t *group_epoch_num_str =
            vssq_messenger_group_epoch_keyknox_storage_stringify_epoch_num(group_epoch_num);

    const vssc_card_t *owner_card = vssq_messenger_user_card(owner);
    const vsc_str_t owner_identity = vssc_card_identity(owner_card);

    vssk_keyknox_entry_t *keyknox_entry = vssq_messenger_group_epoch_keyknox_storage_keyknox_pull_entry(
            self, vsc_str_buffer_str(session_id_hex), vsc_str_buffer_str(group_epoch_num_str), owner_identity, error);

    vsc_str_buffer_destroy(&session_id_hex);
    vsc_str_buffer_destroy(&group_epoch_num_str);

    if (NULL == keyknox_entry) {
        return NULL;
    }

    vssq_messenger_group_epoch_t *group_epoch =
            vssq_messenger_group_epoch_keyknox_storage_keyknox_unpack_group_epoch(self, keyknox_entry, owner, error);

    vssk_keyknox_entry_destroy(&keyknox_entry);

    return group_epoch;
}

//
//  Pull all epochs from the Keyknox, decrypt it and verify owner's signature.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_list_t *
vssq_messenger_group_epoch_keyknox_storage_read_all(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, const vssq_messenger_user_t *owner, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(session_id));
    VSSQ_ASSERT_PTR(owner);

    vssc_number_list_t *epoch_nums =
            vssq_messenger_group_epoch_keyknox_storage_read_epoch_nums(self, session_id, owner, error);

    if (NULL == epoch_nums) {
        return NULL;
    }

    vssq_messenger_group_epoch_list_t *group_epoch_list = vssq_messenger_group_epoch_list_new();

    for (const vssc_number_list_t *epoch_num_it = epoch_nums;
            (epoch_num_it != NULL) && vssc_number_list_has_item(epoch_num_it);
            epoch_num_it = vssc_number_list_next(epoch_num_it)) {

        const size_t group_epoch_num = vssc_number_list_item(epoch_num_it);

        vssq_messenger_group_epoch_t *group_epoch =
                vssq_messenger_group_epoch_keyknox_storage_read(self, session_id, group_epoch_num, owner, error);

        if (group_epoch != NULL) {
            vssq_messenger_group_epoch_list_add(group_epoch_list, &group_epoch);
        } else {
            vssc_number_list_destroy(&epoch_nums);
            vssq_messenger_group_epoch_list_destroy(&group_epoch_list);
            return NULL;
        }
    }

    vssc_number_list_destroy(&epoch_nums);

    return group_epoch_list;
}

//
//  Remove all epochs from the Keyknox.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_epoch_keyknox_storage_remove_all(
        const vssq_messenger_group_epoch_keyknox_storage_t *self, vsc_data_t session_id) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(session_id));

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssk_error_t keyknox_sdk_error;
    vssk_error_reset(&keyknox_sdk_error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vsc_str_buffer_t *session_id_hex = NULL;

    //
    //  Reset Keyknox entries.
    //
    session_id_hex = vsc_str_buffer_new_with_capacity(vscf_binary_to_hex_len(session_id.len));
    vscf_binary_to_hex(session_id, session_id_hex);

    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_reset(keyknox_client, k_keyknox_root_id_group_sessions,
            vsc_str_buffer_str(session_id_hex), vsc_str_empty(), vsc_str_empty());

    http_response = vssq_messenger_auth_send_virgil_request(self->auth, http_request, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        error.status = vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR;
        goto cleanup;
    }

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vsc_str_buffer_destroy(&session_id_hex);

    return error.status;
}

//
//  Pull available epoch serial numbers.
//
VSSQ_PUBLIC vssc_number_list_t *
vssq_messenger_group_epoch_keyknox_storage_read_epoch_nums(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, const vssq_messenger_user_t *owner, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(session_id));
    VSSQ_ASSERT_PTR(owner);

    //
    //  Declare vars.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_error_t keyknox_sdk_error;
    vssk_error_reset(&keyknox_sdk_error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssc_number_list_t *epoch_nums = NULL;
    vsc_str_buffer_t *session_id_hex = NULL;

    //
    //  Pull epochs from the Keyknox.
    //
    const vssc_card_t *owner_card = vssq_messenger_user_card(owner);
    const vsc_str_t owner_identity = vssc_card_identity(owner_card);

    session_id_hex = vsc_str_buffer_new_with_capacity(vscf_binary_to_hex_len(session_id.len));
    vscf_binary_to_hex(session_id, session_id_hex);

    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_get_keys(
            keyknox_client, k_keyknox_root_id_group_sessions, vsc_str_buffer_str(session_id_hex), owner_identity);

    http_response = vssq_messenger_auth_send_virgil_request(self->auth, http_request, error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    if (!vssc_http_response_body_is_json_array(http_response)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    const vssc_json_array_t *json_array = vssc_http_response_body_as_json_array(http_response);

    epoch_nums = vssc_json_array_get_number_values(json_array, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vsc_str_buffer_destroy(&session_id_hex);

    return epoch_nums;
}

//
//  Return string representation of the given number.
//
VSSQ_PUBLIC vsc_str_buffer_t *
vssq_messenger_group_epoch_keyknox_storage_stringify_epoch_num(size_t num) {

    vsc_str_buffer_t *num_str_buf =
            vsc_str_buffer_new_with_capacity(vssq_messenger_group_epoch_keyknox_storage_NUM_STR_LEN_MAX);

    const int len =
            vssq_snprintf(vsc_str_buffer_unused_chars(num_str_buf), vsc_str_buffer_unused_len(num_str_buf), "%zu", num);

    VSSQ_ASSERT(len > 0 && (size_t)len < (size_t)vssq_messenger_group_epoch_keyknox_storage_NUM_STR_LEN_MAX);
    vsc_str_buffer_inc_used(num_str_buf, (size_t)len);

    return num_str_buf;
}

//
//  Encrypt a group epoch and put it to the Keyknox entry.
//
static vssk_keyknox_entry_t *
vssq_messenger_group_epoch_keyknox_storage_keyknox_pack_group_epoch(
        const vssq_messenger_group_epoch_keyknox_storage_t *self, vsc_data_t session_id,
        const vssq_messenger_group_epoch_t *group_epoch, const vssq_messenger_user_list_t *participants,
        vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(session_id));
    VSSQ_ASSERT_PTR(group_epoch);
    VSSQ_ASSERT_PTR(participants);

    //
    //  Declare vars.
    //
    vscf_status_t foundation_status = vscf_status_SUCCESS;

    char epoch_num_chars[4] = {'\0'};

    vssc_json_object_t *group_epoch_json = NULL;
    vscf_recipient_cipher_t *cipher = NULL;

    vsc_str_buffer_t *session_id_hex = NULL;
    vsc_buffer_t *keyknox_meta = NULL;
    vsc_buffer_t *keyknox_value = NULL;

    vssk_keyknox_entry_t *keyknox_entry = NULL;

    //
    //  Export.
    //
    group_epoch_json = vssq_messenger_group_epoch_to_json(group_epoch);
    vsc_data_t group_epoch_json_data = vsc_str_as_data(vssc_json_object_as_str(group_epoch_json));

    //
    //  Encrypt.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);

    // add self (owner) to recipients and signers
    const vssq_messenger_user_t *owner = vssq_messenger_auth_user(self->auth);
    const vssc_card_t *owner_card = vssq_messenger_user_card(owner);
    const vsc_data_t owner_id = vssc_card_public_key_id(owner_card);
    const vscf_impl_t *owner_public_key = vssc_card_public_key(owner_card);
    vscf_recipient_cipher_add_key_recipient(cipher, owner_id, owner_public_key);

    const vssq_messenger_creds_t *owner_creds = vssq_messenger_auth_creds(self->auth);
    const vscf_impl_t *owner_private_key = vssq_messenger_creds_private_key(owner_creds);

    vscf_recipient_cipher_add_key_recipient(cipher, owner_id, owner_public_key);

    foundation_status = vscf_recipient_cipher_add_signer(cipher, owner_id, owner_private_key);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED);
        goto cleanup;
    }

    // add others
    for (const vssq_messenger_user_list_t *user_it = participants;
            (user_it != NULL) && vssq_messenger_user_list_has_item(user_it);
            user_it = vssq_messenger_user_list_next(user_it)) {

        const vssq_messenger_user_t *user = vssq_messenger_user_list_item(user_it);
        const vssc_card_t *user_card = vssq_messenger_user_card(user);
        const vsc_data_t recipient_id = vssc_card_public_key_id(user_card);
        const vscf_impl_t *recipient_public_key = vssc_card_public_key(user_card);
        vscf_recipient_cipher_add_key_recipient(cipher, recipient_id, recipient_public_key);
    }


    foundation_status = vscf_recipient_cipher_start_signed_encryption(cipher, group_epoch_json_data.len);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED);
        goto cleanup;
    }


    keyknox_meta = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_len(cipher));
    vscf_recipient_cipher_pack_message_info(cipher, keyknox_meta);

    keyknox_value =
            vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len(cipher, group_epoch_json_data.len) +
                                         vscf_recipient_cipher_encryption_out_len(cipher, 0));

    foundation_status = vscf_recipient_cipher_process_encryption(cipher, group_epoch_json_data, keyknox_value);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED);
        goto cleanup;
    }

    foundation_status = vscf_recipient_cipher_finish_encryption(cipher, keyknox_value);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED);
        goto cleanup;
    }

    const size_t footer_len = vscf_recipient_cipher_message_info_footer_len(cipher);
    vsc_buffer_reserve_unused(keyknox_value, footer_len);

    foundation_status = vscf_recipient_cipher_pack_message_info_footer(cipher, keyknox_value);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED);
        goto cleanup;
    }

    //
    //  Pack.
    //
    session_id_hex = vsc_str_buffer_new_with_capacity(vscf_binary_to_hex_len(session_id.len));
    vscf_binary_to_hex(session_id, session_id_hex);

    const size_t epoch_num = vssq_messenger_group_epoch_num(group_epoch);
    VSSQ_ASSERT(epoch_num < 1000);

    vssq_snprintf(epoch_num_chars, sizeof(epoch_num_chars) - 1, "%zu", epoch_num);
    vsc_str_t epoch_num_str = vsc_str_from_str(epoch_num_chars);

    const vssc_string_list_t *keyknox_identites = vssq_messenger_group_epoch_participant_identities(group_epoch);
    keyknox_entry = vssk_keyknox_entry_new_with(k_keyknox_root_id_group_sessions, vsc_str_buffer_str(session_id_hex),
            epoch_num_str, keyknox_identites, vsc_buffer_data(keyknox_meta), vsc_buffer_data(keyknox_value),
            vsc_data_empty());

cleanup:
    vssc_json_object_destroy(&group_epoch_json);
    vscf_recipient_cipher_destroy(&cipher);
    vsc_str_buffer_destroy(&session_id_hex);
    vsc_buffer_destroy(&keyknox_meta);
    vsc_buffer_destroy(&keyknox_value);
    vsc_str_buffer_destroy(&session_id_hex);

    return keyknox_entry;
}

//
//  Extract a group epoch from the Keyknox entry and decrypt it.
//
static vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_keyknox_storage_keyknox_unpack_group_epoch(
        const vssq_messenger_group_epoch_keyknox_storage_t *self, const vssk_keyknox_entry_t *keyknox_entry,
        const vssq_messenger_user_t *owner, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT_PTR(keyknox_entry);
    VSSQ_ASSERT_PTR(owner);

    //
    //  Declare vars.
    //
    vscf_recipient_cipher_t *cipher = NULL;
    vsc_buffer_t *group_epoch_data = NULL;
    vssq_messenger_group_epoch_t *group_epoch = NULL;

    //
    //  Decrypt Keyknox entry.
    //
    vscf_status_t foundation_status = vscf_status_SUCCESS;

    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);

    const vssc_card_t *owner_card = vssq_messenger_user_card(owner);
    const vsc_data_t owner_id = vssc_card_public_key_id(owner_card);
    const vscf_impl_t *owner_public_key = vssc_card_public_key(owner_card);

    const vssq_messenger_user_t *self_user = vssq_messenger_auth_user(self->auth);
    const vssc_card_t *self_card = vssq_messenger_user_card(self_user);
    const vsc_data_t self_id = vssc_card_public_key_id(self_card);

    const vssq_messenger_creds_t *self_creds = vssq_messenger_auth_creds(self->auth);
    const vscf_impl_t *self_private_key = vssq_messenger_creds_private_key(self_creds);

    vsc_data_t keyknox_meta = vssk_keyknox_entry_meta(keyknox_entry);
    vsc_data_t keyknox_value = vssk_keyknox_entry_value(keyknox_entry);

    foundation_status =
            vscf_recipient_cipher_start_decryption_with_key(cipher, self_id, self_private_key, keyknox_meta);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    group_epoch_data =
            vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(cipher, keyknox_value.len) +
                                         vscf_recipient_cipher_decryption_out_len(cipher, 0));

    foundation_status = vscf_recipient_cipher_process_decryption(cipher, keyknox_value, group_epoch_data);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    foundation_status = vscf_recipient_cipher_finish_decryption(cipher, group_epoch_data);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    //
    //  Verify signature.
    //
    if (!vscf_recipient_cipher_is_data_signed(cipher)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(cipher);
    if (!vscf_signer_info_list_has_item(signer_infos)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);
    if (!vsc_data_equal(owner_id, vscf_signer_info_signer_id(signer_info))) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    if (!vscf_recipient_cipher_verify_signer_info(cipher, signer_info, owner_public_key)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    vsc_str_t group_epoch_str = vsc_str_from_data(vsc_buffer_data(group_epoch_data));
    group_epoch = vssq_messenger_group_epoch_from_json_str(group_epoch_str, error);

cleanup:
    vscf_recipient_cipher_destroy(&cipher);
    vsc_buffer_destroy(&group_epoch_data);

    return group_epoch;
}

//
//  Push an encrypted group epoch to the Keyknox.
//
static vssq_status_t
vssq_messenger_group_epoch_keyknox_storage_keyknox_push_entry(
        const vssq_messenger_group_epoch_keyknox_storage_t *self, const vssk_keyknox_entry_t *keyknox_entry) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT_PTR(keyknox_entry);

    vssq_error_t error;
    vssq_error_reset(&error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new();
    vssc_http_request_t *http_request = vssk_keyknox_client_make_request_push(keyknox_client, keyknox_entry);
    vssc_http_response_t *http_response = vssq_messenger_auth_send_virgil_request(self->auth, http_request, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        error.status = vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR;
        goto cleanup;
    }

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);

    return error.status;
}

//
//  Pull an encrypted group epoch from the Keyknox.
//
static vssk_keyknox_entry_t *
vssq_messenger_group_epoch_keyknox_storage_keyknox_pull_entry(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_str_t session_id, vsc_str_t group_epoch_num, vsc_str_t owner_identity, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);

    //
    //  Declare vars.
    //
    vssk_error_t keyknox_sdk_error;
    vssk_error_reset(&keyknox_sdk_error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssk_keyknox_entry_t *keyknox_entry = NULL;

    //
    //  Pull encrypted credentials from the Keyknox.
    //
    keyknox_client = vssk_keyknox_client_new();
    http_request = vssk_keyknox_client_make_request_pull(
            keyknox_client, k_keyknox_root_id_group_sessions, session_id, group_epoch_num, owner_identity);

    http_response = vssq_messenger_auth_send_virgil_request(self->auth, http_request, error);

    if (NULL == http_response) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_REQUEST_FAILED);
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    keyknox_entry = vssk_keyknox_client_process_response_pull(http_response, &keyknox_sdk_error);

    if (vssk_error_has_error(&keyknox_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);

    return keyknox_entry;
}
