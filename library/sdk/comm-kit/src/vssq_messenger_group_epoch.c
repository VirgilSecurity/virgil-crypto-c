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
//  Contains credentials of a group session related to the specifc epoch.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_group_epoch.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_group_epoch_defs.h"

#include <virgil/sdk/core/vssc_json_object.h>
#include <virgil/sdk/core/private/vssc_json_object_private.h>
#include <virgil/sdk/core/private/vssc_json_array_private.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_group_epoch_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_group_epoch_init_ctx(vssq_messenger_group_epoch_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_group_epoch_cleanup_ctx(vssq_messenger_group_epoch_t *self);

//
//  Create fully defined object.
//
static void
vssq_messenger_group_epoch_init_ctx_with_disown(vssq_messenger_group_epoch_t *self,
        const vscf_group_session_message_t *group_info_message, vssc_string_list_t **participant_identities_ref);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
static void
vssq_messenger_group_epoch_init_with_all_disown(vssq_messenger_group_epoch_t *self,
        vscf_group_session_message_t **group_info_message_ref, vssc_string_list_t **participant_identities_ref);

//
//  Create fully defined object.
//
static void
vssq_messenger_group_epoch_init_ctx_with_all_disown(vssq_messenger_group_epoch_t *self,
        vscf_group_session_message_t **group_info_message_ref, vssc_string_list_t **participant_identities_ref);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
static vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_new_with_all_disown(vscf_group_session_message_t **group_info_message_ref,
        vssc_string_list_t **participant_identities_ref);

//
//  JSON key: group_message
//
static const char k_json_key_group_message_chars[] = "group_message";

//
//  JSON key: group_message
//
static const vsc_str_t k_json_key_group_message = {
    k_json_key_group_message_chars,
    sizeof(k_json_key_group_message_chars) - 1
};

//
//  JSON key: participants
//
static const char k_json_key_participants_chars[] = "participants";

//
//  JSON key: participants
//
static const vsc_str_t k_json_key_participants = {
    k_json_key_participants_chars,
    sizeof(k_json_key_participants_chars) - 1
};

//
//  Return size of 'vssq_messenger_group_epoch_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_epoch_ctx_size(void) {

    return sizeof(vssq_messenger_group_epoch_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_init(vssq_messenger_group_epoch_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_epoch_t));

    self->refcnt = 1;

    vssq_messenger_group_epoch_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_cleanup(vssq_messenger_group_epoch_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_group_epoch_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_epoch_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_new(void) {

    vssq_messenger_group_epoch_t *self = (vssq_messenger_group_epoch_t *) vssq_alloc(sizeof (vssq_messenger_group_epoch_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_group_epoch_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_init_with_disown(vssq_messenger_group_epoch_t *self,
        const vscf_group_session_message_t *group_info_message, vssc_string_list_t **participant_identities_ref) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_epoch_t));

    self->refcnt = 1;

    vssq_messenger_group_epoch_init_ctx_with_disown(self, group_info_message, participant_identities_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_new_with_disown(const vscf_group_session_message_t *group_info_message,
        vssc_string_list_t **participant_identities_ref) {

    vssq_messenger_group_epoch_t *self = (vssq_messenger_group_epoch_t *) vssq_alloc(sizeof (vssq_messenger_group_epoch_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_group_epoch_init_with_disown(self, group_info_message, participant_identities_ref);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
static void
vssq_messenger_group_epoch_init_with_all_disown(vssq_messenger_group_epoch_t *self,
        vscf_group_session_message_t **group_info_message_ref, vssc_string_list_t **participant_identities_ref) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_group_epoch_t));

    self->refcnt = 1;

    vssq_messenger_group_epoch_init_ctx_with_all_disown(self, group_info_message_ref, participant_identities_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
static vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_new_with_all_disown(vscf_group_session_message_t **group_info_message_ref,
        vssc_string_list_t **participant_identities_ref) {

    vssq_messenger_group_epoch_t *self = (vssq_messenger_group_epoch_t *) vssq_alloc(sizeof (vssq_messenger_group_epoch_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_group_epoch_init_with_all_disown(self, group_info_message_ref, participant_identities_ref);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_delete(const vssq_messenger_group_epoch_t *self) {

    vssq_messenger_group_epoch_t *local_self = (vssq_messenger_group_epoch_t *)self;

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

    vssq_messenger_group_epoch_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_group_epoch_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_destroy(vssq_messenger_group_epoch_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_group_epoch_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_group_epoch_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_shallow_copy(vssq_messenger_group_epoch_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_shallow_copy_const(const vssq_messenger_group_epoch_t *self) {

    return vssq_messenger_group_epoch_shallow_copy((vssq_messenger_group_epoch_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_group_epoch_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_group_epoch_init_ctx(vssq_messenger_group_epoch_t *self) {

    VSSQ_UNUSED(self);
    VSSQ_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_group_epoch_cleanup_ctx(vssq_messenger_group_epoch_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_group_session_message_delete(self->group_info_message);
    vssc_string_list_destroy(&self->participant_identities);
}

//
//  Create fully defined object.
//
static void
vssq_messenger_group_epoch_init_ctx_with_disown(vssq_messenger_group_epoch_t *self,
        const vscf_group_session_message_t *group_info_message, vssc_string_list_t **participant_identities_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(group_info_message);
    VSSQ_ASSERT_REF(participant_identities_ref);
    VSSQ_ASSERT(vscf_group_session_message_get_type(group_info_message) == vscf_group_msg_type_GROUP_INFO);

    self->group_info_message = vscf_group_session_message_shallow_copy_const(group_info_message);
    self->participant_identities = *participant_identities_ref;

    *participant_identities_ref = NULL;
}

//
//  Create fully defined object.
//
static void
vssq_messenger_group_epoch_init_ctx_with_all_disown(vssq_messenger_group_epoch_t *self,
        vscf_group_session_message_t **group_info_message_ref, vssc_string_list_t **participant_identities_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_REF(group_info_message_ref);
    VSSQ_ASSERT_REF(participant_identities_ref);

    self->group_info_message = *group_info_message_ref;
    self->participant_identities = *participant_identities_ref;

    *group_info_message_ref = NULL;
    *participant_identities_ref = NULL;
}

//
//  Return group epoch serial number.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_epoch_num(const vssq_messenger_group_epoch_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vscf_group_session_message_get_epoch(self->group_info_message);
}

//
//  Return group epoch info and credentials.
//
VSSQ_PUBLIC const vscf_group_session_message_t *
vssq_messenger_group_epoch_group_info_message(const vssq_messenger_group_epoch_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->group_info_message);

    return self->group_info_message;
}

//
//  Return participant identities (Card's identities) that have access to this epoch.
//
VSSQ_PUBLIC const vssc_string_list_t *
vssq_messenger_group_epoch_participant_identities(const vssq_messenger_group_epoch_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->participant_identities);

    return self->participant_identities;
}

//
//  Return epoch as JSON object.
//
//  JSON format:
//  {
//      "group_message" : "BASE64(GroupMessage)"
//      "participants" : ["identity1", "identity2", ...]
//  }
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_group_epoch_to_json(const vssq_messenger_group_epoch_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssc_json_object_t *json_obj = vssc_json_object_new();

    //
    //  Write 'group_message'.
    //
    const size_t group_message_data_len = vscf_group_session_message_serialize_len(self->group_info_message);
    vsc_buffer_t *group_message_data = vsc_buffer_new_with_capacity(group_message_data_len);
    vscf_group_session_message_serialize(self->group_info_message, group_message_data);
    vssc_json_object_add_binary_value(json_obj, k_json_key_group_message, vsc_buffer_data(group_message_data));
    vsc_buffer_destroy(&group_message_data);

    //
    //  Write 'participants'.
    //
    vssc_json_array_t *participants_json_arr = vssc_json_array_new();
    vssc_json_array_add_string_values(participants_json_arr, self->participant_identities);

    vssc_json_object_add_array_value_disown(json_obj, k_json_key_participants, &participants_json_arr);

    return json_obj;
}

//
//  Parse epoch from JSON.
//
//  JSON format:
//  {
//      "group_message" : "BASE64(GroupMessage)"
//      "participants" : ["identity1", "identity2", ...]
//  }
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_from_json(const vssc_json_object_t *json_obj, vssq_error_t *error) {

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vsc_buffer_t *group_message_data = NULL;
    vscf_group_session_message_t *group_info_message = NULL;
    vssc_json_array_t *participants_json_arr = NULL;
    vssc_string_list_t *participants = NULL;


    group_message_data = vssc_json_object_get_binary_value_new(json_obj, k_json_key_group_message, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED);
        goto error;
    }

    group_info_message = vscf_group_session_message_deserialize(vsc_buffer_data(group_message_data), &foundation_error);
    if (vscf_error_has_error(&foundation_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED);
        goto error;
    }

    if (vscf_group_session_message_get_type(group_info_message) != vscf_group_msg_type_GROUP_INFO) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED);
        goto error;
    }

    participants_json_arr = vssc_json_object_get_array_value(json_obj, k_json_key_participants, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED);
        goto error;
    }

    participants = vssc_json_array_get_string_values(participants_json_arr, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED);
        goto error;
    }

    vsc_buffer_destroy(&group_message_data);
    vssc_json_array_destroy(&participants_json_arr);

    return vssq_messenger_group_epoch_new_with_all_disown(&group_info_message, &participants);

error:
    vsc_buffer_destroy(&group_message_data);
    vscf_group_session_message_destroy(&group_info_message);
    vssc_json_array_destroy(&participants_json_arr);
    vssc_string_list_destroy(&participants);

    return NULL;
}

//
//  Parse epoch from JSON string.
//
//  JSON format:
//  {
//      "group_message" : "BASE64(GroupMessage)"
//      "participants" : ["identity1", "identity2", ...]
//  }
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_from_json_str(vsc_str_t json_str, vssq_error_t *error) {

    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(json_str));

    vssc_json_object_t *json_obj = vssc_json_object_parse(json_str, NULL);

    if (NULL == json_obj) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED);
        return NULL;
    }

    vssq_messenger_group_epoch_t *self = vssq_messenger_group_epoch_from_json(json_obj, error);

    vssc_json_object_destroy(&json_obj);

    return self;
}
