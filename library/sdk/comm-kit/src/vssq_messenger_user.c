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
//  Information about a messenger user, i.e. username, Virgil Card, etc.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_user.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_user_private.h"
#include "vssq_messenger_user_defs.h"

#include <virgil/sdk/core/vssc_card_manager.h>
#include <virgil/sdk/core/vssc_json_object.h>
#include <virgil/sdk/core/private/vssc_json_object_private.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_user_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_user_init_ctx(vssq_messenger_user_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_user_cleanup_ctx(vssq_messenger_user_t *self);

//
//  Create an object with required fields.
//
static void
vssq_messenger_user_init_ctx_with_card(vssq_messenger_user_t *self, const vssc_card_t *card);

//
//  Create an object with required fields.
//
static void
vssq_messenger_user_init_ctx_with_card_disown(vssq_messenger_user_t *self, vssc_card_t **card_ref);

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

static const char k_json_key_username_chars[] = "username";

static const vsc_str_t k_json_key_username = {
    k_json_key_username_chars,
    sizeof(k_json_key_username_chars) - 1
};

static const char k_json_key_phone_number_chars[] = "phone_number";

static const vsc_str_t k_json_key_phone_number = {
    k_json_key_phone_number_chars,
    sizeof(k_json_key_phone_number_chars) - 1
};

static const char k_json_key_email_chars[] = "email";

static const vsc_str_t k_json_key_email = {
    k_json_key_email_chars,
    sizeof(k_json_key_email_chars) - 1
};

static const char k_json_key_raw_card_chars[] = "raw_card";

static const vsc_str_t k_json_key_raw_card = {
    k_json_key_raw_card_chars,
    sizeof(k_json_key_raw_card_chars) - 1
};

//
//  Return size of 'vssq_messenger_user_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_user_ctx_size(void) {

    return sizeof(vssq_messenger_user_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_user_init(vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_user_t));

    self->refcnt = 1;

    vssq_messenger_user_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_user_cleanup(vssq_messenger_user_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_user_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_user_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_new(void) {

    vssq_messenger_user_t *self = (vssq_messenger_user_t *) vssq_alloc(sizeof (vssq_messenger_user_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_user_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create an object with required fields.
//
VSSQ_PUBLIC void
vssq_messenger_user_init_with_card(vssq_messenger_user_t *self, const vssc_card_t *card) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_user_t));

    self->refcnt = 1;

    vssq_messenger_user_init_ctx_with_card(self, card);
}

//
//  Allocate class context and perform it's initialization.
//  Create an object with required fields.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_new_with_card(const vssc_card_t *card) {

    vssq_messenger_user_t *self = (vssq_messenger_user_t *) vssq_alloc(sizeof (vssq_messenger_user_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_user_init_with_card(self, card);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create an object with required fields.
//
VSSQ_PUBLIC void
vssq_messenger_user_init_with_card_disown(vssq_messenger_user_t *self, vssc_card_t **card_ref) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_user_t));

    self->refcnt = 1;

    vssq_messenger_user_init_ctx_with_card_disown(self, card_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create an object with required fields.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_new_with_card_disown(vssc_card_t **card_ref) {

    vssq_messenger_user_t *self = (vssq_messenger_user_t *) vssq_alloc(sizeof (vssq_messenger_user_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_user_init_with_card_disown(self, card_ref);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_user_delete(const vssq_messenger_user_t *self) {

    vssq_messenger_user_t *local_self = (vssq_messenger_user_t *)self;

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

    vssq_messenger_user_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_user_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_user_destroy(vssq_messenger_user_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_user_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_user_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_shallow_copy(vssq_messenger_user_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_user_shallow_copy_const(const vssq_messenger_user_t *self) {

    return vssq_messenger_user_shallow_copy((vssq_messenger_user_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_user_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_user_init_ctx(vssq_messenger_user_t *self) {

    VSSQ_UNUSED(self);
    VSSQ_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_user_cleanup_ctx(vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssc_card_delete(self->card);
    vsc_str_mutable_release(&self->username);
}

//
//  Create an object with required fields.
//
static void
vssq_messenger_user_init_ctx_with_card(vssq_messenger_user_t *self, const vssc_card_t *card) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(card);

    self->card = vssc_card_shallow_copy_const(card);
}

//
//  Create an object with required fields.
//
static void
vssq_messenger_user_init_ctx_with_card_disown(vssq_messenger_user_t *self, vssc_card_t **card_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_REF(card_ref);

    self->card = *card_ref;
    *card_ref = NULL;
}

//
//  Return a user's Card.
//
VSSQ_PUBLIC const vssc_card_t *
vssq_messenger_user_card(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->card);

    return self->card;
}

//
//  Return a user's identity (Card's identity).
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_identity(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->card);

    return vssc_card_identity(self->card);
}

//
//  Return a user's public key (Card's public key).
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_user_public_key(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->card);

    return vssc_card_public_key(self->card);
}

//
//  Return a user's public key identifier (Card's public key identifier).
//
VSSQ_PUBLIC vsc_data_t
vssq_messenger_user_public_key_id(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->card);

    return vssc_card_public_key_id(self->card);
}

//
//  Return true if a username defined.
//
VSSQ_PUBLIC bool
vssq_messenger_user_has_username(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vsc_str_mutable_is_valid(self->username);
}

//
//  Return username, or an empty string if username not defined.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_username(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->username)) {
        return vsc_str_mutable_as_str(self->username);
    } else {
        return vsc_str_empty();
    }
}

//
//  Set an optional username.
//
VSSQ_PUBLIC void
vssq_messenger_user_set_username(vssq_messenger_user_t *self, vsc_str_t username) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));

    vsc_str_mutable_release(&self->username);
    self->username = vsc_str_mutable_from_str(username);
}

//
//  Return true if a phone number defined.
//
VSSQ_PUBLIC bool
vssq_messenger_user_has_phone_number(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vsc_str_mutable_is_valid(self->phone_number);
}

//
//  Return phone number, or an empty string if phone number not defined.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_phone_number(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->phone_number)) {
        return vsc_str_mutable_as_str(self->phone_number);
    } else {
        return vsc_str_empty();
    }
}

//
//  Set an optional phone number.
//
VSSQ_PUBLIC void
vssq_messenger_user_set_phone_number(vssq_messenger_user_t *self, vsc_str_t phone_number) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(phone_number));

    vsc_str_mutable_release(&self->phone_number);
    self->phone_number = vsc_str_mutable_from_str(phone_number);
}

//
//  Return true if a email defined.
//
VSSQ_PUBLIC bool
vssq_messenger_user_has_email(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vsc_str_mutable_is_valid(self->email);
}

//
//  Return email, or an empty string if email not defined.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_email(const vssq_messenger_user_t *self) {

    VSSQ_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->email)) {
        return vsc_str_mutable_as_str(self->email);
    } else {
        return vsc_str_empty();
    }
}

//
//  Set an optional email.
//
VSSQ_PUBLIC void
vssq_messenger_user_set_email(vssq_messenger_user_t *self, vsc_str_t email) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(email));

    vsc_str_mutable_release(&self->email);
    self->email = vsc_str_mutable_from_str(email);
}

//
//  Return user as JSON object.
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_user_to_json(const vssq_messenger_user_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_UNUSED(error);

    //
    //  Build json:
    //
    //  {
    //      "version" : "v1",
    //      "raw_card" : {},
    //      "username" : "STRING OPTIONAL",
    //      "phone_number" : "STRING OPTIONAL",
    //      "email" : "STRING OPTIONAL",
    //  }
    //
    vssc_json_object_t *card_json_obj = vssc_raw_card_export_as_json(vssc_card_get_raw_card(self->card));
    VSSQ_ASSERT_PTR(card_json_obj);

    vssc_json_object_t *json_obj = vssc_json_object_new();
    vssc_json_object_add_string_value(json_obj, k_json_key_version, k_json_version_v1);
    vssc_json_object_add_object_value(json_obj, k_json_key_raw_card, card_json_obj);

    vsc_str_t username = vssq_messenger_user_username(self);
    if (vsc_str_is_valid_and_non_empty(username)) {
        vssc_json_object_add_string_value(json_obj, k_json_key_username, username);
    }

    vsc_str_t phone_number = vssq_messenger_user_phone_number(self);
    if (vsc_str_is_valid_and_non_empty(phone_number)) {
        vssc_json_object_add_string_value(json_obj, k_json_key_phone_number, phone_number);
    }

    vsc_str_t email = vssq_messenger_user_email(self);
    if (vsc_str_is_valid_and_non_empty(email)) {
        vssc_json_object_add_string_value(json_obj, k_json_key_email, email);
    }

    vssc_json_object_destroy(&card_json_obj);

    return json_obj;
}

//
//  Parse user from JSON.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_from_json(const vssc_json_object_t *json_obj, const vscf_impl_t *random, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(json_obj);
    VSSQ_ASSERT_PTR(random);

    //
    //  Parse json:
    //
    //  {
    //      "version" : "v1",
    //      "raw_card" : {},
    //      "username" : "STRING OPTIONAL",
    //      "phone_number" : "STRING OPTIONAL",
    //      "email" : "STRING OPTIONAL",
    //  }
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_card_manager_t *card_manager = NULL;
    vssc_json_object_t *raw_card_json = NULL;
    vssc_raw_card_t *raw_card = NULL;
    vssc_card_t *card = NULL;
    vssq_messenger_user_t *self = NULL;

    vsc_str_t version = vssc_json_object_get_string_value(json_obj, k_json_key_version, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error) || !vsc_str_equal(k_json_version_v1, version)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_USER_FAILED_VERSION_MISMATCH);
        return NULL;
    }

    raw_card_json = vssc_json_object_get_object_value(json_obj, k_json_key_raw_card, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_USER_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    raw_card = vssc_raw_card_import_from_json(raw_card_json, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_USER_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, (vscf_impl_t *)random);
    core_sdk_error.status = vssc_card_manager_configure(card_manager);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_USER_FAILED_PARSE_FAILED);
        goto cleanup;
    }


    card = vssc_card_manager_import_raw_card(card_manager, raw_card, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_USER_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    self = vssq_messenger_user_new_with_card_disown(&card);

    vsc_str_t username = vssc_json_object_get_string_value(json_obj, k_json_key_username, &core_sdk_error);
    if (vsc_str_is_valid_and_non_empty(username)) {
        vssq_messenger_user_set_username(self, username);
    }

    vsc_str_t phone_number = vssc_json_object_get_string_value(json_obj, k_json_key_phone_number, &core_sdk_error);
    if (vsc_str_is_valid_and_non_empty(phone_number)) {
        vssq_messenger_user_set_phone_number(self, phone_number);
    }

    vsc_str_t email = vssc_json_object_get_string_value(json_obj, k_json_key_email, &core_sdk_error);
    if (vsc_str_is_valid_and_non_empty(email)) {
        vssq_messenger_user_set_email(self, email);
    }

cleanup:
    vssc_card_manager_destroy(&card_manager);
    vssc_json_object_destroy(&raw_card_json);
    vssc_raw_card_destroy(&raw_card);
    vssc_card_destroy(&card);

    return self;
}

//
//  Parse user from JSON string.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_from_json_str(vsc_str_t json_str, const vscf_impl_t *random, vssq_error_t *error) {

    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(json_str));
    VSSQ_ASSERT_PTR(random);

    vssc_json_object_t *json_obj = vssc_json_object_parse(json_str, NULL);

    if (NULL == json_obj) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED);
        return NULL;
    }

    vssq_messenger_user_t *self = vssq_messenger_user_from_json(json_obj, random, error);

    vssc_json_object_destroy(&json_obj);

    return self;
}
