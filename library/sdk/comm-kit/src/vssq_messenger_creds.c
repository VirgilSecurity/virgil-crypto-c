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


//  @description
// --------------------------------------------------------------------------
//  Contains user private key and credentials (JWT) to the messenger services.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_creds.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_creds_private.h"
#include "vssq_messenger_creds_defs.h"

#include <virgil/crypto/foundation/vscf_key_provider.h>
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
//  Note, this method is called automatically when method vssq_messenger_creds_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_creds_init_ctx(vssq_messenger_creds_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_creds_cleanup_ctx(vssq_messenger_creds_t *self);

//
//  Create fully defined object.
//
static void
vssq_messenger_creds_init_ctx_with(vssq_messenger_creds_t *self, vsc_str_t card_id, vsc_str_t username,
        const vscf_impl_t *private_key);

//
//  Create fully defined object.
//
static void
vssq_messenger_creds_init_ctx_with_disown(vssq_messenger_creds_t *self, vsc_str_t username, vsc_str_t card_id,
        vscf_impl_t **private_key_ref);

static const char k_json_key_version_chars[] = "version";

static const vsc_str_t k_json_key_version = {
    k_json_key_version_chars,
    sizeof(k_json_key_version_chars) - 1
};

static const char k_json_key_card_id_chars[] = "card_id";

static const vsc_str_t k_json_key_card_id = {
    k_json_key_card_id_chars,
    sizeof(k_json_key_card_id_chars) - 1
};

static const char k_json_key_username_chars[] = "username";

static const vsc_str_t k_json_key_username = {
    k_json_key_username_chars,
    sizeof(k_json_key_username_chars) - 1
};

static const char k_json_key_private_key_chars[] = "private_key";

static const vsc_str_t k_json_key_private_key = {
    k_json_key_private_key_chars,
    sizeof(k_json_key_private_key_chars) - 1
};

static const char k_version_v1_chars[] = "v1";

static const vsc_str_t k_version_v1 = {
    k_version_v1_chars,
    sizeof(k_version_v1_chars) - 1
};

//
//  Return size of 'vssq_messenger_creds_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_creds_ctx_size(void) {

    return sizeof(vssq_messenger_creds_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_creds_init(vssq_messenger_creds_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_creds_t));

    self->refcnt = 1;

    vssq_messenger_creds_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_creds_cleanup(vssq_messenger_creds_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_creds_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_creds_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_new(void) {

    vssq_messenger_creds_t *self = (vssq_messenger_creds_t *) vssq_alloc(sizeof (vssq_messenger_creds_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_creds_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_creds_init_with(vssq_messenger_creds_t *self, vsc_str_t card_id, vsc_str_t username,
        const vscf_impl_t *private_key) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_creds_t));

    self->refcnt = 1;

    vssq_messenger_creds_init_ctx_with(self, card_id, username, private_key);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_new_with(vsc_str_t card_id, vsc_str_t username, const vscf_impl_t *private_key) {

    vssq_messenger_creds_t *self = (vssq_messenger_creds_t *) vssq_alloc(sizeof (vssq_messenger_creds_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_creds_init_with(self, card_id, username, private_key);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_creds_init_with_disown(vssq_messenger_creds_t *self, vsc_str_t username, vsc_str_t card_id,
        vscf_impl_t **private_key_ref) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_creds_t));

    self->refcnt = 1;

    vssq_messenger_creds_init_ctx_with_disown(self, username, card_id, private_key_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_new_with_disown(vsc_str_t username, vsc_str_t card_id, vscf_impl_t **private_key_ref) {

    vssq_messenger_creds_t *self = (vssq_messenger_creds_t *) vssq_alloc(sizeof (vssq_messenger_creds_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_creds_init_with_disown(self, username, card_id, private_key_ref);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_creds_delete(const vssq_messenger_creds_t *self) {

    vssq_messenger_creds_t *local_self = (vssq_messenger_creds_t *)self;

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

    vssq_messenger_creds_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_creds_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_creds_destroy(vssq_messenger_creds_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_creds_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_creds_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_shallow_copy(vssq_messenger_creds_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_creds_shallow_copy_const(const vssq_messenger_creds_t *self) {

    return vssq_messenger_creds_shallow_copy((vssq_messenger_creds_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_creds_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_creds_init_ctx(vssq_messenger_creds_t *self) {

    VSSQ_UNUSED(self);
    VSSQ_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_creds_cleanup_ctx(vssq_messenger_creds_t *self) {

    VSSQ_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->username);
    vsc_str_mutable_release(&self->card_id);
    vscf_impl_delete(self->private_key);
}

//
//  Create fully defined object.
//
static void
vssq_messenger_creds_init_ctx_with(
        vssq_messenger_creds_t *self, vsc_str_t card_id, vsc_str_t username, const vscf_impl_t *private_key) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(card_id));
    VSSQ_ASSERT_PTR(private_key);

    self->username = vsc_str_mutable_from_str(username);
    self->card_id = vsc_str_mutable_from_str(card_id);
    self->private_key = vscf_impl_shallow_copy_const(private_key);
}

//
//  Create fully defined object.
//
static void
vssq_messenger_creds_init_ctx_with_disown(
        vssq_messenger_creds_t *self, vsc_str_t username, vsc_str_t card_id, vscf_impl_t **private_key_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(card_id));
    VSSQ_ASSERT_REF(private_key_ref);

    self->username = vsc_str_mutable_from_str(username);
    self->card_id = vsc_str_mutable_from_str(card_id);
    self->private_key = *private_key_ref;

    *private_key_ref = NULL;
}

//
//  Return identifier of the user Virgil Card.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_creds_card_id(const vssq_messenger_creds_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_mutable_is_valid(self->card_id));

    return vsc_str_mutable_as_str(self->card_id);
}

//
//  Return the username.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_creds_username(const vssq_messenger_creds_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_mutable_is_valid(self->username));

    return vsc_str_mutable_as_str(self->username);
}

//
//  Return the user private key.
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_creds_private_key(const vssq_messenger_creds_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->private_key);

    return self->private_key;
}

//
//  Return credentials as JSON object.
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_creds_to_json(const vssq_messenger_creds_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->private_key);

    //
    //  Decalre vars.
    //
    vsc_buffer_t *exported_private_key = NULL;
    vscf_key_provider_t *key_provider = NULL;
    vssc_json_object_t *json_obj = NULL;

    vscf_status_t foundation_status = vscf_status_SUCCESS;

    //
    //  Setup crypto and declare vars.
    //
    key_provider = vscf_key_provider_new();

    foundation_status = vscf_key_provider_setup_defaults(key_provider);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_EXPORT_CREDS_FAILED_INIT_CRYPTO_FAILED);
        goto cleanup;
    }

    //
    //  Export private key.
    //
    const size_t exported_private_key_len = vscf_key_provider_exported_private_key_len(key_provider, self->private_key);

    exported_private_key = vsc_buffer_new_with_capacity(exported_private_key_len);

    foundation_status = vscf_key_provider_export_private_key(key_provider, self->private_key, exported_private_key);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_EXPORT_CREDS_FAILED_EXPORT_PRIVATE_KEY_FAILED);
        goto cleanup;
    }

    //
    //  Build json:
    //
    //  {
    //      "version" : "v1",
    //      "username" : "STRING",
    //      "card_id" : "HEX_STRING",
    //      "private_key" : "BASE64_STRING"
    //  }
    //
    json_obj = vssc_json_object_new();

    vssc_json_object_add_string_value(json_obj, k_json_key_version, k_version_v1);
    vssc_json_object_add_string_value(json_obj, k_json_key_username, vssq_messenger_creds_username(self));
    vssc_json_object_add_string_value(json_obj, k_json_key_card_id, vssq_messenger_creds_card_id(self));
    vssc_json_object_add_binary_value(json_obj, k_json_key_private_key, vsc_buffer_data(exported_private_key));

cleanup:
    vscf_key_provider_destroy(&key_provider);
    vsc_buffer_destroy(&exported_private_key);

    return json_obj;
}

//
//  Parse credentials from JSON.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_from_json(const vssc_json_object_t *json_obj, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(json_obj);

    //
    //  Parse json:
    //
    //  {
    //      "version" : "v1",
    //      "username" : "STRING",
    //      "card_id" : "HEX_STRING",
    //      "private_key" : "BASE64_STRING"
    //  }
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_str_t version = vssc_json_object_get_string_value(json_obj, k_json_key_version, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error) || !vsc_str_equal(k_version_v1, version)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED);
        return NULL;
    }

    vsc_str_t username = vssc_json_object_get_string_value(json_obj, k_json_key_username, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error) || vsc_str_is_empty(username)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED);
        return NULL;
    }

    vsc_str_t card_id = vssc_json_object_get_string_value(json_obj, k_json_key_card_id, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error) || vsc_str_is_empty(card_id)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED);
        return NULL;
    }

    vsc_buffer_t *private_key_buf =
            vssc_json_object_get_binary_value_new(json_obj, k_json_key_private_key, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED);
        return NULL;
    }

    //
    //  Setup crypto and declare vars.
    //
    vssq_messenger_creds_t *self = NULL;
    vscf_impl_t *private_key = NULL;

    vscf_key_provider_t *key_provider = vscf_key_provider_new();

    vscf_status_t foundation_status = vscf_key_provider_setup_defaults(key_provider);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_INIT_CRYPTO_FAILED);
        goto cleanup;
    }

    //
    //  Import private key.
    //
    private_key = vscf_key_provider_import_private_key(key_provider, vsc_buffer_data(private_key_buf), NULL);

    if (NULL == private_key) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_IMPORT_PRIVATE_KEY_FAILED);
        goto cleanup;
    }

    self = vssq_messenger_creds_new_with_disown(username, card_id, &private_key);

cleanup:
    vsc_buffer_destroy(&private_key_buf);
    vscf_key_provider_destroy(&key_provider);

    return self;
}

//
//  Parse credentials from JSON string.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_from_json_str(vsc_str_t json_str, vssq_error_t *error) {

    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(json_str));

    vssc_json_object_t *json_obj = vssc_json_object_parse(json_str, NULL);

    if (NULL == json_obj) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED);
        return NULL;
    }

    vssq_messenger_creds_t *self = vssq_messenger_creds_from_json(json_obj, error);

    vssc_json_object_destroy(&json_obj);

    return self;
}
