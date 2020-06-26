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
//  Helps to communicate with Virgil Keyknox Service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssk_keyknox_client.h"
#include "vssk_memory.h"
#include "vssk_assert.h"
#include "vssk_keyknox_client_defs.h"

#include <virgil/crypto/foundation/private/vscf_base64_private.h>
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
//  Note, this method is called automatically when method vssk_keyknox_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssk_keyknox_client_init_ctx(vssk_keyknox_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssk_keyknox_client_cleanup_ctx(vssk_keyknox_client_t *self);

//
//  Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssk_keyknox_client_init_ctx_with_base_url(vssk_keyknox_client_t *self, vsc_str_t url);

//
//  Parse keyknox entry from json object.
//
static vssk_keyknox_entry_t *
vssk_keyknox_client_parse_keyknox_entry(const vssc_virgil_http_response_t *response, vssk_error_t *error);

//
//  Base service URL.
//
static const char k_base_url[] = "https://api.virgilsecurity.com";

//
//  Base service URL.
//
static const vsc_str_t k_base_url_str = {
    k_base_url,
    sizeof(k_base_url) - 1
};

//
//  POST /push
//
static const char k_url_path_push[] = "/keyknox/v2/push";

//
//  POST /push
//
static const vsc_str_t k_url_path_push_str = {
    k_url_path_push,
    sizeof(k_url_path_push) - 1
};

//
//  POST /pull
//
static const char k_url_path_pull[] = "/keyknox/v2/pull";

//
//  POST /pull
//
static const vsc_str_t k_url_path_pull_str = {
    k_url_path_pull,
    sizeof(k_url_path_pull) - 1
};

//
//  POST /keys
//
static const char k_url_path_keys[] = "/keyknox/v2/keys";

//
//  POST /keys
//
static const vsc_str_t k_url_path_keys_str = {
    k_url_path_keys,
    sizeof(k_url_path_keys) - 1
};

//
//  POST /reset
//
static const char k_url_path_reset[] = "/keyknox/v2/reset";

//
//  POST /reset
//
static const vsc_str_t k_url_path_reset_str = {
    k_url_path_reset,
    sizeof(k_url_path_reset) - 1
};

//
//  JSON key: owner
//
static const char k_json_key_owner[] = "owner";

//
//  JSON key: owner
//
static const vsc_str_t k_json_key_owner_str = {
    k_json_key_owner,
    sizeof(k_json_key_owner) - 1
};

//
//  JSON key: root
//
static const char k_json_key_root[] = "root";

//
//  JSON key: root
//
static const vsc_str_t k_json_key_root_str = {
    k_json_key_root,
    sizeof(k_json_key_root) - 1
};

//
//  JSON key: path
//
static const char k_json_key_path[] = "path";

//
//  JSON key: path
//
static const vsc_str_t k_json_key_path_str = {
    k_json_key_path,
    sizeof(k_json_key_path) - 1
};

//
//  JSON key: key
//
static const char k_json_key_key[] = "key";

//
//  JSON key: key
//
static const vsc_str_t k_json_key_key_str = {
    k_json_key_key,
    sizeof(k_json_key_key) - 1
};

//
//  JSON key: identity
//
static const char k_json_key_identity[] = "identity";

//
//  JSON key: identity
//
static const vsc_str_t k_json_key_identity_str = {
    k_json_key_identity,
    sizeof(k_json_key_identity) - 1
};

//
//  JSON key: identities
//
static const char k_json_key_identities[] = "identities";

//
//  JSON key: identities
//
static const vsc_str_t k_json_key_identities_str = {
    k_json_key_identities,
    sizeof(k_json_key_identities) - 1
};

//
//  JSON key: meta
//
static const char k_json_key_meta[] = "meta";

//
//  JSON key: meta
//
static const vsc_str_t k_json_key_meta_str = {
    k_json_key_meta,
    sizeof(k_json_key_meta) - 1
};

//
//  JSON key: value
//
static const char k_json_key_value[] = "value";

//
//  JSON key: value
//
static const vsc_str_t k_json_key_value_str = {
    k_json_key_value,
    sizeof(k_json_key_value) - 1
};

//
//  Custom HTTP header: Virgil-Keyknox-Hash
//
static const char k_header_name_virgil_keyknox_hash[] = "Virgil-Keyknox-Hash";

//
//  Custom HTTP header: Virgil-Keyknox-Hash
//
static const vsc_str_t k_header_name_virgil_keyknox_hash_str = {
    k_header_name_virgil_keyknox_hash,
    sizeof(k_header_name_virgil_keyknox_hash) - 1
};

//
//  Custom HTTP header: Virgil-Keyknox-Previous-Hash
//
static const char k_header_name_virgil_keyknox_previous_hash[] = "Virgil-Keyknox-Previous-Hash";

//
//  Custom HTTP header: Virgil-Keyknox-Previous-Hash
//
static const vsc_str_t k_header_name_virgil_keyknox_previous_hash_str = {
    k_header_name_virgil_keyknox_previous_hash,
    sizeof(k_header_name_virgil_keyknox_previous_hash) - 1
};

//
//  Return size of 'vssk_keyknox_client_t'.
//
VSSK_PUBLIC size_t
vssk_keyknox_client_ctx_size(void) {

    return sizeof(vssk_keyknox_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSK_PUBLIC void
vssk_keyknox_client_init(vssk_keyknox_client_t *self) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_client_t));

    self->refcnt = 1;

    vssk_keyknox_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSK_PUBLIC void
vssk_keyknox_client_cleanup(vssk_keyknox_client_t *self) {

    if (self == NULL) {
        return;
    }

    vssk_keyknox_client_cleanup_ctx(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_client_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSK_PUBLIC vssk_keyknox_client_t *
vssk_keyknox_client_new(void) {

    vssk_keyknox_client_t *self = (vssk_keyknox_client_t *) vssk_alloc(sizeof (vssk_keyknox_client_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_client_init(self);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSK_PUBLIC void
vssk_keyknox_client_init_with_base_url(vssk_keyknox_client_t *self, vsc_str_t url) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_client_t));

    self->refcnt = 1;

    vssk_keyknox_client_init_ctx_with_base_url(self, url);
}

//
//  Allocate class context and perform it's initialization.
//  Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSK_PUBLIC vssk_keyknox_client_t *
vssk_keyknox_client_new_with_base_url(vsc_str_t url) {

    vssk_keyknox_client_t *self = (vssk_keyknox_client_t *) vssk_alloc(sizeof (vssk_keyknox_client_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_client_init_with_base_url(self, url);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSK_PUBLIC void
vssk_keyknox_client_delete(const vssk_keyknox_client_t *self) {

    vssk_keyknox_client_t *local_self = (vssk_keyknox_client_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSK_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSK_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssk_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssk_keyknox_client_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssk_keyknox_client_new ()'.
//
VSSK_PUBLIC void
vssk_keyknox_client_destroy(vssk_keyknox_client_t **self_ref) {

    VSSK_ASSERT_PTR(self_ref);

    vssk_keyknox_client_t *self = *self_ref;
    *self_ref = NULL;

    vssk_keyknox_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSK_PUBLIC vssk_keyknox_client_t *
vssk_keyknox_client_shallow_copy(vssk_keyknox_client_t *self) {

    VSSK_ASSERT_PTR(self);

    #if defined(VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSK_PUBLIC const vssk_keyknox_client_t *
vssk_keyknox_client_shallow_copy_const(const vssk_keyknox_client_t *self) {

    return vssk_keyknox_client_shallow_copy((vssk_keyknox_client_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssk_keyknox_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssk_keyknox_client_init_ctx(vssk_keyknox_client_t *self) {

    VSSK_ASSERT_PTR(self);

    vssk_keyknox_client_init_ctx_with_base_url(self, k_base_url_str);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssk_keyknox_client_cleanup_ctx(vssk_keyknox_client_t *self) {

    VSSK_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->push_url);
    vsc_str_mutable_release(&self->pull_url);
    vsc_str_mutable_release(&self->keys_url);
    vsc_str_mutable_release(&self->reset_url);
}

//
//  Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssk_keyknox_client_init_ctx_with_base_url(vssk_keyknox_client_t *self, vsc_str_t url) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(url));

    self->push_url = vsc_str_mutable_concat(url, k_url_path_push_str);
    self->pull_url = vsc_str_mutable_concat(url, k_url_path_pull_str);
    self->keys_url = vsc_str_mutable_concat(url, k_url_path_keys_str);
    self->reset_url = vsc_str_mutable_concat(url, k_url_path_reset_str);
}

//
//  Create request that performs push operation.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_push(const vssk_keyknox_client_t *self, const vssk_keyknox_entry_t *new_entry) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT_PTR(new_entry);

    //
    //  Validate fields.
    //
    vsc_str_t root = vssk_keyknox_entry_root(new_entry);
    vsc_str_t path = vssk_keyknox_entry_path(new_entry);
    vsc_str_t key = vssk_keyknox_entry_key(new_entry);
    vsc_data_t meta = vssk_keyknox_entry_meta(new_entry);
    vsc_data_t value = vssk_keyknox_entry_value(new_entry);
    const vssc_string_list_t *identities = vssk_keyknox_entry_identities(new_entry);

    VSSK_ASSERT(!vsc_str_is_empty(root));
    VSSK_ASSERT(!vsc_str_is_empty(path));
    VSSK_ASSERT(!vsc_str_is_empty(key));
    VSSK_ASSERT(!vsc_data_is_empty(meta));
    VSSK_ASSERT(!vsc_data_is_empty(value));
    VSSK_ASSERT(vssc_string_list_has_item(identities));

    //
    //  Create json body.
    //
    vssc_json_object_t *json = vssc_json_object_new();
    vssc_json_object_add_string_value(json, k_json_key_root_str, root);
    vssc_json_object_add_string_value(json, k_json_key_path_str, path);
    vssc_json_object_add_string_value(json, k_json_key_key_str, key);
    vssc_json_object_add_binary_value(json, k_json_key_meta_str, meta);
    vssc_json_object_add_binary_value(json, k_json_key_value_str, value);

    vssc_json_array_t *identities_json = vssc_json_array_new();
    for (const vssc_string_list_t *identity_it = identities;
            (identity_it != NULL) && vssc_string_list_has_item(identity_it);
            identity_it = vssc_string_list_next(identity_it)) {

        vssc_json_array_add_string_value(identities_json, vssc_string_list_item(identity_it));
    }
    vssc_json_object_add_array_value(json, k_json_key_identities_str, identities_json);
    vssc_json_array_destroy(&identities_json);

    //
    //  Create request.
    //
    vsc_str_t json_body = vssc_json_object_as_str(json);
    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post_str, vsc_str_mutable_as_str(self->push_url), json_body);

    vssc_json_object_destroy(&json);

    //
    //  Add headers.
    //
    vsc_data_t previous_hash = vssk_keyknox_entry_hash(new_entry);
    if (!vsc_data_is_empty(previous_hash)) {
        vsc_buffer_t *previous_hash_buf = vscf_base64_encode_new(previous_hash);
        vsc_str_t previous_hash_str = vsc_str_from_data(vsc_buffer_data(previous_hash_buf));

        vssc_http_request_add_header(http_request, k_header_name_virgil_keyknox_previous_hash_str, previous_hash_str);

        vsc_buffer_destroy(&previous_hash_buf);
    }

    return http_request;
}

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_client_process_response_push(const vssc_virgil_http_response_t *response, vssk_error_t *error) {

    VSSK_ASSERT_PTR(response);

    return vssk_keyknox_client_parse_keyknox_entry(response, error);
}

//
//  Create request that performs pull operation.
//  Note, identity can be empty.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_pull(
        const vssk_keyknox_client_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key, vsc_str_t identity) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(root));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(path));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(key));
    VSSK_ASSERT(vsc_str_is_valid(identity));

    //
    //  Create json body.
    //
    vssc_json_object_t *json = vssc_json_object_new();
    vssc_json_object_add_string_value(json, k_json_key_root_str, root);
    vssc_json_object_add_string_value(json, k_json_key_path_str, path);
    vssc_json_object_add_string_value(json, k_json_key_key_str, key);

    if (!vsc_str_is_empty(identity)) {
        vssc_json_object_add_string_value(json, k_json_key_identity_str, identity);
    }

    //
    //  Create request.
    //
    vsc_str_t json_body = vssc_json_object_as_str(json);
    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post_str, vsc_str_mutable_as_str(self->pull_url), json_body);

    vssc_json_object_destroy(&json);

    return http_request;
}

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_client_process_response_pull(const vssc_virgil_http_response_t *response, vssk_error_t *error) {

    VSSK_ASSERT_PTR(response);

    return vssk_keyknox_client_parse_keyknox_entry(response, error);
}

//
//  Create request that performs reset operation.
//
//  Note, all parameters can be empty.
//  Note, if identity is given, only "key" parameter can be optional.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_reset(
        const vssk_keyknox_client_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key, vsc_str_t identity) {

    VSSK_ASSERT(vsc_str_is_valid(identity));
    VSSK_ASSERT(vsc_str_is_valid(key));

    if (vsc_str_is_empty(identity)) {
        VSSK_ASSERT(vsc_str_is_valid(root));
        VSSK_ASSERT(vsc_str_is_valid(path));
    } else {
        VSSK_ASSERT(vsc_str_is_valid_and_non_empty(root));
        VSSK_ASSERT(vsc_str_is_valid_and_non_empty(path));
    }

    //
    //  Create json body.
    //
    vssc_json_object_t *json = vssc_json_object_new();

    if (!vsc_str_is_empty(root)) {
        vssc_json_object_add_string_value(json, k_json_key_root_str, root);
    }

    if (!vsc_str_is_empty(path)) {
        vssc_json_object_add_string_value(json, k_json_key_path_str, path);
    }

    if (!vsc_str_is_empty(key)) {
        vssc_json_object_add_string_value(json, k_json_key_key_str, key);
    }

    if (!vsc_str_is_empty(identity)) {
        vssc_json_object_add_string_value(json, k_json_key_identity_str, identity);
    }

    //
    //  Create request.
    //
    vsc_str_t json_body = vssc_json_object_as_str(json);
    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post_str, vsc_str_mutable_as_str(self->reset_url), json_body);

    vssc_json_object_destroy(&json);

    return http_request;
}

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_client_process_response_reset(const vssc_virgil_http_response_t *response, vssk_error_t *error) {

    VSSK_ASSERT_PTR(response);

    vssc_error_t core_error;
    vssc_error_reset(&core_error);

    if (!vssc_virgil_http_response_is_success(response)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        return NULL;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_virgil_http_response_has_body(response)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_object_t *json = vssc_virgil_http_response_body(response);

    vsc_str_t owner = vssc_json_object_get_string_value(json, k_json_key_owner_str, &core_error);
    if (vsc_str_is_empty(owner)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        return NULL;
    };

    vsc_str_t root = vssc_json_object_get_string_value(json, k_json_key_root_str, &core_error);
    if (vssc_error_has_error(&core_error)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        return NULL;
    };

    vsc_str_t path = vssc_json_object_get_string_value(json, k_json_key_path_str, &core_error);
    if (vssc_error_has_error(&core_error)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        return NULL;
    };

    vsc_str_t key = vssc_json_object_get_string_value(json, k_json_key_key_str, &core_error);
    if (vssc_error_has_error(&core_error)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        return NULL;
    };

    return vssk_keyknox_entry_new_with_reset_entry(owner, root, path, key);
}

//
//  Create request that performs get keys operation.
//
//  Note, all parameters can be empty.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_get_keys(
        const vssk_keyknox_client_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t identity) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT(vsc_str_is_valid(root));
    VSSK_ASSERT(vsc_str_is_valid(path));
    VSSK_ASSERT(vsc_str_is_valid(identity));

    //
    //  Create json body.
    //
    vssc_json_object_t *json = vssc_json_object_new();

    if (!vsc_str_is_empty(root)) {
        vssc_json_object_add_string_value(json, k_json_key_root_str, root);
    }

    if (!vsc_str_is_empty(path)) {
        vssc_json_object_add_string_value(json, k_json_key_path_str, path);
    }

    if (!vsc_str_is_empty(identity)) {
        vssc_json_object_add_string_value(json, k_json_key_identity_str, identity);
    }

    //
    //  Create request.
    //
    vsc_str_t json_body = vssc_json_object_as_str(json);
    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post_str, vsc_str_mutable_as_str(self->keys_url), json_body);

    vssc_json_object_destroy(&json);

    return http_request;
}

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssc_string_list_t *
vssk_keyknox_client_process_response_get_keys(const vssc_virgil_http_response_t *response, vssk_error_t *error) {

    VSSK_ASSERT_PTR(response);

    vssc_error_t core_error;
    vssc_error_reset(&core_error);

    if (!vssc_virgil_http_response_is_success(response)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        return NULL;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_virgil_http_response_has_array_body(response)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_array_t *json_array = vssc_virgil_http_response_array_body(response);

    vssc_string_list_t *keys = vssc_string_list_new();
    for (size_t pos = 0; pos < vssc_json_array_len(json_array); ++pos) {
        vsc_str_t key = vssc_json_array_get_string_value(json_array, pos, &core_error);

        if (vsc_str_is_empty(key)) {
            vssc_string_list_destroy(&keys);

            VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);

            return NULL;
        }

        vssc_string_list_add(keys, key);
    }

    return keys;
}

//
//  Parse keyknox entry from json object.
//
static vssk_keyknox_entry_t *
vssk_keyknox_client_parse_keyknox_entry(const vssc_virgil_http_response_t *response, vssk_error_t *error) {

    VSSK_ASSERT_PTR(response);

    vssc_error_t core_error;
    vssc_error_reset(&core_error);

    vssc_json_array_t *identities_json = NULL;
    vssc_string_list_t *identities = NULL;
    vsc_buffer_t *meta = NULL;
    vsc_buffer_t *value = NULL;
    vsc_buffer_t *hash = NULL;


    if (!vssc_virgil_http_response_is_success(response)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        goto fail;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_virgil_http_response_has_body(response)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        goto fail;
    }

    const vssc_json_object_t *json = vssc_virgil_http_response_body(response);

    vsc_str_t owner = vssc_json_object_get_string_value(json, k_json_key_owner_str, &core_error);
    if (vsc_str_is_empty(owner)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    };

    vsc_str_t root = vssc_json_object_get_string_value(json, k_json_key_root_str, &core_error);
    if (vsc_str_is_empty(root)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    };

    vsc_str_t path = vssc_json_object_get_string_value(json, k_json_key_path_str, &core_error);
    if (vsc_str_is_empty(path)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    };

    vsc_str_t key = vssc_json_object_get_string_value(json, k_json_key_key_str, &core_error);
    if (vsc_str_is_empty(key)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    };


    identities_json = vssc_json_object_get_array_value(json, k_json_key_identities_str, &core_error);
    if (NULL == identities_json) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    }

    identities = vssc_string_list_new();
    for (size_t pos = 0; pos < vssc_json_array_len(identities_json); ++pos) {
        vsc_str_t identity = vssc_json_array_get_string_value(identities_json, pos, &core_error);

        if (vssc_error_has_error(&core_error)) {
            VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
            goto fail;
        }

        vssc_string_list_add(identities, identity);
    }

    meta = vssc_json_object_get_binary_value_new(json, k_json_key_meta_str, &core_error);
    if (NULL == meta) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    }

    value = vssc_json_object_get_binary_value_new(json, k_json_key_value_str, &core_error);
    if (NULL == value) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    }

    vsc_str_t hash_str =
            vssc_virgil_http_response_find_header(response, k_header_name_virgil_keyknox_hash_str, &core_error);

    if (vssc_error_has_error(&core_error)) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    }

    hash = vscf_base64_decode_new(vsc_str_as_data(hash_str), NULL);
    if (NULL == hash) {
        VSSK_ERROR_SAFE_UPDATE(error, vssk_status_KEYKNOX_ENTRY_PARSE_FAILED);
        goto fail;
    }

    vssc_json_array_destroy(&identities_json);

    return vssk_keyknox_entry_new_with_owner_disown(owner, root, path, key, &identities, &meta, &value, &hash);

fail:
    vssc_json_array_destroy(&identities_json);
    vssc_string_list_destroy(&identities);
    vsc_buffer_destroy(&meta);
    vsc_buffer_destroy(&value);
    vsc_buffer_destroy(&hash);

    return NULL;
}
