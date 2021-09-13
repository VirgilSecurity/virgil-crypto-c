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
//  Helps to communicate with Virgil Pythia Service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssp_pythia_client.h"
#include "vssp_memory.h"
#include "vssp_assert.h"
#include "vssp_pythia_client_defs.h"
#include "vssp_brain_key_seed_private.h"

#include <virgil/sdk/core/vssc_json_object.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssp_pythia_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssp_pythia_client_init_ctx(vssp_pythia_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssp_pythia_client_cleanup_ctx(vssp_pythia_client_t *self);

//
//  Create Pythia Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssp_pythia_client_init_ctx_with_base_url(vssp_pythia_client_t *self, vsc_str_t url);

//
//  Base service URL.
//
static const char k_base_url_chars[] = "https://api.virgilsecurity.com";

//
//  Base service URL.
//
static const vsc_str_t k_base_url = {
    k_base_url_chars,
    sizeof(k_base_url_chars) - 1
};

//
//  POST /brainkey
//
static const char k_brain_key_url_path_chars[] = "/pythia/v1/brainkey";

//
//  POST /brainkey
//
static const vsc_str_t k_brain_key_url_path = {
    k_brain_key_url_path_chars,
    sizeof(k_brain_key_url_path_chars) - 1
};

//
//  JSON key: blinded_password
//
static const char k_json_key_blinded_password_chars[] = "blinded_password";

//
//  JSON key: blinded_password
//
static const vsc_str_t k_json_key_blinded_password = {
    k_json_key_blinded_password_chars,
    sizeof(k_json_key_blinded_password_chars) - 1
};

//
//  JSON key: brainkey_id
//
static const char k_json_key_brainkey_id_chars[] = "brainkey_id";

//
//  JSON key: brainkey_id
//
static const vsc_str_t k_json_key_brainkey_id = {
    k_json_key_brainkey_id_chars,
    sizeof(k_json_key_brainkey_id_chars) - 1
};

//
//  JSON key: seed
//
static const char k_json_key_seed_chars[] = "seed";

//
//  JSON key: seed
//
static const vsc_str_t k_json_key_seed = {
    k_json_key_seed_chars,
    sizeof(k_json_key_seed_chars) - 1
};

//
//  Return size of 'vssp_pythia_client_t'.
//
VSSP_PUBLIC size_t
vssp_pythia_client_ctx_size(void) {

    return sizeof(vssp_pythia_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSP_PUBLIC void
vssp_pythia_client_init(vssp_pythia_client_t *self) {

    VSSP_ASSERT_PTR(self);

    vssp_zeroize(self, sizeof(vssp_pythia_client_t));

    self->refcnt = 1;

    vssp_pythia_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSP_PUBLIC void
vssp_pythia_client_cleanup(vssp_pythia_client_t *self) {

    if (self == NULL) {
        return;
    }

    vssp_pythia_client_cleanup_ctx(self);

    vssp_zeroize(self, sizeof(vssp_pythia_client_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSP_PUBLIC vssp_pythia_client_t *
vssp_pythia_client_new(void) {

    vssp_pythia_client_t *self = (vssp_pythia_client_t *) vssp_alloc(sizeof (vssp_pythia_client_t));
    VSSP_ASSERT_ALLOC(self);

    vssp_pythia_client_init(self);

    self->self_dealloc_cb = vssp_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Pythia Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSP_PUBLIC void
vssp_pythia_client_init_with_base_url(vssp_pythia_client_t *self, vsc_str_t url) {

    VSSP_ASSERT_PTR(self);

    vssp_zeroize(self, sizeof(vssp_pythia_client_t));

    self->refcnt = 1;

    vssp_pythia_client_init_ctx_with_base_url(self, url);
}

//
//  Allocate class context and perform it's initialization.
//  Create Pythia Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSP_PUBLIC vssp_pythia_client_t *
vssp_pythia_client_new_with_base_url(vsc_str_t url) {

    vssp_pythia_client_t *self = (vssp_pythia_client_t *) vssp_alloc(sizeof (vssp_pythia_client_t));
    VSSP_ASSERT_ALLOC(self);

    vssp_pythia_client_init_with_base_url(self, url);

    self->self_dealloc_cb = vssp_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSP_PUBLIC void
vssp_pythia_client_delete(const vssp_pythia_client_t *self) {

    vssp_pythia_client_t *local_self = (vssp_pythia_client_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSP_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSP_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssp_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssp_pythia_client_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssp_pythia_client_new ()'.
//
VSSP_PUBLIC void
vssp_pythia_client_destroy(vssp_pythia_client_t **self_ref) {

    VSSP_ASSERT_PTR(self_ref);

    vssp_pythia_client_t *self = *self_ref;
    *self_ref = NULL;

    vssp_pythia_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSP_PUBLIC vssp_pythia_client_t *
vssp_pythia_client_shallow_copy(vssp_pythia_client_t *self) {

    VSSP_ASSERT_PTR(self);

    #if defined(VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSP_PUBLIC const vssp_pythia_client_t *
vssp_pythia_client_shallow_copy_const(const vssp_pythia_client_t *self) {

    return vssp_pythia_client_shallow_copy((vssp_pythia_client_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssp_pythia_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssp_pythia_client_init_ctx(vssp_pythia_client_t *self) {

    VSSP_ASSERT_PTR(self);

    vssp_pythia_client_init_ctx_with_base_url(self, k_base_url);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssp_pythia_client_cleanup_ctx(vssp_pythia_client_t *self) {

    VSSP_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->brain_key_url);
}

//
//  Create Pythia Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssp_pythia_client_init_ctx_with_base_url(vssp_pythia_client_t *self, vsc_str_t url) {

    VSSP_ASSERT_PTR(self);
    VSSP_ASSERT(vsc_str_is_valid_and_non_empty(url));

    self->brain_key_url = vsc_str_mutable_concat(url, k_brain_key_url_path);
}

//
//  Create request that generates seed using given blinded password.
//
VSSP_PUBLIC vssc_http_request_t *
vssp_pythia_client_make_request_generate_seed(const vssp_pythia_client_t *self, vsc_data_t blinded_password) {

    VSSP_ASSERT_PTR(self);
    VSSP_ASSERT(vsc_data_is_valid_and_non_empty(blinded_password));

    return vssp_pythia_client_make_request_generate_seed_with_id(self, blinded_password, vsc_str_empty());
}

//
//  Create request that generates seed using given blinded password and brainkey id.
//  Note, BrainKeyID can be empty.
//
VSSP_PUBLIC vssc_http_request_t *
vssp_pythia_client_make_request_generate_seed_with_id(
        const vssp_pythia_client_t *self, vsc_data_t blinded_password, vsc_str_t brain_key_id) {

    VSSP_ASSERT_PTR(self);
    VSSP_ASSERT(vsc_data_is_valid_and_non_empty(blinded_password));
    VSSP_ASSERT(vsc_str_is_valid(brain_key_id));

    vssc_json_object_t *json_obj = vssc_json_object_new();
    vssc_json_object_add_binary_value(json_obj, k_json_key_blinded_password, blinded_password);

    if (!vsc_str_is_empty(brain_key_id)) {
        vssc_json_object_add_string_value(json_obj, k_json_key_brainkey_id, brain_key_id);
    }

    vsc_data_t body = vsc_str_as_data(vssc_json_object_as_str(json_obj));

    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post, vsc_str_mutable_as_str(self->brain_key_url), body);

    vssc_json_object_destroy(&json_obj);

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    return http_request;
}

//
//  Map response to the correspond model.
//
VSSP_PUBLIC vssp_brain_key_seed_t *
vssp_pythia_client_process_response_generate_seed(const vssc_http_response_t *response, vssp_error_t *error) {

    VSSP_ASSERT_PTR(response);

    if (!vssc_http_response_is_success(response)) {
        VSSP_ERROR_SAFE_UPDATE(error, vssp_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        return NULL;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_http_response_body_is_json_object(response)) {
        VSSP_ERROR_SAFE_UPDATE(error, vssp_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_object_t *response_body = vssc_http_response_body_as_json_object(response);

    const size_t seed_len = vssc_json_object_get_binary_value_len(response_body, k_json_key_seed);
    if (0 == seed_len) {
        VSSP_ERROR_SAFE_UPDATE(error, vssp_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(seed_len);

    const vssc_status_t parse_status = vssc_json_object_get_binary_value(response_body, k_json_key_seed, seed);

    if (parse_status == vssc_status_SUCCESS) {
        return vssp_brain_key_seed_new_with_seed_disown(&seed);
    }

    vsc_buffer_destroy(&seed);

    VSSP_ERROR_SAFE_UPDATE(error, vssp_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
    return NULL;
}
