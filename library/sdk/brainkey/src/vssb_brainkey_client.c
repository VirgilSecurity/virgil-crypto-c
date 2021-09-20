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
//  Helps to communicate with Virgil Brainkey Service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssb_brainkey_client.h"
#include "vssb_memory.h"
#include "vssb_assert.h"
#include "vssb_brainkey_client_defs.h"
#include "vssb_brainkey_hardened_point_private.h"
#include "vssb_status.h"

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
//  Note, this method is called automatically when method vssb_brainkey_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssb_brainkey_client_init_ctx(vssb_brainkey_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssb_brainkey_client_cleanup_ctx(vssb_brainkey_client_t *self);

//
//  Create Brainkey Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssb_brainkey_client_init_ctx_with_base_url(vssb_brainkey_client_t *self, vsc_str_t url);

//
//  Map service response status to the SDK status.
//
static vssb_status_t
vssb_brainkey_client_map_service_status(const vssc_http_response_t *response) VSSB_NODISCARD;

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
//  POST /brainkey/v2/harden
//
static const char k_brainkey_url_path_chars[] = "/brainkey/v2/harden";

//
//  POST /brainkey/v2/harden
//
static const vsc_str_t k_brainkey_url_path = {
    k_brainkey_url_path_chars,
    sizeof(k_brainkey_url_path_chars) - 1
};

//
//  JSON key: blinded_point
//
static const char k_json_key_blinded_point_chars[] = "blinded_point";

//
//  JSON key: blinded_point
//
static const vsc_str_t k_json_key_blinded_point = {
    k_json_key_blinded_point_chars,
    sizeof(k_json_key_blinded_point_chars) - 1
};

//
//  JSON key: hardened_point
//
static const char k_json_key_hardened_point_chars[] = "hardened_point";

//
//  JSON key: hardened_point
//
static const vsc_str_t k_json_key_hardened_point = {
    k_json_key_hardened_point_chars,
    sizeof(k_json_key_hardened_point_chars) - 1
};

//
//  Return size of 'vssb_brainkey_client_t'.
//
VSSB_PUBLIC size_t
vssb_brainkey_client_ctx_size(void) {

    return sizeof(vssb_brainkey_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSB_PUBLIC void
vssb_brainkey_client_init(vssb_brainkey_client_t *self) {

    VSSB_ASSERT_PTR(self);

    vssb_zeroize(self, sizeof(vssb_brainkey_client_t));

    self->refcnt = 1;

    vssb_brainkey_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSB_PUBLIC void
vssb_brainkey_client_cleanup(vssb_brainkey_client_t *self) {

    if (self == NULL) {
        return;
    }

    vssb_brainkey_client_cleanup_ctx(self);

    vssb_zeroize(self, sizeof(vssb_brainkey_client_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSB_PUBLIC vssb_brainkey_client_t *
vssb_brainkey_client_new(void) {

    vssb_brainkey_client_t *self = (vssb_brainkey_client_t *) vssb_alloc(sizeof (vssb_brainkey_client_t));
    VSSB_ASSERT_ALLOC(self);

    vssb_brainkey_client_init(self);

    self->self_dealloc_cb = vssb_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Brainkey Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSB_PUBLIC void
vssb_brainkey_client_init_with_base_url(vssb_brainkey_client_t *self, vsc_str_t url) {

    VSSB_ASSERT_PTR(self);

    vssb_zeroize(self, sizeof(vssb_brainkey_client_t));

    self->refcnt = 1;

    vssb_brainkey_client_init_ctx_with_base_url(self, url);
}

//
//  Allocate class context and perform it's initialization.
//  Create Brainkey Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSB_PUBLIC vssb_brainkey_client_t *
vssb_brainkey_client_new_with_base_url(vsc_str_t url) {

    vssb_brainkey_client_t *self = (vssb_brainkey_client_t *) vssb_alloc(sizeof (vssb_brainkey_client_t));
    VSSB_ASSERT_ALLOC(self);

    vssb_brainkey_client_init_with_base_url(self, url);

    self->self_dealloc_cb = vssb_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSB_PUBLIC void
vssb_brainkey_client_delete(const vssb_brainkey_client_t *self) {

    vssb_brainkey_client_t *local_self = (vssb_brainkey_client_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSB_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSB_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssb_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssb_brainkey_client_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssb_brainkey_client_new ()'.
//
VSSB_PUBLIC void
vssb_brainkey_client_destroy(vssb_brainkey_client_t **self_ref) {

    VSSB_ASSERT_PTR(self_ref);

    vssb_brainkey_client_t *self = *self_ref;
    *self_ref = NULL;

    vssb_brainkey_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSB_PUBLIC vssb_brainkey_client_t *
vssb_brainkey_client_shallow_copy(vssb_brainkey_client_t *self) {

    VSSB_ASSERT_PTR(self);

    #if defined(VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSB_PUBLIC const vssb_brainkey_client_t *
vssb_brainkey_client_shallow_copy_const(const vssb_brainkey_client_t *self) {

    return vssb_brainkey_client_shallow_copy((vssb_brainkey_client_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssb_brainkey_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssb_brainkey_client_init_ctx(vssb_brainkey_client_t *self) {

    VSSB_ASSERT_PTR(self);

    vssb_brainkey_client_init_ctx_with_base_url(self, k_base_url);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssb_brainkey_client_cleanup_ctx(vssb_brainkey_client_t *self) {

    VSSB_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->brainkey_url);
}

//
//  Create Brainkey Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssb_brainkey_client_init_ctx_with_base_url(vssb_brainkey_client_t *self, vsc_str_t url) {

    VSSB_ASSERT_PTR(self);
    VSSB_ASSERT(vsc_str_is_valid_and_non_empty(url));

    self->brainkey_url = vsc_str_mutable_concat(url, k_brainkey_url_path);
}

//
//  Create request that makes a hardened point from a blinded point.
//
VSSB_PUBLIC vssc_http_request_t *
vssb_brainkey_client_make_request_harden_point(const vssb_brainkey_client_t *self, vsc_data_t blinded_point) {

    VSSB_ASSERT_PTR(self);
    VSSB_ASSERT(vsc_data_is_valid_and_non_empty(blinded_point));

    vssc_json_object_t *json_obj = vssc_json_object_new();
    vssc_json_object_add_binary_value(json_obj, k_json_key_blinded_point, blinded_point);

    vsc_data_t body = vsc_str_as_data(vssc_json_object_as_str(json_obj));

    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post, vsc_str_mutable_as_str(self->brainkey_url), body);

    vssc_json_object_destroy(&json_obj);

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    return http_request;
}

//
//  Map response to the correspond model.
//
VSSB_PUBLIC vssb_brainkey_hardened_point_t *
vssb_brainkey_client_process_response_harden_point(const vssc_http_response_t *response, vssb_error_t *error) {

    VSSB_ASSERT_PTR(response);

    if (!vssc_http_response_is_success(response)) {
        vssb_status_t service_status = vssb_brainkey_client_map_service_status(response);
        VSSB_ERROR_SAFE_UPDATE(error, service_status);
        return NULL;
    }


    if (!vssc_http_response_body_is_json_object(response)) {
        VSSB_ERROR_SAFE_UPDATE(error, vssb_status_HTTP_RESPONSE_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_object_t *response_body = vssc_http_response_body_as_json_object(response);

    const size_t hardened_point_len = vssc_json_object_get_binary_value_len(response_body, k_json_key_hardened_point);
    if (0 == hardened_point_len) {
        VSSB_ERROR_SAFE_UPDATE(error, vssb_status_HTTP_RESPONSE_PARSE_FAILED);
        return NULL;
    }

    vsc_buffer_t *hardened_point = vsc_buffer_new_with_capacity(hardened_point_len);

    const vssc_status_t parse_status =
            vssc_json_object_get_binary_value(response_body, k_json_key_hardened_point, hardened_point);

    if (parse_status == vssc_status_SUCCESS) {
        return vssb_brainkey_hardened_point_new_with_value_disown(&hardened_point);
    }

    vsc_buffer_destroy(&hardened_point);

    VSSB_ERROR_SAFE_UPDATE(error, vssb_status_HTTP_RESPONSE_PARSE_FAILED);
    return NULL;
}

//
//  Map service response status to the SDK status.
//
static vssb_status_t
vssb_brainkey_client_map_service_status(const vssc_http_response_t *response) {

    VSSB_ASSERT_PTR(response);

    if (vssc_http_response_is_success(response)) {
        return vssb_status_SUCCESS;
    }

    if (vssc_http_response_has_service_error(response)) {
        const size_t service_error_code = vssc_http_response_service_error_code(response);
        switch (service_error_code) {
        case 1000:
            return vssb_status_HTTP_SERVICE_ERROR_SERVER_INTERNAL_ERROR;

        case 1001:
            return vssb_status_HTTP_SERVICE_ERROR_BAD_BLINDED_POINT_DATA;

        case 1002:
            return vssb_status_HTTP_SERVICE_ERROR_INVALID_JSON;

        default:
            return vssb_status_HTTP_SERVICE_ERROR_UNDEFINED;
        };
    }

    return vssb_status_HTTP_RESPONSE_ERROR;
}
