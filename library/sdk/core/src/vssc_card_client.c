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
//  Helps to communicate with Virgil Card Service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_card_client.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_card_client_defs.h"
#include "vssc_json_object.h"
#include "vssc_json_object_private.h"
#include "vssc_json_array.h"
#include "vssc_raw_card_list_private.h"

#include <virgil/crypto/common/vsc_str_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_client_init_ctx(vssc_card_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_client_cleanup_ctx(vssc_card_client_t *self);

//
//  Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssc_card_client_init_ctx_with_base_url(vssc_card_client_t *self, vsc_str_t url);

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
//  POST|GET /card.
//
static const char k_url_path_card_chars[] = "/card/v5";

//
//  POST|GET /card.
//
static const vsc_str_t k_url_path_card = {
    k_url_path_card_chars,
    sizeof(k_url_path_card_chars) - 1
};

//
//  POST /actions/search.
//
static const char k_url_path_search_chars[] = "/card/v5/actions/search";

//
//  POST /actions/search.
//
static const vsc_str_t k_url_path_search = {
    k_url_path_search_chars,
    sizeof(k_url_path_search_chars) - 1
};

//
//  POST /actions/revoke.
//
static const char k_url_path_revoke_chars[] = "/card/v5/actions/revoke";

//
//  POST /actions/revoke.
//
static const vsc_str_t k_url_path_revoke = {
    k_url_path_revoke_chars,
    sizeof(k_url_path_revoke_chars) - 1
};

//
//  JSON KEY: identities.
//
static const char k_json_key_identities_chars[] = "identities";

//
//  JSON KEY: identities.
//
static const vsc_str_t k_json_key_identities = {
    k_json_key_identities_chars,
    sizeof(k_json_key_identities_chars) - 1
};

//
//  HTTP Header name: X-Virgil-Is-Superseeded
//
static const char k_header_name_x_virgil_is_superseeded_chars[] = "X-Virgil-Is-Superseeded";

//
//  HTTP Header name: X-Virgil-Is-Superseeded
//
static const vsc_str_t k_header_name_x_virgil_is_superseeded = {
    k_header_name_x_virgil_is_superseeded_chars,
    sizeof(k_header_name_x_virgil_is_superseeded_chars) - 1
};

//
//  Return size of 'vssc_card_client_t'.
//
VSSC_PUBLIC size_t
vssc_card_client_ctx_size(void) {

    return sizeof(vssc_card_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_client_init(vssc_card_client_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_client_t));

    self->refcnt = 1;

    vssc_card_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_client_cleanup(vssc_card_client_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_card_client_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_card_client_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_client_t *
vssc_card_client_new(void) {

    vssc_card_client_t *self = (vssc_card_client_t *) vssc_alloc(sizeof (vssc_card_client_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_client_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSC_PUBLIC void
vssc_card_client_init_with_base_url(vssc_card_client_t *self, vsc_str_t url) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_client_t));

    self->refcnt = 1;

    vssc_card_client_init_ctx_with_base_url(self, url);
}

//
//  Allocate class context and perform it's initialization.
//  Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSC_PUBLIC vssc_card_client_t *
vssc_card_client_new_with_base_url(vsc_str_t url) {

    vssc_card_client_t *self = (vssc_card_client_t *) vssc_alloc(sizeof (vssc_card_client_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_client_init_with_base_url(self, url);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_client_delete(const vssc_card_client_t *self) {

    vssc_card_client_t *local_self = (vssc_card_client_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssc_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssc_card_client_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_client_new ()'.
//
VSSC_PUBLIC void
vssc_card_client_destroy(vssc_card_client_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_card_client_t *self = *self_ref;
    *self_ref = NULL;

    vssc_card_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_client_t *
vssc_card_client_shallow_copy(vssc_card_client_t *self) {

    VSSC_ASSERT_PTR(self);

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_card_client_t *
vssc_card_client_shallow_copy_const(const vssc_card_client_t *self) {

    return vssc_card_client_shallow_copy((vssc_card_client_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_client_init_ctx(vssc_card_client_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_card_client_init_ctx_with_base_url(self, k_base_url);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_client_cleanup_ctx(vssc_card_client_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->base_url);
}

//
//  Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
static void
vssc_card_client_init_ctx_with_base_url(vssc_card_client_t *self, vsc_str_t url) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(url));

    self->base_url = vsc_str_mutable_from_str(url);
}

//
//  Create request that creates Virgil Card instance on the Virgil Cards Service.
//
//  Also makes the Card accessible for search/get queries from other users.
//  Note, "raw card" should contain appropriate signatures.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_publish_card(const vssc_card_client_t *self, const vssc_raw_card_t *raw_card) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(raw_card);

    vssc_json_object_t *json = vssc_raw_card_export_as_json(raw_card);
    vsc_str_t json_body = vssc_json_object_as_str(json);

    vsc_str_mutable_t card_url = vsc_str_mutable_concat(vsc_str_mutable_as_str(self->base_url), k_url_path_card);

    vssc_http_request_t *http_request =
            vssc_http_request_new_with_body(vssc_http_request_method_post, vsc_str_mutable_as_str(card_url), json_body);

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    vssc_json_object_destroy(&json);
    vsc_str_mutable_release(&card_url);

    return http_request;
}

//
//  Map response to the correspond model.
//  Return "raw card" of published Card.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_client_process_response_publish_card(const vssc_http_response_t *response, vssc_error_t *error) {

    VSSC_ASSERT_PTR(response);

    if (!vssc_http_response_is_success(response)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        return NULL;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_http_response_body_is_json_object(response)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_object_t *response_body = vssc_http_response_body_as_json_object(response);

    vssc_raw_card_t *result = vssc_raw_card_import_from_json(response_body, error);

    return result;
}

//
//  Create request that returns card from the Virgil Cards Service with given ID, if exists.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_get_card(const vssc_card_client_t *self, vsc_str_t card_id) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(card_id));

    const size_t url_len = self->base_url.len + k_url_path_card.len + 1 /* slash */ + card_id.len + 1 /* null */;
    vsc_str_buffer_t *url = vsc_str_buffer_new_with_capacity(url_len);

    vsc_str_buffer_write_str(url, vsc_str_mutable_as_str(self->base_url));
    vsc_str_buffer_write_str(url, k_url_path_card);
    vsc_str_buffer_write_char(url, '/');
    vsc_str_buffer_write_str(url, card_id);
    vsc_str_buffer_make_null_terminated(url);

    vssc_http_request_t *http_request =
            vssc_http_request_new_with_url(vssc_http_request_method_get, vsc_str_buffer_str(url));

    vsc_str_buffer_destroy(&url);

    return http_request;
}

//
//  Map response to the correspond model.
//  Return "raw card" if Card was found.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_client_process_response_get_card(const vssc_http_response_t *response, vssc_error_t *error) {

    VSSC_ASSERT_PTR(response);

    if (!vssc_http_response_is_success(response)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        return NULL;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_http_response_body_is_json_object(response)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_object_t *response_body = vssc_http_response_body_as_json_object(response);

    vssc_raw_card_t *raw_card = vssc_raw_card_import_from_json(response_body, error);
    if (NULL == raw_card) {
        return NULL;
    }

    //
    //  Check if Card is outdated
    //
    vsc_str_t is_outdated_str = vssc_http_response_find_header(response, k_header_name_x_virgil_is_superseeded, NULL);

    const bool is_outdated = vsc_str_equal(is_outdated_str, vsc_str("true", 4));
    vssc_raw_card_set_is_outdated(raw_card, is_outdated);

    return raw_card;
}

//
//  Create request that returns cards list from the Virgil Cards Service for given identity.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_search_cards_with_identity(const vssc_card_client_t *self, vsc_str_t identity) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));

    vssc_string_list_t *identities = vssc_string_list_new();
    vssc_string_list_add(identities, identity);

    vssc_http_request_t *http_request = vssc_card_client_make_request_search_cards_with_identities(self, identities);

    vssc_string_list_destroy(&identities);

    return http_request;
}

//
//  Create request that returns cards list from the Virgil Cards Service for given identities.
//
//  Note, current amount of identities to search in a single request is limited to 50 items.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_search_cards_with_identities(const vssc_card_client_t *self,
        const vssc_string_list_t *identities) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(identities);
    VSSC_ASSERT(vssc_string_list_has_item(identities));

    vsc_str_mutable_t search_url = vsc_str_mutable_concat(vsc_str_mutable_as_str(self->base_url), k_url_path_search);

    vssc_json_array_t *identities_json = vssc_json_array_new();
    vssc_json_array_add_string_values(identities_json, identities);

    vssc_json_object_t *json_body = vssc_json_object_new();
    vssc_json_object_add_array_value_disown(json_body, k_json_key_identities, &identities_json);

    vsc_str_t json_body_str = vssc_json_object_as_str(json_body);

    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post, vsc_str_mutable_as_str(search_url), json_body_str);

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    vsc_str_mutable_release(&search_url);
    vssc_json_object_destroy(&json_body);

    return http_request;
}

//
//  Map response to the correspond model.
//  Return "raw card list" if founded Cards.
//
VSSC_PUBLIC vssc_raw_card_list_t *
vssc_card_client_process_response_search_cards(const vssc_http_response_t *response, vssc_error_t *error) {

    VSSC_ASSERT_PTR(response);

    if (!vssc_http_response_is_success(response)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR);
        return NULL;
    }

    // TODO: Check Content-Type to be equal application/json

    if (!vssc_http_response_body_is_json_array(response)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_RESPONSE_BODY_PARSE_FAILED);
        return NULL;
    }

    const vssc_json_array_t *response_body = vssc_http_response_body_as_json_array(response);

    vssc_raw_card_list_t *raw_cards = vssc_raw_card_list_new();

    for (size_t pos = 0; pos < vssc_json_array_count(response_body); ++pos) {
        vssc_json_object_t *raw_card_json = vssc_json_array_get_object_value(response_body, pos, NULL);

        if (NULL == raw_card_json) {
            vssc_raw_card_list_destroy(&raw_cards);
            VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
            return NULL;
        }

        vssc_raw_card_t *raw_card = vssc_raw_card_import_from_json(raw_card_json, error);
        vssc_json_object_destroy(&raw_card_json);

        if (NULL == raw_card) {
            vssc_raw_card_list_destroy(&raw_cards);
            return NULL;
        }

        vssc_raw_card_list_add(raw_cards, &raw_card);
    }

    return raw_cards;
}

//
//  Revoke an active Virgil Card using its ID only.
//
//  Note, only HTTP status might be checked within a correspond response.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_revoke_card_with_id(const vssc_card_client_t *self, vsc_str_t card_id) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(card_id));

    vsc_str_t base_url = vsc_str_mutable_as_str(self->base_url);

    const size_t revoke_url_len = base_url.len + k_url_path_revoke.len + 1 /* slash */ + card_id.len + 1 /* null */;
    vsc_str_buffer_t *revoke_url = vsc_str_buffer_new_with_capacity(revoke_url_len);

    vsc_str_buffer_write_str(revoke_url, base_url);
    vsc_str_buffer_write_str(revoke_url, k_url_path_revoke);
    vsc_str_buffer_write_char(revoke_url, '/');
    vsc_str_buffer_write_str(revoke_url, card_id);
    vsc_str_buffer_make_null_terminated(revoke_url);

    vssc_http_request_t *http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post, vsc_str_buffer_str(revoke_url), vsc_str_empty());

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    vsc_str_buffer_destroy(&revoke_url);

    return http_request;
}
