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
//  This class contains HTTP response information alongside with information
//  that is specific for Virgil services.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_virgil_http_response.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_virgil_http_response_defs.h"
#include "vssc_json_object.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_virgil_http_response_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_virgil_http_response_init_ctx(vssc_virgil_http_response_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_virgil_http_response_cleanup_ctx(vssc_virgil_http_response_t *self);

//
//  Perform initialization of pre-allocated context.
//  Creat fully defined object.
//
static void
vssc_virgil_http_response_init_with(vssc_virgil_http_response_t *self, size_t http_status_code,
        vssc_http_header_list_t **http_headers_ref, vssc_json_object_t **http_body_ref,
        vssc_json_array_t **http_array_body_ref);

//
//  Creat fully defined object.
//
static void
vssc_virgil_http_response_init_ctx_with(vssc_virgil_http_response_t *self, size_t http_status_code,
        vssc_http_header_list_t **http_headers_ref, vssc_json_object_t **http_body_ref,
        vssc_json_array_t **http_array_body_ref);

//
//  Allocate class context and perform it's initialization.
//  Creat fully defined object.
//
static vssc_virgil_http_response_t *
vssc_virgil_http_response_new_with(size_t http_status_code, vssc_http_header_list_t **http_headers_ref,
        vssc_json_object_t **http_body_ref, vssc_json_array_t **http_array_body_ref);

static const char k_json_key_service_error_code_chars[] = "code";

static const vsc_str_t k_json_key_service_error_code = {
    k_json_key_service_error_code_chars,
    sizeof(k_json_key_service_error_code_chars) - 1
};

static const char k_json_key_service_error_message_chars[] = "message";

static const vsc_str_t k_json_key_service_error_message = {
    k_json_key_service_error_message_chars,
    sizeof(k_json_key_service_error_message_chars) - 1
};

//
//  Return size of 'vssc_virgil_http_response_t'.
//
VSSC_PUBLIC size_t
vssc_virgil_http_response_ctx_size(void) {

    return sizeof(vssc_virgil_http_response_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_virgil_http_response_init(vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_virgil_http_response_t));

    self->refcnt = 1;

    vssc_virgil_http_response_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_virgil_http_response_cleanup(vssc_virgil_http_response_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_virgil_http_response_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_virgil_http_response_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_response_new(void) {

    vssc_virgil_http_response_t *self = (vssc_virgil_http_response_t *) vssc_alloc(sizeof (vssc_virgil_http_response_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_virgil_http_response_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Creat fully defined object.
//
static void
vssc_virgil_http_response_init_with(vssc_virgil_http_response_t *self, size_t http_status_code,
        vssc_http_header_list_t **http_headers_ref, vssc_json_object_t **http_body_ref,
        vssc_json_array_t **http_array_body_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_virgil_http_response_t));

    self->refcnt = 1;

    vssc_virgil_http_response_init_ctx_with(self, http_status_code, http_headers_ref, http_body_ref, http_array_body_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Creat fully defined object.
//
static vssc_virgil_http_response_t *
vssc_virgil_http_response_new_with(size_t http_status_code, vssc_http_header_list_t **http_headers_ref,
        vssc_json_object_t **http_body_ref, vssc_json_array_t **http_array_body_ref) {

    vssc_virgil_http_response_t *self = (vssc_virgil_http_response_t *) vssc_alloc(sizeof (vssc_virgil_http_response_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_virgil_http_response_init_with(self, http_status_code, http_headers_ref, http_body_ref, http_array_body_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_virgil_http_response_delete(const vssc_virgil_http_response_t *self) {

    vssc_virgil_http_response_t *local_self = (vssc_virgil_http_response_t *)self;

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

    vssc_virgil_http_response_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_virgil_http_response_new ()'.
//
VSSC_PUBLIC void
vssc_virgil_http_response_destroy(vssc_virgil_http_response_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_virgil_http_response_t *self = *self_ref;
    *self_ref = NULL;

    vssc_virgil_http_response_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_response_shallow_copy(vssc_virgil_http_response_t *self) {

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
VSSC_PUBLIC const vssc_virgil_http_response_t *
vssc_virgil_http_response_shallow_copy_const(const vssc_virgil_http_response_t *self) {

    return vssc_virgil_http_response_shallow_copy((vssc_virgil_http_response_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_virgil_http_response_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_virgil_http_response_init_ctx(vssc_virgil_http_response_t *self) {

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_virgil_http_response_cleanup_ctx(vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_json_object_destroy(&self->http_body);
    vssc_json_array_destroy(&self->http_array_body);
    vssc_http_header_list_destroy(&self->http_headers);
}

//
//  Creat fully defined object.
//
static void
vssc_virgil_http_response_init_ctx_with(vssc_virgil_http_response_t *self, size_t http_status_code,
        vssc_http_header_list_t **http_headers_ref, vssc_json_object_t **http_body_ref,
        vssc_json_array_t **http_array_body_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(http_headers_ref);
    VSSC_ASSERT(100 <= http_status_code && http_status_code <= 599);

    self->http_status_code = http_status_code;

    self->http_headers = *http_headers_ref;
    *http_headers_ref = NULL;

    if (http_body_ref) {
        self->http_body = *http_body_ref;
        *http_body_ref = NULL;
    }

    if (http_array_body_ref) {
        self->http_array_body = *http_array_body_ref;
        *http_array_body_ref = NULL;
    }
}

//
//  Create self from the parsed HTTP response.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_response_create_from_http_response(const vssc_http_response_t *http_response, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_response);

    const size_t http_status_code = vssc_http_response_status_code(http_response);
    if (100 > http_status_code || http_status_code > 599) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_STATUS_CODE_INVALID);
        return NULL;
    }

    const vssc_http_header_list_t *headers = vssc_http_response_headers(http_response);
    VSSC_ASSERT_PTR(headers);

    vssc_http_header_list_t *headers_copy = vssc_http_header_list_shallow_copy((vssc_http_header_list_t *)headers);

    // TODO: check that header content-type = application/json

    vsc_str_t http_body_str = vssc_http_response_body(http_response);
    if (vsc_str_is_empty(http_body_str)) {
        return vssc_virgil_http_response_new_with(http_status_code, &headers_copy, NULL, NULL);
    }

    vssc_json_object_t *http_body = vssc_json_object_parse(http_body_str, NULL);
    if (http_body) {
        return vssc_virgil_http_response_new_with(http_status_code, &headers_copy, &http_body, NULL);
    }

    vssc_json_array_t *http_array_body = vssc_json_array_parse(http_body_str, error);
    if (http_array_body) {
        return vssc_virgil_http_response_new_with(http_status_code, &headers_copy, NULL, &http_array_body);
    }

    vssc_http_header_list_destroy(&headers_copy);

    return NULL;
}

//
//  Return HTTP status code.
//
VSSC_PUBLIC size_t
vssc_virgil_http_response_status_code(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->http_status_code;
}

//
//  Return true if correspond HTTP request was succeed.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_is_success(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return vssc_http_response_is_status_code_success(self->http_status_code);
}

//
//  Return true if response handles a valid body as JSON object.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_body_is_json_object(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->http_body != NULL;
}

//
//  Return true if response handles a valid body as JSON array.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_body_is_json_array(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->http_array_body != NULL;
}

//
//  Return response body as JSON object.
//
VSSC_PUBLIC const vssc_json_object_t *
vssc_virgil_http_response_body_as_json_object(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->http_body);

    return self->http_body;
}

//
//  Return response body as JSON array.
//
VSSC_PUBLIC const vssc_json_array_t *
vssc_virgil_http_response_body_as_json_array(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->http_array_body);

    return self->http_array_body;
}

//
//  Return true if response handles a service error and it's description.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_has_service_error(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (vssc_virgil_http_response_is_success(self) || !vssc_virgil_http_response_body_is_json_object(self)) {
        return false;
    }

    vssc_error_t error;
    vssc_error_reset(&error);

    const int error_code = vssc_json_object_get_int_value(self->http_body, k_json_key_service_error_code, &error);
    VSSC_UNUSED(error_code);

    return !vssc_error_has_error(&error);
}

//
//  Return service error code.
//
VSSC_PUBLIC size_t
vssc_virgil_http_response_service_error_code(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (vssc_virgil_http_response_is_success(self) || !vssc_virgil_http_response_body_is_json_object(self)) {
        return 0;
    }

    vssc_error_t error;
    vssc_error_reset(&error);

    const int error_code = vssc_json_object_get_int_value(self->http_body, k_json_key_service_error_code, &error);

    if (!vssc_error_has_error(&error) && error_code > 0) {
        return (size_t)error_code;
    }

    return 0;
}

//
//  Return service error description.
//  Note, empty string can be returned.
//
VSSC_PUBLIC vsc_str_t
vssc_virgil_http_response_service_error_description(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (vssc_virgil_http_response_is_success(self) || !vssc_virgil_http_response_body_is_json_object(self)) {
        return vsc_str_empty();
    }

    return vssc_json_object_get_string_value(self->http_body, k_json_key_service_error_message, NULL);
}

//
//  Return HTTP headers.
//
VSSC_PUBLIC const vssc_http_header_list_t *
vssc_virgil_http_response_headers(const vssc_virgil_http_response_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->http_headers);

    return self->http_headers;
}

//
//  Find header by it's name.
//
VSSC_PUBLIC vsc_str_t
vssc_virgil_http_response_find_header(const vssc_virgil_http_response_t *self, vsc_str_t name, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->http_headers);

    return vssc_http_header_list_find(self->http_headers, name, error);
}
