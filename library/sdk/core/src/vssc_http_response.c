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
//  This class contains HTTP response information alongside with information
//  that is specific for the Virgil services.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_response.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_http_response_internal.h"
#include "vssc_http_response_defs.h"
#include "vssc_json_object.h"

#include <virgil/crypto/common/vsc_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_http_response_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_http_response_init_ctx(vssc_http_response_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_http_response_cleanup_ctx(vssc_http_response_t *self);

//
//  Create response with a status only.
//
static void
vssc_http_response_init_ctx_with_status(vssc_http_response_t *self, size_t status_code);

//
//  Create response with a status and body.
//
static void
vssc_http_response_init_ctx_with_body(vssc_http_response_t *self, size_t status_code, vsc_data_t body);

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
//  Return size of 'vssc_http_response_t'.
//
VSSC_PUBLIC size_t
vssc_http_response_ctx_size(void) {

    return sizeof(vssc_http_response_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_http_response_init(vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_response_t));

    self->refcnt = 1;

    vssc_http_response_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_http_response_cleanup(vssc_http_response_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_http_response_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_http_response_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_new(void) {

    vssc_http_response_t *self = (vssc_http_response_t *) vssc_alloc(sizeof (vssc_http_response_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_response_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create response with a status only.
//
VSSC_PUBLIC void
vssc_http_response_init_with_status(vssc_http_response_t *self, size_t status_code) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_response_t));

    self->refcnt = 1;

    vssc_http_response_init_ctx_with_status(self, status_code);
}

//
//  Allocate class context and perform it's initialization.
//  Create response with a status only.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_new_with_status(size_t status_code) {

    vssc_http_response_t *self = (vssc_http_response_t *) vssc_alloc(sizeof (vssc_http_response_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_response_init_with_status(self, status_code);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create response with a status and body.
//
VSSC_PUBLIC void
vssc_http_response_init_with_body(vssc_http_response_t *self, size_t status_code, vsc_data_t body) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_response_t));

    self->refcnt = 1;

    vssc_http_response_init_ctx_with_body(self, status_code, body);
}

//
//  Allocate class context and perform it's initialization.
//  Create response with a status and body.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_new_with_body(size_t status_code, vsc_data_t body) {

    vssc_http_response_t *self = (vssc_http_response_t *) vssc_alloc(sizeof (vssc_http_response_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_response_init_with_body(self, status_code, body);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_http_response_delete(const vssc_http_response_t *self) {

    vssc_http_response_t *local_self = (vssc_http_response_t *)self;

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

    vssc_http_response_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_http_response_new ()'.
//
VSSC_PUBLIC void
vssc_http_response_destroy(vssc_http_response_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_http_response_t *self = *self_ref;
    *self_ref = NULL;

    vssc_http_response_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_shallow_copy(vssc_http_response_t *self) {

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
VSSC_PUBLIC const vssc_http_response_t *
vssc_http_response_shallow_copy_const(const vssc_http_response_t *self) {

    return vssc_http_response_shallow_copy((vssc_http_response_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_http_response_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_http_response_init_ctx(vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    self->headers = vssc_http_header_list_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_http_response_cleanup_ctx(vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->body);
    vssc_json_object_destroy(&self->body_json_object);
    vssc_json_array_destroy(&self->body_json_array);
    vssc_http_header_list_destroy(&self->headers);
}

//
//  Create response with a status only.
//
static void
vssc_http_response_init_ctx_with_status(vssc_http_response_t *self, size_t status_code) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(100 <= status_code && status_code <= 599);

    vssc_http_response_init_ctx(self);
    vssc_http_response_set_status(self, status_code);
}

//
//  Create response with a status and body.
//
static void
vssc_http_response_init_ctx_with_body(vssc_http_response_t *self, size_t status_code, vsc_data_t body) {

    VSSC_ASSERT_PTR(self);

    vssc_http_response_init_ctx_with_status(self, status_code);
    vssc_http_response_set_body(self, body);
}

//
//  Set HTTP status.
//
VSSC_PUBLIC void
vssc_http_response_set_status(vssc_http_response_t *self, size_t status_code) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(100 <= status_code && status_code <= 599);

    self->status_code = status_code;
}

//
//  Set HTTP body.
//
VSSC_PUBLIC void
vssc_http_response_set_body(vssc_http_response_t *self, vsc_data_t body) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_data_is_valid_and_non_empty(body));

    vsc_buffer_t *body_buffer = vsc_buffer_new_with_data(body);
    vssc_http_response_set_body_disown(self, &body_buffer);
}

//
//  Set HTTP body.
//
VSSC_PUBLIC void
vssc_http_response_set_body_disown(vssc_http_response_t *self, vsc_buffer_t **body_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(body_ref);
    VSSC_ASSERT(vsc_buffer_is_valid(*body_ref));

    self->body = *body_ref;
    *body_ref = NULL;

    vsc_str_t body = vsc_str_from_data(vsc_buffer_data(self->body));

    if (!vsc_str_is_empty(body)) {
        self->body_json_object = vssc_json_object_parse(body, NULL);

        if (NULL == self->body_json_object) {
            self->body_json_array = vssc_json_array_parse(body, NULL);
        }
    }
}

//
//  Add HTTP header.
//
VSSC_PUBLIC void
vssc_http_response_add_header(vssc_http_response_t *self, vsc_str_t name, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(name));
    VSSC_ASSERT(vsc_str_is_valid(value));

    vssc_http_header_t *header = vssc_http_header_new_with(name, value);
    vssc_http_header_list_add(self->headers, &header);
}

//
//  Return true if underlying status code is in range [200..299].
//
VSSC_PUBLIC bool
vssc_http_response_is_success(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return vssc_http_response_is_status_code_success(self->status_code);
}

//
//  Return HTTP status code.
//
VSSC_PUBLIC size_t
vssc_http_response_status_code(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->status_code;
}

//
//  Return HTTP body.
//
VSSC_PUBLIC vsc_data_t
vssc_http_response_body(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (NULL == self->body) {
        return vsc_data_empty();
    } else {
        return vsc_buffer_data(self->body);
    }
}

//
//  Return HTTP headers.
//
VSSC_PUBLIC const vssc_http_header_list_t *
vssc_http_response_headers(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->headers);

    return self->headers;
}

//
//  Find header by it's name.
//
VSSC_PUBLIC vsc_str_t
vssc_http_response_find_header(const vssc_http_response_t *self, vsc_str_t name, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->headers);

    return vssc_http_header_list_find(self->headers, name, error);
}

//
//  Return true if response handles a valid body as JSON object.
//
VSSC_PUBLIC bool
vssc_http_response_body_is_json_object(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->body_json_object != NULL;
}

//
//  Return true if response handles a valid body as JSON array.
//
VSSC_PUBLIC bool
vssc_http_response_body_is_json_array(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->body_json_array != NULL;
}

//
//  Return response body as JSON object.
//
VSSC_PUBLIC const vssc_json_object_t *
vssc_http_response_body_as_json_object(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->body_json_object);

    return self->body_json_object;
}

//
//  Return response body as JSON array.
//
VSSC_PUBLIC const vssc_json_array_t *
vssc_http_response_body_as_json_array(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->body_json_array);

    return self->body_json_array;
}

//
//  Return true if response handles a service error and it's description.
//
VSSC_PUBLIC bool
vssc_http_response_has_service_error(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (vssc_http_response_is_success(self) || !vssc_http_response_body_is_json_object(self)) {
        return false;
    }

    vssc_error_t error;
    vssc_error_reset(&error);

    const int error_code =
            vssc_json_object_get_int_value(self->body_json_object, k_json_key_service_error_code, &error);
    VSSC_UNUSED(error_code);

    return !vssc_error_has_error(&error);
}

//
//  Return service error code.
//
VSSC_PUBLIC size_t
vssc_http_response_service_error_code(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (vssc_http_response_is_success(self) || !vssc_http_response_body_is_json_object(self)) {
        return 0;
    }

    vssc_error_t error;
    vssc_error_reset(&error);

    const int error_code =
            vssc_json_object_get_int_value(self->body_json_object, k_json_key_service_error_code, &error);

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
vssc_http_response_service_error_description(const vssc_http_response_t *self) {

    VSSC_ASSERT_PTR(self);

    if (vssc_http_response_is_success(self) || !vssc_http_response_body_is_json_object(self)) {
        return vsc_str_empty();
    }

    return vssc_json_object_get_string_value(self->body_json_object, k_json_key_service_error_message, NULL);
}

//
//  Check status code range [200..299].
//
VSSC_PUBLIC bool
vssc_http_response_is_status_code_success(size_t http_status_code) {

    return 200 <= http_status_code && http_status_code <= 299;
}
