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
//  Handles HTTP request in a most generic way.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_request.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_http_request_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_http_request_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_http_request_init_ctx(vssc_http_request_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_http_request_cleanup_ctx(vssc_http_request_t *self);

//
//  Create HTTP request with URL.
//
static void
vssc_http_request_init_ctx_with_url(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url);

//
//  Create HTTP request with URL and body.
//
static void
vssc_http_request_init_ctx_with_body(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url, vsc_str_t body);

//
//  HTTP method: GET
//
VSSC_PUBLIC const char vssc_http_request_method_get[] = "GET";

//
//  HTTP method: GET
//
VSSC_PUBLIC const vsc_str_t vssc_http_request_method_get_str = {
    vssc_http_request_method_get,
    sizeof(vssc_http_request_method_get) - 1
};

//
//  HTTP method: POST
//
VSSC_PUBLIC const char vssc_http_request_method_post[] = "POST";

//
//  HTTP method: POST
//
VSSC_PUBLIC const vsc_str_t vssc_http_request_method_post_str = {
    vssc_http_request_method_post,
    sizeof(vssc_http_request_method_post) - 1
};

//
//  HTTP method: PUT
//
VSSC_PUBLIC const char vssc_http_request_method_put[] = "PUT";

//
//  HTTP method: PUT
//
VSSC_PUBLIC const vsc_str_t vssc_http_request_method_put_str = {
    vssc_http_request_method_put,
    sizeof(vssc_http_request_method_put) - 1
};

//
//  HTTP method: DELETE
//
VSSC_PUBLIC const char vssc_http_request_method_delete[] = "DELETE";

//
//  HTTP method: DELETE
//
VSSC_PUBLIC const vsc_str_t vssc_http_request_method_delete_str = {
    vssc_http_request_method_delete,
    sizeof(vssc_http_request_method_delete) - 1
};

//
//  Return size of 'vssc_http_request_t'.
//
VSSC_PUBLIC size_t
vssc_http_request_ctx_size(void) {

    return sizeof(vssc_http_request_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_http_request_init(vssc_http_request_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_request_t));

    self->refcnt = 1;

    vssc_http_request_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_http_request_cleanup(vssc_http_request_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_http_request_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_http_request_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_new(void) {

    vssc_http_request_t *self = (vssc_http_request_t *) vssc_alloc(sizeof (vssc_http_request_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_request_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create HTTP request with URL.
//
VSSC_PUBLIC void
vssc_http_request_init_with_url(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_request_t));

    self->refcnt = 1;

    vssc_http_request_init_ctx_with_url(self, method, url);
}

//
//  Allocate class context and perform it's initialization.
//  Create HTTP request with URL.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_new_with_url(vsc_str_t method, vsc_str_t url) {

    vssc_http_request_t *self = (vssc_http_request_t *) vssc_alloc(sizeof (vssc_http_request_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_request_init_with_url(self, method, url);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create HTTP request with URL and body.
//
VSSC_PUBLIC void
vssc_http_request_init_with_body(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url, vsc_str_t body) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_request_t));

    self->refcnt = 1;

    vssc_http_request_init_ctx_with_body(self, method, url, body);
}

//
//  Allocate class context and perform it's initialization.
//  Create HTTP request with URL and body.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_new_with_body(vsc_str_t method, vsc_str_t url, vsc_str_t body) {

    vssc_http_request_t *self = (vssc_http_request_t *) vssc_alloc(sizeof (vssc_http_request_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_request_init_with_body(self, method, url, body);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_http_request_delete(vssc_http_request_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssc_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vssc_http_request_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_http_request_new ()'.
//
VSSC_PUBLIC void
vssc_http_request_destroy(vssc_http_request_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_http_request_t *self = *self_ref;
    *self_ref = NULL;

    vssc_http_request_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_shallow_copy(vssc_http_request_t *self) {

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


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_http_request_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_http_request_init_ctx(vssc_http_request_t *self) {

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_http_request_cleanup_ctx(vssc_http_request_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->method);
    vsc_str_mutable_release(&self->url);
    vsc_str_mutable_release(&self->body);

    vssc_http_header_list_destroy(&self->headers);
}

//
//  Create HTTP request with URL.
//
static void
vssc_http_request_init_ctx_with_url(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid(method));
    VSSC_ASSERT(!vsc_str_is_empty(method));
    VSSC_ASSERT(vsc_str_is_valid(url));
    VSSC_ASSERT(!vsc_str_is_empty(url));

    self->method = vsc_str_mutable_from_str(method);
    self->url = vsc_str_mutable_from_str(url);
    self->headers = vssc_http_header_list_new();
}

//
//  Create HTTP request with URL and body.
//
static void
vssc_http_request_init_ctx_with_body(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url, vsc_str_t body) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid(body));
    VSSC_ASSERT(!vsc_str_is_empty(body));

    vssc_http_request_init_ctx_with_url(self, method, url);

    self->body = vsc_str_mutable_from_str(body);
}

//
//  Add HTTP header.
//
VSSC_PUBLIC void
vssc_http_request_add_header(vssc_http_request_t *self, vsc_str_t name, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(name));
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(value));

    vssc_http_header_t *header = vssc_http_header_new_with(name, value);
    vssc_http_header_list_add(self->headers, &header);
}

//
//  Return HTTP method.
//
VSSC_PUBLIC vsc_str_t
vssc_http_request_method(const vssc_http_request_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->method);
}

//
//  Return HTTP url.
//
VSSC_PUBLIC vsc_str_t
vssc_http_request_url(const vssc_http_request_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->url);
}

//
//  Return HTTP body.
//
VSSC_PUBLIC vsc_str_t
vssc_http_request_body(const vssc_http_request_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->body);
}

//
//  Return HTTP headers.
//
VSSC_PUBLIC const vssc_http_header_list_t *
vssc_http_request_headers(const vssc_http_request_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->headers);

    return self->headers;
}
