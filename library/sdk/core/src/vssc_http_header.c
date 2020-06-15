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
//  Handles HTTP header in a most generic way.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_header.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_http_header_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_http_header_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_http_header_init_ctx(vssc_http_header_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_http_header_cleanup_ctx(vssc_http_header_t *self);

//
//  Create fully defined HTTP header.
//
//  Prerequisite: name is not empty.
//  Prerequisite: value is not empty.
//
static void
vssc_http_header_init_ctx_with(vssc_http_header_t *self, vsc_str_t name, vsc_str_t value);

//
//  Header name: Authorization
//
VSSC_PUBLIC const char vssc_http_header_name_authorization[] = "Authorization";

//
//  Header name: Authorization
//
VSSC_PUBLIC const vsc_str_t vssc_http_header_name_authorization_str = {
    vssc_http_header_name_authorization,
    sizeof(vssc_http_header_name_authorization) - 1
};

//
//  Header name: Content-Type
//
VSSC_PUBLIC const char vssc_http_header_name_content_type[] = "Content-Type";

//
//  Header name: Content-Type
//
VSSC_PUBLIC const vsc_str_t vssc_http_header_name_content_type_str = {
    vssc_http_header_name_content_type,
    sizeof(vssc_http_header_name_content_type) - 1
};

//
//  Header value: application/json
//
VSSC_PUBLIC const char vssc_http_header_value_application_json[] = "application/json";

//
//  Header value: application/json
//
VSSC_PUBLIC const vsc_str_t vssc_http_header_value_application_json_str = {
    vssc_http_header_value_application_json,
    sizeof(vssc_http_header_value_application_json) - 1
};

//
//  Return size of 'vssc_http_header_t'.
//
VSSC_PUBLIC size_t
vssc_http_header_ctx_size(void) {

    return sizeof(vssc_http_header_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_http_header_init(vssc_http_header_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_header_t));

    self->refcnt = 1;

    vssc_http_header_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_http_header_cleanup(vssc_http_header_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_http_header_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_http_header_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_http_header_t *
vssc_http_header_new(void) {

    vssc_http_header_t *self = (vssc_http_header_t *) vssc_alloc(sizeof (vssc_http_header_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_header_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined HTTP header.
//
//  Prerequisite: name is not empty.
//  Prerequisite: value is not empty.
//
VSSC_PUBLIC void
vssc_http_header_init_with(vssc_http_header_t *self, vsc_str_t name, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_header_t));

    self->refcnt = 1;

    vssc_http_header_init_ctx_with(self, name, value);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined HTTP header.
//
//  Prerequisite: name is not empty.
//  Prerequisite: value is not empty.
//
VSSC_PUBLIC vssc_http_header_t *
vssc_http_header_new_with(vsc_str_t name, vsc_str_t value) {

    vssc_http_header_t *self = (vssc_http_header_t *) vssc_alloc(sizeof (vssc_http_header_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_header_init_with(self, name, value);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_http_header_delete(const vssc_http_header_t *self) {

    vssc_http_header_t *local_self = (vssc_http_header_t *)self;

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

    vssc_http_header_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_http_header_new ()'.
//
VSSC_PUBLIC void
vssc_http_header_destroy(vssc_http_header_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_http_header_t *self = *self_ref;
    *self_ref = NULL;

    vssc_http_header_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_header_t *
vssc_http_header_shallow_copy(vssc_http_header_t *self) {

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
VSSC_PUBLIC const vssc_http_header_t *
vssc_http_header_shallow_copy_const(const vssc_http_header_t *self) {

    return vssc_http_header_shallow_copy((vssc_http_header_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_http_header_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_http_header_init_ctx(vssc_http_header_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_http_header_cleanup_ctx(vssc_http_header_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->name);
    vsc_str_mutable_release(&self->value);
}

//
//  Create fully defined HTTP header.
//
//  Prerequisite: name is not empty.
//  Prerequisite: value is not empty.
//
static void
vssc_http_header_init_ctx_with(vssc_http_header_t *self, vsc_str_t name, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(name));
    VSSC_ASSERT(vsc_str_is_valid(value));

    self->name = vsc_str_mutable_from_str(name);
    self->value = vsc_str_mutable_from_str(value);
}

//
//  Return HTTP header name.
//
VSSC_PUBLIC vsc_str_t
vssc_http_header_name(const vssc_http_header_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->name);
}

//
//  Return HTTP header value.
//
VSSC_PUBLIC vsc_str_t
vssc_http_header_value(const vssc_http_header_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->value);
}
