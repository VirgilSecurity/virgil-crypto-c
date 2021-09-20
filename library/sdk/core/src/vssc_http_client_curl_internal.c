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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_client_curl_internal.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_http_client_curl_defs.h"
#include "vssc_http_client.h"
#include "vssc_http_client_api.h"
#include "vssc_impl.h"
#include "vssc_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vssc_api_t *
vssc_http_client_curl_find_api(vssc_api_tag_t api_tag);

//
//  Configuration of the interface API 'http client api'.
//
static const vssc_http_client_api_t http_client_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'http_client' MUST be equal to the 'vssc_api_tag_HTTP_CLIENT'.
    //
    vssc_api_tag_HTTP_CLIENT,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vssc_impl_tag_HTTP_CLIENT_CURL,
    //
    //  Send given request over HTTP.
    //
    (vssc_http_client_api_send_fn)vssc_http_client_curl_send
};

//
//  Compile-time known information about 'http client curl' implementation.
//
static const vssc_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vssc_impl_tag_HTTP_CLIENT_CURL,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vssc_http_client_curl_find_api,
    //
    //  Release acquired inner resources.
    //
    (vssc_impl_cleanup_fn)vssc_http_client_curl_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vssc_impl_delete_fn)vssc_http_client_curl_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSSC_PUBLIC void
vssc_http_client_curl_init(vssc_http_client_curl_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_client_curl_t));

    self->info = &info;
    self->refcnt = 1;

    vssc_http_client_curl_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vssc_http_client_curl_init()'.
//
VSSC_PUBLIC void
vssc_http_client_curl_cleanup(vssc_http_client_curl_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_http_client_curl_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_http_client_curl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSSC_PUBLIC vssc_http_client_curl_t *
vssc_http_client_curl_new(void) {

    vssc_http_client_curl_t *self = (vssc_http_client_curl_t *) vssc_alloc(sizeof (vssc_http_client_curl_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_http_client_curl_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vssc_http_client_curl_new()'.
//
VSSC_PUBLIC void
vssc_http_client_curl_delete(const vssc_http_client_curl_t *self) {

    vssc_http_client_curl_t *local_self = (vssc_http_client_curl_t *)self;

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

    vssc_http_client_curl_cleanup(local_self);

    vssc_dealloc(local_self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vssc_http_client_curl_new()'.
//  Given reference is nullified.
//
VSSC_PUBLIC void
vssc_http_client_curl_destroy(vssc_http_client_curl_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_http_client_curl_t *self = *self_ref;
    *self_ref = NULL;

    vssc_http_client_curl_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_client_curl_t *
vssc_http_client_curl_shallow_copy(vssc_http_client_curl_t *self) {

    // Proxy to the parent implementation.
    return (vssc_http_client_curl_t *)vssc_impl_shallow_copy((vssc_impl_t *)self);
}

//
//  Copy given implementation context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_http_client_curl_t *
vssc_http_client_curl_shallow_copy_const(const vssc_http_client_curl_t *self) {

    // Proxy to the parent implementation.
    return (vssc_http_client_curl_t *)vssc_impl_shallow_copy((vssc_impl_t *)self);
}

//
//  Perform initialization of pre-allocated context.
//  Use custom CA bundle.
//
VSSC_PUBLIC void
vssc_http_client_curl_init_with_ca(vssc_http_client_curl_t *self, vsc_str_t ca_bundle_path) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_http_client_curl_t));

    self->info = &info;
    self->refcnt = 1;

    vssc_http_client_curl_init_ctx_with_ca(self, ca_bundle_path);
}

//
//  Allocate implementation context and perform it's initialization.
//  Use custom CA bundle.
//
VSSC_PUBLIC vssc_http_client_curl_t *
vssc_http_client_curl_new_with_ca(vsc_str_t ca_bundle_path) {

    vssc_http_client_curl_t *self = vssc_http_client_curl_new();

    vssc_http_client_curl_init_with_ca(self, ca_bundle_path);

    return self;
}

//
//  Return size of 'vssc_http_client_curl_t' type.
//
VSSC_PUBLIC size_t
vssc_http_client_curl_impl_size(void) {

    return sizeof (vssc_http_client_curl_t);
}

//
//  Cast to the 'vssc_impl_t' type.
//
VSSC_PUBLIC vssc_impl_t *
vssc_http_client_curl_impl(vssc_http_client_curl_t *self) {

    VSSC_ASSERT_PTR(self);
    return (vssc_impl_t *)(self);
}

//
//  Cast to the const 'vssc_impl_t' type.
//
VSSC_PUBLIC const vssc_impl_t *
vssc_http_client_curl_impl_const(const vssc_http_client_curl_t *self) {

    VSSC_ASSERT_PTR(self);
    return (const vssc_impl_t *)(self);
}

static const vssc_api_t *
vssc_http_client_curl_find_api(vssc_api_tag_t api_tag) {

    switch(api_tag) {
        case vssc_api_tag_HTTP_CLIENT:
            return (const vssc_api_t *) &http_client_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
