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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Handles HTTP request in a most generic way.
// --------------------------------------------------------------------------

#ifndef VSSC_HTTP_REQUEST_H_INCLUDED
#define VSSC_HTTP_REQUEST_H_INCLUDED

#include "vssc_library.h"
#include "vssc_http_header_list.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'http request' context.
//
#ifndef VSSC_HTTP_REQUEST_T_DEFINED
#define VSSC_HTTP_REQUEST_T_DEFINED
    typedef struct vssc_http_request_t vssc_http_request_t;
#endif // VSSC_HTTP_REQUEST_T_DEFINED

//
//  HTTP method: GET
//
VSSC_PUBLIC extern const char vssc_http_request_method_get[];

//
//  HTTP method: GET
//
VSSC_PUBLIC extern const vsc_str_t vssc_http_request_method_get_str;

//
//  HTTP method: POST
//
VSSC_PUBLIC extern const char vssc_http_request_method_post[];

//
//  HTTP method: POST
//
VSSC_PUBLIC extern const vsc_str_t vssc_http_request_method_post_str;

//
//  HTTP method: PUT
//
VSSC_PUBLIC extern const char vssc_http_request_method_put[];

//
//  HTTP method: PUT
//
VSSC_PUBLIC extern const vsc_str_t vssc_http_request_method_put_str;

//
//  HTTP method: DELETE
//
VSSC_PUBLIC extern const char vssc_http_request_method_delete[];

//
//  HTTP method: DELETE
//
VSSC_PUBLIC extern const vsc_str_t vssc_http_request_method_delete_str;

//
//  Return size of 'vssc_http_request_t'.
//
VSSC_PUBLIC size_t
vssc_http_request_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_http_request_init(vssc_http_request_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_http_request_cleanup(vssc_http_request_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create HTTP request with URL.
//
VSSC_PUBLIC void
vssc_http_request_init_with_url(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url);

//
//  Allocate class context and perform it's initialization.
//  Create HTTP request with URL.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_new_with_url(vsc_str_t method, vsc_str_t url);

//
//  Perform initialization of pre-allocated context.
//  Create HTTP request with URL and body.
//
VSSC_PUBLIC void
vssc_http_request_init_with_body(vssc_http_request_t *self, vsc_str_t method, vsc_str_t url, vsc_str_t body);

//
//  Allocate class context and perform it's initialization.
//  Create HTTP request with URL and body.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_new_with_body(vsc_str_t method, vsc_str_t url, vsc_str_t body);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_http_request_delete(const vssc_http_request_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_http_request_new ()'.
//
VSSC_PUBLIC void
vssc_http_request_destroy(vssc_http_request_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_http_request_shallow_copy(vssc_http_request_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_http_request_t *
vssc_http_request_shallow_copy_const(const vssc_http_request_t *self);

//
//  Add HTTP header.
//
VSSC_PUBLIC void
vssc_http_request_add_header(vssc_http_request_t *self, vsc_str_t name, vsc_str_t value);

//
//  Return HTTP method.
//
VSSC_PUBLIC vsc_str_t
vssc_http_request_method(const vssc_http_request_t *self);

//
//  Return HTTP url.
//
VSSC_PUBLIC vsc_str_t
vssc_http_request_url(const vssc_http_request_t *self);

//
//  Return HTTP body.
//
VSSC_PUBLIC vsc_str_t
vssc_http_request_body(const vssc_http_request_t *self);

//
//  Return HTTP headers.
//
VSSC_PUBLIC const vssc_http_header_list_t *
vssc_http_request_headers(const vssc_http_request_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_HTTP_REQUEST_H_INCLUDED
//  @end
