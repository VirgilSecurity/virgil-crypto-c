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
//  This module contains 'http client x' implementation.
// --------------------------------------------------------------------------

#ifndef VSSC_HTTP_CLIENT_X_H_INCLUDED
#define VSSC_HTTP_CLIENT_X_H_INCLUDED

#include "vssc_library.h"
#include "vssc_impl.h"
#include "vssc_http_request.h"
#include "vssc_error.h"
#include "vssc_http_response.h"

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
//  Handles implementation details.
//
#ifndef VSSC_HTTP_CLIENT_X_T_DEFINED
#define VSSC_HTTP_CLIENT_X_T_DEFINED
    typedef struct vssc_http_client_x_t vssc_http_client_x_t;
#endif // VSSC_HTTP_CLIENT_X_T_DEFINED

//
//  Return size of 'vssc_http_client_x_t' type.
//
VSSC_PUBLIC size_t
vssc_http_client_x_impl_size(void);

//
//  Cast to the 'vssc_impl_t' type.
//
VSSC_PUBLIC vssc_impl_t *
vssc_http_client_x_impl(vssc_http_client_x_t *self);

//
//  Cast to the const 'vssc_impl_t' type.
//
VSSC_PUBLIC const vssc_impl_t *
vssc_http_client_x_impl_const(const vssc_http_client_x_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSSC_PUBLIC void
vssc_http_client_x_init(vssc_http_client_x_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vssc_http_client_x_init()'.
//
VSSC_PUBLIC void
vssc_http_client_x_cleanup(vssc_http_client_x_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSSC_PUBLIC vssc_http_client_x_t *
vssc_http_client_x_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vssc_http_client_x_new()'.
//
VSSC_PUBLIC void
vssc_http_client_x_delete(const vssc_http_client_x_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vssc_http_client_x_new()'.
//  Given reference is nullified.
//
VSSC_PUBLIC void
vssc_http_client_x_destroy(vssc_http_client_x_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_client_x_t *
vssc_http_client_x_shallow_copy(vssc_http_client_x_t *self);

//
//  Copy given implementation context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_http_client_x_t *
vssc_http_client_x_shallow_copy_const(const vssc_http_client_x_t *self);

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_x_send(vssc_http_client_x_t *self, const vssc_http_request_t *http_request, vssc_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_HTTP_CLIENT_X_H_INCLUDED
//  @end
