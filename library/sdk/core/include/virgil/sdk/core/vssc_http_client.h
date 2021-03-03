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
//  HTTP client interface.
// --------------------------------------------------------------------------

#ifndef VSSC_HTTP_CLIENT_H_INCLUDED
#define VSSC_HTTP_CLIENT_H_INCLUDED

#include "vssc_library.h"
#include "vssc_impl.h"
#include "vssc_http_request.h"
#include "vssc_error.h"
#include "vssc_http_response.h"
#include "vssc_api.h"

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
//  Contains API requirements of the interface 'http client'.
//
#ifndef VSSC_HTTP_CLIENT_API_T_DEFINED
#define VSSC_HTTP_CLIENT_API_T_DEFINED
    typedef struct vssc_http_client_api_t vssc_http_client_api_t;
#endif // VSSC_HTTP_CLIENT_API_T_DEFINED

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_send(vssc_impl_t *impl, const vssc_http_request_t *http_request, vssc_error_t *error);

//
//  Return http client API, or NULL if it is not implemented.
//
VSSC_PUBLIC const vssc_http_client_api_t *
vssc_http_client_api(const vssc_impl_t *impl);

//
//  Check if given object implements interface 'http client'.
//
VSSC_PUBLIC bool
vssc_http_client_is_implemented(const vssc_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSSC_PUBLIC vssc_api_tag_t
vssc_http_client_api_tag(const vssc_http_client_api_t *http_client_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_HTTP_CLIENT_H_INCLUDED
//  @end
