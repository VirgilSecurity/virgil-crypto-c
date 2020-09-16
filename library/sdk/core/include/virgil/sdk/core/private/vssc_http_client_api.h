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
//  Interface 'http client' API.
// --------------------------------------------------------------------------

#ifndef VSSC_HTTP_CLIENT_API_H_INCLUDED
#define VSSC_HTTP_CLIENT_API_H_INCLUDED

#include "vssc_library.h"
#include "vssc_api.h"
#include "vssc_impl.h"
#include "vssc_http_request.h"
#include "vssc_error.h"
#include "vssc_http_response.h"

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
//  Callback. Send given request over HTTP.
//
typedef vssc_http_response_t * (*vssc_http_client_api_send_fn)(vssc_impl_t *impl,
        const vssc_http_request_t *http_request, vssc_error_t *error);

//
//  Callback. Send given request over HTTP.
//
typedef vssc_http_response_t * (*vssc_http_client_api_auth_send_fn)(vssc_impl_t *impl,
        const vssc_http_request_t *http_request, vsc_str_t auth_type, vsc_str_t auth_credentials, vssc_error_t *error);

//
//  Contains API requirements of the interface 'http client'.
//
struct vssc_http_client_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'http_client' MUST be equal to the 'vssc_api_tag_HTTP_CLIENT'.
    //
    vssc_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vssc_impl_tag_t impl_tag;
    //
    //  Send given request over HTTP.
    //
    vssc_http_client_api_send_fn send_cb;
    //
    //  Send given request over HTTP.
    //
    vssc_http_client_api_auth_send_fn auth_send_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_HTTP_CLIENT_API_H_INCLUDED
//  @end