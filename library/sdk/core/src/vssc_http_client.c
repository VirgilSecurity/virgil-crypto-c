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
//  HTTP client interface.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_client.h"
#include "vssc_http_client_api.h"
#include "vssc_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_send(vssc_impl_t *impl, const vssc_http_request_t *http_request, vssc_error_t *error) {

    const vssc_http_client_api_t *http_client_api = vssc_http_client_api(impl);
    VSSC_ASSERT_PTR (http_client_api);

    VSSC_ASSERT_PTR (http_client_api->send_cb);
    return http_client_api->send_cb (impl, http_request, error);
}

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_auth_send(vssc_impl_t *impl, const vssc_http_request_t *http_request, vsc_str_t auth_type,
        vsc_str_t auth_credentials, vssc_error_t *error) {

    const vssc_http_client_api_t *http_client_api = vssc_http_client_api(impl);
    VSSC_ASSERT_PTR (http_client_api);

    VSSC_ASSERT_PTR (http_client_api->auth_send_cb);
    return http_client_api->auth_send_cb (impl, http_request, auth_type, auth_credentials, error);
}

//
//  Return http client API, or NULL if it is not implemented.
//
VSSC_PUBLIC const vssc_http_client_api_t *
vssc_http_client_api(const vssc_impl_t *impl) {

    VSSC_ASSERT_PTR (impl);

    const vssc_api_t *api = vssc_impl_api(impl, vssc_api_tag_HTTP_CLIENT);
    return (const vssc_http_client_api_t *) api;
}

//
//  Check if given object implements interface 'http client'.
//
VSSC_PUBLIC bool
vssc_http_client_is_implemented(const vssc_impl_t *impl) {

    VSSC_ASSERT_PTR (impl);

    return vssc_impl_api(impl, vssc_api_tag_HTTP_CLIENT) != NULL;
}

//
//  Returns interface unique identifier.
//
VSSC_PUBLIC vssc_api_tag_t
vssc_http_client_api_tag(const vssc_http_client_api_t *http_client_api) {

    VSSC_ASSERT_PTR (http_client_api);

    return http_client_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
