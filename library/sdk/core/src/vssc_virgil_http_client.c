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
//  Virgil HTTP client.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_virgil_http_client.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_http_client.h"
#include "vssc_impl.h"

#if VSSC_VIRGIL_HTTP_CLIENT
#   include "vssc_http_client_curl.h"
#endif

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Create palatform dependent implementation of HTTP Client.
//
//  Note, "ca bundle path" is optional.
//
static vssc_impl_t *
vssc_virgil_http_client_create_http_client_impl(vsc_str_t ca_bundle_path);

//
//  Authorization type: Virgil
//
static const char k_header_authorization_type_chars[] = "Virgil";

//
//  Authorization type: Virgil
//
static const vsc_str_t k_header_authorization_type = {
    k_header_authorization_type_chars,
    sizeof(k_header_authorization_type_chars) - 1
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Send request over HTTP.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_client_send(const vssc_http_request_t *http_request, const vssc_jwt_t *jwt, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT_PTR(jwt);

    return vssc_virgil_http_client_send_with_ca(http_request, jwt, vsc_str_empty(), error);
}

//
//  Send request over HTTP with a path to Certificate Authority bundle.
//
//  Note, argument "ca bundle path" can be empty.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_client_send_with_ca(
        const vssc_http_request_t *http_request, const vssc_jwt_t *jwt, vsc_str_t ca_bundle_path, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT_PTR(jwt);
    VSSC_ASSERT(vsc_str_is_valid(ca_bundle_path));


    vssc_impl_t *http_client = vssc_virgil_http_client_create_http_client_impl(ca_bundle_path);
    VSSC_ASSERT_PTR(http_client);

    vssc_http_response_t *http_response = vssc_http_client_auth_send(
            http_client, http_request, k_header_authorization_type, vssc_jwt_as_string(jwt), error);

    vssc_virgil_http_response_t *virgil_http_response = NULL;

    if (NULL == http_response) {
        goto cleanup;
    }

    virgil_http_response = vssc_virgil_http_response_create_from_http_response(http_response, error);

cleanup:
    vssc_http_response_destroy(&http_response);
    vssc_impl_destroy(&http_client);

    return virgil_http_response;
}

//
//  Send custom request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_virgil_http_client_send_custom(const vssc_http_request_t *http_request, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);

    return vssc_virgil_http_client_send_custom_with_ca(http_request, vsc_str_empty(), error);
}

//
//  Send custom request over HTTP with a path to Certificate Authority bundle.
//
//  Note, argument ca_bundle can be empty.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_virgil_http_client_send_custom_with_ca(
        const vssc_http_request_t *http_request, vsc_str_t ca_bundle_path, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT(vsc_str_is_valid(ca_bundle_path));


    vssc_impl_t *http_client = vssc_virgil_http_client_create_http_client_impl(ca_bundle_path);
    VSSC_ASSERT_PTR(http_client);

    vssc_http_response_t *http_response = vssc_http_client_send(http_client, http_request, error);

    vssc_impl_destroy(&http_client);

    return http_response;
}

//
//  Create palatform dependent implementation of HTTP Client.
//
//  Note, "ca bundle path" is optional.
//
static vssc_impl_t *
vssc_virgil_http_client_create_http_client_impl(vsc_str_t ca_bundle_path) {

#if VSSC_VIRGIL_HTTP_CLIENT
    if (vsc_str_is_valid_and_non_empty(ca_bundle_path)) {
        return vssc_http_client_curl_impl(vssc_http_client_curl_new_with_ca(ca_bundle_path));
    } else {
        return vssc_http_client_curl_impl(vssc_http_client_curl_new());
    }
#endif

    VSSC_ASSERT(0 && "Default HTTP Client implementation is not defined.");

    return NULL;
}
