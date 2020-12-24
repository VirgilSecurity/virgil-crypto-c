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
//  TODO: Add "virgil-agent" header.
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

#if VSSC_HTTP_CLIENT_CURL
#   include "vssc_http_client_curl.h"
#endif

#if VSSC_HTTP_CLIENT_X
#   include "vssc_http_client_x.h"
#endif

#if VSSC_VIRGIL_HTTP_CLIENT_DEBUG
#   include <stdio.h>
#endif

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Create platform dependent implementation of HTTP Client.
//
//  Note, "ca bundle path" is optional.
//
static vssc_impl_t *
vssc_virgil_http_client_create_http_client_impl(vsc_str_t ca_bundle_path);

//
//  Print HTTP request.
//  Note, available only if VSSC_VIRGIL_HTTP_CLIENT_DEBUG option is ON.
//
static void
vssc_virgil_http_client_debug_print_request(const vssc_http_request_t *http_request);

//
//  Print HTTP response.
//  Note, available only if VSSC_VIRGIL_HTTP_CLIENT_DEBUG option is ON.
//
static void
vssc_virgil_http_client_debug_print_response(const vssc_http_response_t *http_response);

//
//  Authorization type: Virgil
//
VSSC_PUBLIC const char vssc_virgil_http_client_k_auth_type_virgil_chars[] = "Virgil";

//
//  Authorization type: Virgil
//
VSSC_PUBLIC const vsc_str_t vssc_virgil_http_client_k_auth_type_virgil = {
    vssc_virgil_http_client_k_auth_type_virgil_chars,
    sizeof(vssc_virgil_http_client_k_auth_type_virgil_chars) - 1
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Send request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_virgil_http_client_send(const vssc_http_request_t *http_request, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);

    return vssc_virgil_http_client_send_with_ca(http_request, vsc_str_empty(), error);
}

//
//  Send request over HTTP with a path to Certificate Authority bundle.
//
//  Note, argument "ca bundle path" can be empty.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_virgil_http_client_send_with_ca(
        const vssc_http_request_t *http_request, vsc_str_t ca_bundle_path, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT(vsc_str_is_valid(ca_bundle_path));

    vssc_virgil_http_client_debug_print_request(http_request);

    vssc_impl_t *http_client = vssc_virgil_http_client_create_http_client_impl(ca_bundle_path);
    VSSC_ASSERT_PTR(http_client);

    vssc_http_response_t *http_response = vssc_http_client_send(http_client, http_request, error);

    if (http_response) {
        vssc_virgil_http_client_debug_print_response(http_response);
    }

    vssc_impl_destroy(&http_client);

    return http_response;
}

//
//  Create platform dependent implementation of HTTP Client.
//
//  Note, "ca bundle path" is optional.
//
static vssc_impl_t *
vssc_virgil_http_client_create_http_client_impl(vsc_str_t ca_bundle_path) {

#if VSSC_HTTP_CLIENT_X
    VSSC_UNUSED(ca_bundle_path);
    return vssc_http_client_x_impl(vssc_http_client_x_new());
#endif

#if VSSC_HTTP_CLIENT_CURL
    if (vsc_str_is_valid_and_non_empty(ca_bundle_path)) {
        return vssc_http_client_curl_impl(vssc_http_client_curl_new_with_ca(ca_bundle_path));
    } else {
        return vssc_http_client_curl_impl(vssc_http_client_curl_new());
    }
#endif

    VSSC_ASSERT(0 && "Default HTTP Client implementation is not defined.");

    return NULL;
}

//
//  Print HTTP request.
//  Note, available only if VSSC_VIRGIL_HTTP_CLIENT_DEBUG option is ON.
//
static void
vssc_virgil_http_client_debug_print_request(const vssc_http_request_t *http_request) {

#if VSSC_VIRGIL_HTTP_CLIENT_DEBUG
    printf("\n---------------------\n");
    printf("Sending HTTP request:\n");
    printf(" METHOD: %s\n", vssc_http_request_method(http_request).chars);
    printf(" URL: %s\n", vssc_http_request_url(http_request).chars);
    printf(" BODY: %s\n", vssc_http_request_body(http_request).chars);


    vsc_str_t auth_header_value = vssc_http_request_auth_header_value(http_request);
    if (!vsc_str_is_empty(auth_header_value)) {
        printf(" HEADER: Authorization: %s\n", auth_header_value.chars);
    }

    for (const vssc_http_header_list_t *header_it = vssc_http_request_headers(http_request);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        printf(" HEADER: %s: %s\n", header_name.chars, header_value.chars);
    }
#else
    VSSC_UNUSED(http_request);
#endif // VSSC_VIRGIL_HTTP_CLIENT_DEBUG
}

//
//  Print HTTP response.
//  Note, available only if VSSC_VIRGIL_HTTP_CLIENT_DEBUG option is ON.
//
static void
vssc_virgil_http_client_debug_print_response(const vssc_http_response_t *http_response) {

#if VSSC_VIRGIL_HTTP_CLIENT_DEBUG
    if (NULL == http_response) {
        return;
    }

    printf("\n---------------------\n");
    printf("Got HTTP response:\n");
    printf(" STATUS: %zu\n", vssc_http_response_status_code(http_response));
    printf(" BODY: %s\n", vssc_http_response_body(http_response).chars);

    for (const vssc_http_header_list_t *header_it = vssc_http_response_headers(http_response);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        printf(" HEADER: %s: %s\n", header_name.chars, header_value.chars);
    }
#else
    VSSC_UNUSED(http_response);
#endif // VSSC_VIRGIL_HTTP_CLIENT_DEBUG
}
