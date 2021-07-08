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
//  This module contains 'http client wasm' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_client_wasm.h"
#include "vssc_assert.h"
#include "vssc_memory.h"
#include "vssc_http_client_wasm_defs.h"
#include "vssc_http_client_wasm_internal.h"

#include <emscripten/fetch.h>
#include <virgil/crypto/common/vsc_str.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Copy given header name and value to an array:
//      {"key1", "value1", "key2", "value2", "key3", "value3", ..., 0 };
//
static void
vssc_http_client_wasm_copy_header(vsc_str_t header_name, vsc_str_t header_value, char **fetch_headers,
        size_t *fetch_headers_index);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Copy given header name and value to an array:
//      {"key1", "value1", "key2", "value2", "key3", "value3", ..., 0 };
//
static void
vssc_http_client_wasm_copy_header(
        vsc_str_t header_name, vsc_str_t header_value, char **fetch_headers, size_t *fetch_headers_index) {

    VSSC_ASSERT_PTR(fetch_headers);
    VSSC_ASSERT_PTR(fetch_headers_index);

    VSSC_ASSERT(NULL == fetch_headers[*fetch_headers_index + 0]);
    VSSC_ASSERT(NULL == fetch_headers[*fetch_headers_index + 1]);

    fetch_headers[*fetch_headers_index + 0] = vssc_alloc(header_name.len + 1);
    fetch_headers[*fetch_headers_index + 1] = vssc_alloc(header_value.len + 1);

    strncpy(fetch_headers[*fetch_headers_index + 0], header_name.chars, header_name.len);
    strncpy(fetch_headers[*fetch_headers_index + 1], header_value.chars, header_value.len);

    *fetch_headers_index += 2;
}

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_wasm_send(
        vssc_http_client_wasm_t *self, const vssc_http_request_t *http_request, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);

    //
    //  Set params.
    //
    emscripten_fetch_attr_t fetch_attr;
    emscripten_fetch_attr_init(&fetch_attr);
    fetch_attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY | EMSCRIPTEN_FETCH_SYNCHRONOUS;

    //
    //  Set HTTP method.
    //
    vsc_str_t http_method = vssc_http_request_method(http_request);
    strncpy(fetch_attr.requestMethod, http_method.chars, http_method.len);

    //
    //  Add headers.
    //
    const vssc_http_header_list_t *request_headers = vssc_http_request_headers(http_request);
    const size_t request_headers_count = vssc_http_header_list_count(request_headers) + 1 /*Authorization header*/;

    const size_t fetch_request_headers_size = 2 * request_headers_count + 1 /*null pointer termination*/;
    char **fetch_request_headers = vssc_alloc(sizeof(char *) * fetch_request_headers_size);
    size_t fetch_request_headers_index = 0;

    // Authorization
    vsc_str_t auth_header_value = vssc_http_request_auth_header_value(http_request);
    if (!vsc_str_is_empty(auth_header_value)) {
        vssc_http_client_wasm_copy_header(vssc_http_header_name_authorization, auth_header_value, fetch_request_headers,
                &fetch_request_headers_index);
        VSSC_ASSERT(fetch_request_headers_index < fetch_request_headers_size);
    }

    // Custom headers.
    for (const vssc_http_header_list_t *header_it = request_headers;
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        vssc_http_client_wasm_copy_header(
                header_name, header_value, fetch_request_headers, &fetch_request_headers_index);
        VSSC_ASSERT(fetch_request_headers_index < fetch_request_headers_size);
    }

    fetch_attr.requestHeaders = (const char *const *)fetch_request_headers;

    //
    //  Set body.
    //
    vsc_data_t body = vssc_http_request_body(http_request);
    if (!vsc_data_is_empty(body)) {
        fetch_attr.requestData = (const char *)body.bytes;
        fetch_attr.requestDataSize = body.len;
    }

    //
    //  Perform the request.
    //
    vsc_str_t url = vssc_http_request_url(http_request);
    VSSC_ASSERT(vsc_str_is_null_terminated(url));
    emscripten_fetch_t *fetch = emscripten_fetch(&fetch_attr, url.chars);

    vssc_http_response_t *response = vssc_http_response_new();
    if (NULL == fetch) {
        goto send_fail;
    }

    vssc_http_response_set_status(response, fetch->status);

    //
    //  Add response headers.
    //
    const size_t fetch_response_headers_length = emscripten_fetch_get_response_headers_length(fetch);
    if (0 == fetch_response_headers_length) {
        goto maybe_succ;
    }

    char *fetch_response_headers_str = vssc_alloc(fetch_response_headers_length + 1);
    emscripten_fetch_get_response_headers(fetch, fetch_response_headers_str, fetch_response_headers_length + 1);
    char **fetch_response_headers = emscripten_fetch_unpack_response_headers(fetch_response_headers_str);
    VSSC_ASSERT_ALLOC(fetch_response_headers);

    for (char **headers_it = fetch_response_headers; *headers_it != NULL; headers_it += 2) {
        vsc_str_t key = vsc_str_from_str(headers_it[0]);
        vsc_str_t value = vsc_str_from_str(headers_it[1]);
        vssc_http_response_add_header(response, key, value);
    }

    emscripten_fetch_free_unpacked_response_headers(fetch_response_headers);
    vssc_dealloc(fetch_response_headers_str);

send_fail:
    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_SEND_REQUEST_FAILED);
    vssc_http_response_destroy(&response);

maybe_succ:
    emscripten_fetch_close(fetch);

    for (char **headers_it = fetch_request_headers; *headers_it != NULL; ++headers_it) {
        vssc_dealloc(*headers_it);
        *headers_it = NULL;
    }
    vssc_dealloc(fetch_request_headers);

    return response;
}
