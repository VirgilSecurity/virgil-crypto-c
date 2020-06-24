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
#include "vssc_http_response_defs.h"

#include <curl/curl.h>
#include <ctype.h>
#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>
#include <virgil/crypto/common/vsc_str_mutable.h>
#include <virgil/crypto/common/vsc_str_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Concatenate header name and header value as "NAME: VALUE".
//  Note, given buffer is reset first and then strings are appended.
//  Note, written string is null-terminated.
//
static void
vssc_virgil_http_client_format_header(vsc_str_t name, vsc_str_t value, vsc_str_buffer_t *out_str);

//
//  Make authorization header as "Authorization: TYPE CREDENTIALS".
//  Note, given buffer is reset first and then strings are appended.
//  Note, written string is null-terminated.
//
static void
vssc_virgil_http_client_format_authorization_header(vsc_str_t type, vsc_str_t credentials, vsc_str_buffer_t *out_str);

//
//  Callback for CURL body writing fucntion.
//
static size_t
vssc_virgil_http_client_write_recevied_data(void *ptr, size_t size, size_t nmemb, vssc_http_response_t *http_response);

//
//  Callback for CURL header writing fucntion.
//
static size_t
vssc_virgil_http_client_write_recevied_header(char *ptr, size_t size, size_t nmemb,
        vssc_http_response_t *http_response);

//
//  Separator between header name and header value.
//
static const char k_header_name_value_separator[] = ": ";

//
//  Separator between header name and header value.
//
static const vsc_str_t k_header_name_value_separator_str = {
    k_header_name_value_separator,
    sizeof(k_header_name_value_separator) - 1
};

//
//  Authorization type: Virgil
//
static const char k_header_authorization_type[] = "Virgil";

//
//  Authorization type: Virgil
//
static const vsc_str_t k_header_authorization_type_str = {
    k_header_authorization_type,
    sizeof(k_header_authorization_type) - 1
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
//  Note, argument ca_bundle can be empty.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_client_send_with_ca(
        const vssc_http_request_t *http_request, const vssc_jwt_t *jwt, vsc_str_t ca_bundle, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT_PTR(jwt);
    VSSC_ASSERT(vsc_str_is_valid(ca_bundle));

    //
    //  Set URL and method.
    //
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, vssc_http_request_url(http_request).chars);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, vssc_http_request_method(http_request).chars);

    if (!vsc_str_is_empty(ca_bundle)) {
        vsc_str_mutable_t ca_null_terminates = vsc_str_mutable_from_str(ca_bundle);
        curl_easy_setopt(curl, CURLOPT_CAINFO, vsc_str_mutable_as_str(ca_null_terminates));
        vsc_str_mutable_release(&ca_null_terminates);
    }

    //
    //  Add headers.
    //
    vsc_str_buffer_t *header_buf = vsc_str_buffer_new_with_capacity(512);
    struct curl_slist *headers = NULL;

    // Authorization
    vssc_virgil_http_client_format_authorization_header(
            k_header_authorization_type_str, vssc_jwt_as_string(jwt), header_buf);

    headers = curl_slist_append(headers, vsc_str_buffer_str(header_buf).chars);
    VSSC_ASSERT_ALLOC(headers);

    // Custom headers.
    for (const vssc_http_header_list_t *header_it = vssc_http_request_headers(http_request);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        vssc_virgil_http_client_format_header(header_name, header_value, header_buf);
        headers = curl_slist_append(headers, vsc_str_buffer_str(header_buf).chars);
        VSSC_ASSERT_ALLOC(headers);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    vsc_str_buffer_destroy(&header_buf);

    //
    //  Set body.
    //
    vsc_str_t body = vssc_http_request_body(http_request);
    if (!vsc_str_is_empty(body)) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.chars);
    }
    //
    //  Set callbacks to build response.
    //
    vssc_http_response_t *response = vssc_http_response_new();
    vssc_virgil_http_response_t *virgil_http_response = NULL;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vssc_virgil_http_client_write_recevied_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, vssc_virgil_http_client_write_recevied_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);

    //
    //  Perform the request.
    //
    const CURLcode send_status = curl_easy_perform(curl);
    if (send_status != CURLE_OK) {
        goto send_fail;
    }

    //
    //  Parse response.
    //
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    response->status_code = response_code;

    virgil_http_response = vssc_virgil_http_response_create_from_http_response(response, error);

    goto maybe_succ;

send_fail:
    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_SEND_REQUEST_FAILED);

maybe_succ:
    vssc_http_response_destroy(&response);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

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
        const vssc_http_request_t *http_request, vsc_str_t ca_bundle, vssc_error_t *error) {

    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT(vsc_str_is_valid(ca_bundle));

    //
    //  Set URL and method.
    //
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, vssc_http_request_url(http_request).chars);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, vssc_http_request_method(http_request).chars);

    if (!vsc_str_is_empty(ca_bundle)) {
        vsc_str_mutable_t ca_null_terminates = vsc_str_mutable_from_str(ca_bundle);
        curl_easy_setopt(curl, CURLOPT_CAINFO, vsc_str_mutable_as_str(ca_null_terminates));
        vsc_str_mutable_release(&ca_null_terminates);
    }

    //
    //  Add headers.
    //
    vsc_str_buffer_t *header_buf = vsc_str_buffer_new_with_capacity(512);
    struct curl_slist *headers = NULL;

    // Custom headers.
    for (const vssc_http_header_list_t *header_it = vssc_http_request_headers(http_request);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        vssc_virgil_http_client_format_header(header_name, header_value, header_buf);
        headers = curl_slist_append(headers, vsc_str_buffer_str(header_buf).chars);
        VSSC_ASSERT_ALLOC(headers);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    vsc_str_buffer_destroy(&header_buf);

    //
    //  Set body.
    //
    vsc_str_t body = vssc_http_request_body(http_request);
    if (!vsc_str_is_empty(body)) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.chars);
    }
    //
    //  Set callbacks to build response.
    //
    vssc_http_response_t *response = vssc_http_response_new();

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vssc_virgil_http_client_write_recevied_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, vssc_virgil_http_client_write_recevied_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);

    //
    //  Perform the request.
    //
    const CURLcode send_status = curl_easy_perform(curl);
    if (send_status != CURLE_OK) {
        goto send_fail;
    }

    //
    //  Parse response.
    //
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    response->status_code = response_code;

    goto maybe_succ;

send_fail:
    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_SEND_REQUEST_FAILED);

    vssc_http_response_destroy(&response);

maybe_succ:
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return response;
}

//
//  Concatenate header name and header value as "NAME: VALUE".
//  Note, given buffer is reset first and then strings are appended.
//  Note, written string is null-terminated.
//
static void
vssc_virgil_http_client_format_header(vsc_str_t name, vsc_str_t value, vsc_str_buffer_t *out_str) {

    VSSC_ASSERT(vsc_str_buffer_is_valid(out_str));

    vsc_str_buffer_reset(out_str);
    vsc_str_buffer_append_str(out_str, name);
    vsc_str_buffer_append_str(out_str, k_header_name_value_separator_str);
    vsc_str_buffer_append_str(out_str, value);
    vsc_str_buffer_append_char(out_str, '\0');
    vsc_str_buffer_dec_used(out_str, 1);
}

//
//  Make authorization header as "Authorization: TYPE CREDENTIALS".
//  Note, given buffer is reset first and then strings are appended.
//  Note, written string is null-terminated.
//
static void
vssc_virgil_http_client_format_authorization_header(vsc_str_t type, vsc_str_t credentials, vsc_str_buffer_t *out_str) {

    VSSC_ASSERT(vsc_str_buffer_is_valid(out_str));

    vsc_str_buffer_reset(out_str);
    vsc_str_buffer_append_str(out_str, vssc_http_header_name_authorization_str);
    vsc_str_buffer_append_str(out_str, k_header_name_value_separator_str);
    vsc_str_buffer_append_str(out_str, type);
    vsc_str_buffer_append_char(out_str, ' ');
    vsc_str_buffer_append_str(out_str, credentials);
    vsc_str_buffer_append_char(out_str, '\0');
    vsc_str_buffer_dec_used(out_str, 1);
}

//
//  Callback for CURL body writing fucntion.
//
static size_t
vssc_virgil_http_client_write_recevied_data(void *ptr, size_t size, size_t nmemb, vssc_http_response_t *http_response) {

    VSSC_ASSERT_PTR(ptr);

    const size_t total_len = size * nmemb;

    if (NULL == http_response->body) {
        http_response->body = vsc_str_buffer_new_with_capacity(total_len);
    }

    vsc_str_t str = vsc_str((const char *)ptr, total_len);

    vsc_str_buffer_append_str(http_response->body, str);

    return total_len;
}

//
//  Callback for CURL header writing fucntion.
//
static size_t
vssc_virgil_http_client_write_recevied_header(
        char *ptr, size_t size, size_t nmemb, vssc_http_response_t *http_response) {

    typedef enum {
        parse_state_INITIAL,
        parse_state_FOUND_NAME,
        parse_state_FOUND_NAME_END,
        parse_state_FOUND_SEP,
        parse_state_FOUND_VALUE,
        parse_state_FOUND_VALUE_END
    } parse_state_t;

    parse_state_t parse_state = parse_state_INITIAL;

    const char *name = "";
    size_t name_len = 0;

    const char *value = "";
    size_t value_len = 0;

    const size_t total_len = size * nmemb;

    bool is_found_sep = false;

    for (size_t pos = 0; pos < total_len; ++pos) {
        const char ch = ptr[pos];

        switch (parse_state) {
        case parse_state_INITIAL: {
            if (!isspace(ch)) {
                name = ptr + pos;
                ++name_len;
                parse_state = parse_state_FOUND_NAME;
            }
            break;
        }

        case parse_state_FOUND_NAME: {
            if (!isspace(ch) && ch != ':') {
                ++name_len;
            } else if (ch == ':') {
                parse_state = parse_state_FOUND_SEP;
                is_found_sep = true;
            } else {
                parse_state = parse_state_FOUND_NAME_END;
            }
            break;
        }

        case parse_state_FOUND_NAME_END: {
            if (ch == ':') {
                parse_state = parse_state_FOUND_SEP;
                is_found_sep = true;
            }
            break;
        }

        case parse_state_FOUND_SEP: {
            if (!isspace(ch) && isprint(ch)) {
                value = ptr + pos;
                ++value_len;
                parse_state = parse_state_FOUND_VALUE;
            }
            break;
        }

        case parse_state_FOUND_VALUE: {
            if (isprint(ch)) {
                ++value_len;
            } else {
                parse_state = parse_state_FOUND_VALUE_END;
            }
            break;
        }

        case parse_state_FOUND_VALUE_END:
            break;
        }

        if (parse_state_FOUND_VALUE_END == parse_state) {
            break;
        }
    }

    if (!is_found_sep) {
        return total_len;
    }

    VSSC_ASSERT(name_len > 0);

    vsc_str_t name_str = vsc_str(name, name_len);
    vsc_str_t value_str = vsc_str(value, value_len);

    vssc_http_response_add_header(http_response, name_str, value_str);

    return total_len;
}
