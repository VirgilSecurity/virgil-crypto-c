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
//  This module contains 'http client curl' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_client_curl.h"
#include "vssc_assert.h"
#include "vssc_memory.h"
#include "vssc_http_client_curl_defs.h"
#include "vssc_http_client_curl_internal.h"
#include "vssc_http_response_internal.h"

#include <curl/curl.h>
#include <ctype.h>
#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>
#include <virgil/crypto/common/vsc_str_mutable.h>
#include <virgil/crypto/common/vsc_str_buffer.h>
#include <virgil/crypto/common/vsc_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Concatenate header name and header value as "NAME: VALUE".
//
//  Note, given buffer is reset first and then strings are appended.
//  Note, written string is null-terminated.
//
static void
vssc_http_client_curl_format_header(vsc_str_t name, vsc_str_t value, vsc_str_buffer_t *out_str);

//
//  Callback for CURL body writing function.
//
static size_t
vssc_http_client_curl_write_recevied_data(void *ptr, size_t size, size_t nmemb, vsc_buffer_t *body_buffer);

//
//  Callback for CURL header writing function.
//
static size_t
vssc_http_client_curl_write_recevied_header(char *ptr, size_t size, size_t nmemb, vssc_http_response_t *http_response);

//
//  Separator between header name and header value.
//
static const char k_header_name_value_separator_chars[] = ": ";

//
//  Separator between header name and header value.
//
static const vsc_str_t k_header_name_value_separator = {
    k_header_name_value_separator_chars,
    sizeof(k_header_name_value_separator_chars) - 1
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vssc_http_client_curl_init() is called.
//  Note, that context is already zeroed.
//
VSSC_PRIVATE void
vssc_http_client_curl_init_ctx(vssc_http_client_curl_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSSC_PRIVATE void
vssc_http_client_curl_cleanup_ctx(vssc_http_client_curl_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->ca_bundle_path);
}

//
//  Use custom CA bundle.
//
VSSC_PUBLIC void
vssc_http_client_curl_init_ctx_with_ca(vssc_http_client_curl_t *self, vsc_str_t ca_bundle_path) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(ca_bundle_path));

    self->ca_bundle_path = vsc_str_mutable_from_str(ca_bundle_path);
}

//
//  Concatenate header name and header value as "NAME: VALUE".
//
//  Note, given buffer is reset first and then strings are appended.
//  Note, written string is null-terminated.
//
static void
vssc_http_client_curl_format_header(vsc_str_t name, vsc_str_t value, vsc_str_buffer_t *out_str) {

    VSSC_ASSERT(vsc_str_buffer_is_valid(out_str));

    vsc_str_buffer_reset(out_str);
    vsc_str_buffer_append_str(out_str, name);
    vsc_str_buffer_append_str(out_str, k_header_name_value_separator);
    vsc_str_buffer_append_str(out_str, value);
    vsc_str_buffer_append_char(out_str, '\0');
    vsc_str_buffer_dec_used(out_str, 1);
}

//
//  Callback for CURL body writing function.
//
static size_t
vssc_http_client_curl_write_recevied_data(void *ptr, size_t size, size_t nmemb, vsc_buffer_t *body_buffer) {

    VSSC_ASSERT_PTR(ptr);
    VSSC_ASSERT_PTR(body_buffer);

    const size_t total_len = size * nmemb;

    vsc_data_t str = vsc_data((const byte *)ptr, total_len);

    vsc_buffer_append_data(body_buffer, str);

    return total_len;
}

//
//  Callback for CURL header writing function.
//
static size_t
vssc_http_client_curl_write_recevied_header(char *ptr, size_t size, size_t nmemb, vssc_http_response_t *http_response) {

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

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_curl_send(
        vssc_http_client_curl_t *self, const vssc_http_request_t *http_request, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);

    //
    //  Set URL and method.
    //
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, vssc_http_request_url(http_request).chars);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, vssc_http_request_method(http_request).chars);

    if (self->ca_bundle_path.chars && self->ca_bundle_path.len != 0) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, self->ca_bundle_path.chars);
    }

    //
    //  Add headers.
    //
    vsc_str_buffer_t *header_buf = vsc_str_buffer_new_with_capacity(512);
    struct curl_slist *headers = NULL;

    // Authorization
    vsc_str_t auth_header_value = vssc_http_request_auth_header_value(http_request);
    if (!vsc_str_is_empty(auth_header_value)) {
        vssc_http_client_curl_format_header(vssc_http_header_name_authorization, auth_header_value, header_buf);
        headers = curl_slist_append(headers, vsc_str_buffer_str(header_buf).chars);
        VSSC_ASSERT_ALLOC(headers);
    }

    // Custom headers.
    for (const vssc_http_header_list_t *header_it = vssc_http_request_headers(http_request);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        vssc_http_client_curl_format_header(header_name, header_value, header_buf);
        headers = curl_slist_append(headers, vsc_str_buffer_str(header_buf).chars);
        VSSC_ASSERT_ALLOC(headers);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    vsc_str_buffer_destroy(&header_buf);

    //
    //  Set body.
    //
    vsc_data_t body = vssc_http_request_body(http_request);
    if (!vsc_data_is_empty(body)) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.bytes);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.len);
    }
    //
    //  Set callbacks to build response.
    //
    vssc_http_response_t *response = vssc_http_response_new();
    vsc_buffer_t *body_buffer = vsc_buffer_new();

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vssc_http_client_curl_write_recevied_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body_buffer);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, vssc_http_client_curl_write_recevied_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);

    char errbuf[CURL_ERROR_SIZE] = {'\0'};
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    //
    //  Perform the request.
    //
    const CURLcode send_status = curl_easy_perform(curl);

    if (send_status != CURLE_OK) {
        fprintf(stderr, "\nlibcurl: (%d) ", send_status);

        if(*errbuf != '\0') {
            fprintf(stderr, "%s\n", errbuf);
        }
        else {
            fprintf(stderr, "%s\n", curl_easy_strerror(send_status));
        }

        goto send_fail;
    }

    //
    //  Parse response.
    //
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    vssc_http_response_set_status(response, response_code);

    if (vsc_buffer_is_valid(body_buffer)) {
        vssc_http_response_set_body_disown(response, &body_buffer);
    } else {
        vsc_buffer_destroy(&body_buffer);
    }

    goto maybe_succ;

send_fail:
    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_SEND_REQUEST_FAILED);
    vssc_http_response_destroy(&response);
    vsc_buffer_destroy(&body_buffer);
    printf("%s", curl_easy_strerror(send_status));

maybe_succ:
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return response;
}
