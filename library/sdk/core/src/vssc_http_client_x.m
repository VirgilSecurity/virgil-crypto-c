//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
//  This module contains 'http client x' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_http_client_x.h"
#include "vssc_assert.h"
#include "vssc_memory.h"
#include "vssc_http_client_x_defs.h"
#include "vssc_http_client_x_internal.h"

#include <virgil/crypto/common/vsc_str.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static NSString *
vssc_http_client_x_create_obj_ascii_string(vsc_str_t str);

static NSString *
vssc_http_client_x_create_obj_utf8_string(vsc_str_t str);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vssc_http_client_x_init() is called.
//  Note, that context is already zeroed.
//
VSSC_PRIVATE void
vssc_http_client_x_init_ctx(vssc_http_client_x_t *self) {

    VSSC_ASSERT_PTR(self);

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    self->session_objc = [NSURLSession sessionWithConfiguration:config];
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSSC_PRIVATE void
vssc_http_client_x_cleanup_ctx(vssc_http_client_x_t *self) {

    VSSC_ASSERT_PTR(self);

    [self->session_objc invalidateAndCancel];
    self->session_objc = nil;
}

static NSString *
vssc_http_client_x_create_obj_ascii_string(vsc_str_t str) {

    NSData *str_data_objc = [NSData dataWithBytes:(const byte *)str.chars length:(NSInteger)str.len];
    NSString *str_objc = [[NSString alloc] initWithData:str_data_objc encoding:NSASCIIStringEncoding];
    return str_objc;
}

static NSString *
vssc_http_client_x_create_obj_utf8_string(vsc_str_t str) {

    NSData *str_data_objc = [NSData dataWithBytes:(const byte *)str.chars length:(NSInteger)str.len];
    NSString *str_objc = [[NSString alloc] initWithData:str_data_objc encoding:NSUTF8StringEncoding];
    return str_objc;
}

//
//  Send given request over HTTP.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_client_x_send(vssc_http_client_x_t *self, const vssc_http_request_t *http_request, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);

    //
    //  Set URL and method.
    //
    vsc_str_t url = vssc_http_request_url(http_request);
    NSURL *url_objc = [[NSURL alloc] initWithString:vssc_http_client_x_create_obj_ascii_string(url)];
    if (nil == url_objc) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_URL_INVALID_FORMAT);
        return NULL;
    }

    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url_objc];

    //
    //  Set HTTP method: GET, POST, etc.
    //
    vsc_str_t http_method = vssc_http_request_method(http_request);
    NSString *http_method_objc = vssc_http_client_x_create_obj_ascii_string(http_method);
    [request setHTTPMethod:http_method_objc];

    //
    //  Add headers.
    //

    // Authorization
    vsc_str_t auth_header_value = vssc_http_request_auth_header_value(http_request);
    if (!vsc_str_is_empty(auth_header_value)) {
        NSString *key_objc = @"Authorization";
        NSString *value_objc = vssc_http_client_x_create_obj_ascii_string(auth_header_value);
        [request setValue:value_objc forHTTPHeaderField:key_objc];
    }

    // Custom headers.
    for (const vssc_http_header_list_t *header_it = vssc_http_request_headers(http_request);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        NSString *header_name_objc = vssc_http_client_x_create_obj_utf8_string(header_name);
        NSString *header_value_objc = vssc_http_client_x_create_obj_utf8_string(header_value);
        [request setValue:header_value_objc forHTTPHeaderField:header_name_objc];
    }

    vsc_data_t body = vssc_http_request_body(http_request);
    if (!vsc_data_is_empty(body)) {
        [request setHTTPBody:[NSData dataWithBytes:body.bytes length:body.len]];
    }

    //
    //  Perform the request.
    //
    __block NSData *_Nullable data = nil;
    __block NSHTTPURLResponse *_Nullable response = nil;
    __block NSError *_Nullable send_error = nil;

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task =
            [self->session_objc dataTaskWithRequest:request
                                  completionHandler:^(NSData *_Nullable ldata, NSURLResponse *_Nullable lresponse,
                                          NSError *_Nullable lerror) {
                                    data = ldata;
                                    response = (NSHTTPURLResponse *)lresponse;
                                    send_error = lerror;
                                    dispatch_semaphore_signal(semaphore);
                                  }];

    [task resume];

    const long semaphore_status = dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    if (semaphore_status != 0 || send_error != nil || nil == response) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_SEND_REQUEST_FAILED);
        return NULL;
    }

    //
    //  Parse HTTP response.
    //
    const NSInteger status_code = response.statusCode;
    if (status_code < 0) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_SEND_REQUEST_FAILED);
        return NULL;
    }

    vssc_http_response_t *http_response = NULL;
    if (nil == data || 0 == data.length) {
        http_response = vssc_http_response_new_with_status((size_t)status_code);
    } else {
        vsc_data_t response_body = vsc_data((const byte *)data.bytes, (size_t)data.length);
        http_response = vssc_http_response_new_with_body((size_t)status_code, response_body);
    }

    //
    //  Add response headers.
    //
    for (NSString *key_objc in response.allHeaderFields) {
        NSString *value_objc = response.allHeaderFields[key_objc];

        vsc_str_t key = vsc_str(key_objc.UTF8String, (size_t)key_objc.length);
        vsc_str_t value = vsc_str(value_objc.UTF8String, (size_t)value_objc.length);

        vssc_http_response_add_header(http_response, key, value);
    }

    return http_response;
}
