#include "vssc_http_client_x_impl.h"

#include "vssc_memory.h"
#include "vssc_assert.h"

#import <Foundation/Foundation.h>


struct vssc_http_client_x_impl_t {
    __strong NSURLSession *session;
};


static vssc_http_response_t *
vssc_http_client_x_impl_send_internal(vssc_http_client_x_impl_t *self, const vssc_http_request_t *http_request,
        vsc_str_t auth_type, vsc_str_t auth_credentials, vssc_error_t *error);


vssc_http_client_x_impl_t *
vssc_http_client_x_impl_new() {
    vssc_http_client_x_impl_t *self = vssc_alloc(sizeof(vssc_http_client_x_impl_t));
    VSSC_ASSERT_ALLOC(self);

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    self->session = [NSURLSession sessionWithConfiguration:config];

    return self;
}


void
vssc_http_client_x_impl_delete(vssc_http_client_x_impl_t *self) {
    if (NULL == self) {
        return;
    }

    [self->session invalidateAndCancel];
    self->session = nil;

    vssc_dealloc(self);
}


vssc_http_response_t *
vssc_http_client_x_impl_send(
        vssc_http_client_x_impl_t *self, const vssc_http_request_t *http_request, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);

    return vssc_http_client_x_impl_send_internal(self, http_request, vsc_str_empty(), vsc_str_empty(), error);
}


vssc_http_response_t *
vssc_http_client_x_auth_impl_send(vssc_http_client_x_impl_t *self, const vssc_http_request_t *http_request,
        vsc_str_t auth_type, vsc_str_t auth_credentials, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(auth_type));
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(auth_credentials));
    VSSC_ASSERT(vsc_str_is_null_terminated(auth_type));
    VSSC_ASSERT(vsc_str_is_null_terminated(auth_credentials));

    return vssc_http_client_x_impl_send_internal(self, http_request, auth_type, auth_credentials, error);
}


static vssc_http_response_t *
vssc_http_client_x_impl_send_internal(vssc_http_client_x_impl_t *self, const vssc_http_request_t *http_request,
        vsc_str_t auth_type, vsc_str_t auth_credentials, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(http_request);

    //
    //  Set URL and method.
    //
    vsc_str_t url = vssc_http_request_url(http_request);
    NSURL *url_objc = [[NSURL alloc] initWithString:[NSString stringWithCString:url.chars
                                                                       encoding:NSASCIIStringEncoding]];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url_objc];
    if (nil == url_objc) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_HTTP_URL_INVALID_FORMAT);
        return NULL;
    }

    //
    //  Add headers.
    //

    // Authorization
    if (vsc_str_is_valid_and_non_empty(auth_type) && vsc_str_is_valid_and_non_empty(auth_credentials)) {
        NSString *key_objc = @"Authorization";
        NSString *type_objc = [NSString stringWithCString:auth_type.chars encoding:NSASCIIStringEncoding];
        NSString *credentials_objc = [NSString stringWithCString:auth_credentials.chars encoding:NSASCIIStringEncoding];
        NSString *value_objc = [NSString stringWithFormat:@"%@ %@", type_objc, credentials_objc];
        [request setValue:value_objc forHTTPHeaderField:key_objc];
    }

    // Custom headers.
    for (const vssc_http_header_list_t *header_it = vssc_http_request_headers(http_request);
            header_it != NULL && vssc_http_header_list_has_item(header_it);
            header_it = vssc_http_header_list_next(header_it)) {

        const vssc_http_header_t *header = vssc_http_header_list_item(header_it);
        vsc_str_t header_name = vssc_http_header_name(header);
        vsc_str_t header_value = vssc_http_header_value(header);

        VSSC_ASSERT(vsc_str_is_null_terminated(header_name));
        VSSC_ASSERT(vsc_str_is_null_terminated(header_value));

        NSString *header_name_objc = [NSString stringWithCString:header_name.chars encoding:NSUTF8StringEncoding];
        NSString *header_value_objc = [NSString stringWithCString:header_value.chars encoding:NSUTF8StringEncoding];
        [request setValue:header_name_objc forHTTPHeaderField:header_value_objc];
    }

    vsc_str_t body = vssc_http_request_body(http_request);
    if (!vsc_str_is_empty(body)) {
        [request setHTTPBody:[NSData dataWithBytes:body.chars length:body.len]];
    }

    //
    //  Perform the request.
    //
    __block NSData *_Nullable data = nil;
    __block NSHTTPURLResponse *_Nullable response = nil;
    __block NSError *_Nullable send_error = nil;

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task =
            [self->session dataTaskWithRequest:request
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
    if (nil == data) {
        http_response = vssc_http_response_new_with_status((size_t)status_code);
    } else {
        // TODO: Check if body is a string.
        vsc_str_t response_body = vsc_str((const char *)data.bytes, (size_t)data.length);
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
