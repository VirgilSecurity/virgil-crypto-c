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
//  This class contains HTTP response information alongside with information
//  that is specific for the Virgil services.
// --------------------------------------------------------------------------

#ifndef VSSC_HTTP_RESPONSE_H_INCLUDED
#define VSSC_HTTP_RESPONSE_H_INCLUDED

#include "vssc_library.h"
#include "vssc_http_header_list.h"
#include "vssc_error.h"
#include "vssc_json_array.h"

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
//  Handle 'http response' context.
//
#ifndef VSSC_HTTP_RESPONSE_T_DEFINED
#define VSSC_HTTP_RESPONSE_T_DEFINED
    typedef struct vssc_http_response_t vssc_http_response_t;
#endif // VSSC_HTTP_RESPONSE_T_DEFINED

//
//  Return size of 'vssc_http_response_t'.
//
VSSC_PUBLIC size_t
vssc_http_response_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_http_response_init(vssc_http_response_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_http_response_cleanup(vssc_http_response_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create response with a status only.
//
VSSC_PUBLIC void
vssc_http_response_init_with_status(vssc_http_response_t *self, size_t status_code);

//
//  Allocate class context and perform it's initialization.
//  Create response with a status only.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_new_with_status(size_t status_code);

//
//  Perform initialization of pre-allocated context.
//  Create response with a status and body.
//
VSSC_PUBLIC void
vssc_http_response_init_with_body(vssc_http_response_t *self, size_t status_code, vsc_str_t body);

//
//  Allocate class context and perform it's initialization.
//  Create response with a status and body.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_new_with_body(size_t status_code, vsc_str_t body);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_http_response_delete(const vssc_http_response_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_http_response_new ()'.
//
VSSC_PUBLIC void
vssc_http_response_destroy(vssc_http_response_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_http_response_t *
vssc_http_response_shallow_copy(vssc_http_response_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_http_response_t *
vssc_http_response_shallow_copy_const(const vssc_http_response_t *self);

//
//  Set HTTP status.
//
VSSC_PUBLIC void
vssc_http_response_set_status(vssc_http_response_t *self, size_t status_code);

//
//  Set HTTP body.
//
VSSC_PUBLIC void
vssc_http_response_set_body(vssc_http_response_t *self, vsc_str_t body);

//
//  Add HTTP header.
//
VSSC_PUBLIC void
vssc_http_response_add_header(vssc_http_response_t *self, vsc_str_t name, vsc_str_t value);

//
//  Return true if underlying status code is in range [200..299].
//
VSSC_PUBLIC bool
vssc_http_response_is_success(const vssc_http_response_t *self);

//
//  Return HTTP status code.
//
VSSC_PUBLIC size_t
vssc_http_response_status_code(const vssc_http_response_t *self);

//
//  Return HTTP body.
//
VSSC_PUBLIC vsc_str_t
vssc_http_response_body(const vssc_http_response_t *self);

//
//  Return HTTP headers.
//
VSSC_PUBLIC const vssc_http_header_list_t *
vssc_http_response_headers(const vssc_http_response_t *self);

//
//  Find header by it's name.
//
VSSC_PUBLIC vsc_str_t
vssc_http_response_find_header(const vssc_http_response_t *self, vsc_str_t name, vssc_error_t *error);

//
//  Return true if response handles a valid body as JSON object.
//
VSSC_PUBLIC bool
vssc_http_response_body_is_json_object(const vssc_http_response_t *self);

//
//  Return true if response handles a valid body as JSON array.
//
VSSC_PUBLIC bool
vssc_http_response_body_is_json_array(const vssc_http_response_t *self);

//
//  Return response body as JSON object.
//
VSSC_PUBLIC const vssc_json_object_t *
vssc_http_response_body_as_json_object(const vssc_http_response_t *self);

//
//  Return response body as JSON array.
//
VSSC_PUBLIC const vssc_json_array_t *
vssc_http_response_body_as_json_array(const vssc_http_response_t *self);

//
//  Return true if response handles a service error and it's description.
//
VSSC_PUBLIC bool
vssc_http_response_has_service_error(const vssc_http_response_t *self);

//
//  Return service error code.
//
VSSC_PUBLIC size_t
vssc_http_response_service_error_code(const vssc_http_response_t *self);

//
//  Return service error description.
//  Note, empty string can be returned.
//
VSSC_PUBLIC vsc_str_t
vssc_http_response_service_error_description(const vssc_http_response_t *self);

//
//  Check status code range [200..299].
//
VSSC_PUBLIC bool
vssc_http_response_is_status_code_success(size_t http_status_code);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_HTTP_RESPONSE_H_INCLUDED
//  @end
