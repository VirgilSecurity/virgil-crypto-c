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
//  that is specific for Virgil services.
// --------------------------------------------------------------------------

#ifndef VSSC_VIRGIL_HTTP_RESPONSE_H_INCLUDED
#define VSSC_VIRGIL_HTTP_RESPONSE_H_INCLUDED

#include "vssc_library.h"
#include "vssc_json_object.h"
#include "vssc_http_response.h"
#include "vssc_error.h"
#include "vssc_virgil_http_response.h"

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
//  Handle 'virgil http response' context.
//
typedef struct vssc_virgil_http_response_t vssc_virgil_http_response_t;

//
//  Return size of 'vssc_virgil_http_response_t'.
//
VSSC_PUBLIC size_t
vssc_virgil_http_response_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_virgil_http_response_init(vssc_virgil_http_response_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_virgil_http_response_cleanup(vssc_virgil_http_response_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_response_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_virgil_http_response_delete(vssc_virgil_http_response_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_virgil_http_response_new ()'.
//
VSSC_PUBLIC void
vssc_virgil_http_response_destroy(vssc_virgil_http_response_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_response_shallow_copy(vssc_virgil_http_response_t *self);

//
//  Create self from the parsed HTTP response.
//
VSSC_PUBLIC vssc_virgil_http_response_t *
vssc_virgil_http_response_create_from_http_response(const vssc_http_response_t *http_response, vssc_error_t *error);

//
//  Return HTTP status code.
//
VSSC_PUBLIC size_t
vssc_virgil_http_response_status_code(const vssc_virgil_http_response_t *self);

//
//  Return true if correspond HTTP request was succeed.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_is_success(const vssc_virgil_http_response_t *self);

//
//  Return true if response contains a valid body.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_has_body(const vssc_virgil_http_response_t *self);

//
//  Return response body as JSON object.
//
VSSC_PUBLIC const vssc_json_object_t *
vssc_virgil_http_response_body(const vssc_virgil_http_response_t *self);

//
//  Return true if response handles a service error and it's description.
//
VSSC_PUBLIC bool
vssc_virgil_http_response_has_service_error(const vssc_virgil_http_response_t *self);

//
//  Return service error code.
//
VSSC_PUBLIC size_t
vssc_virgil_http_response_service_error_code(const vssc_virgil_http_response_t *self);

//
//  Return service error description.
//  Note, empty string can be returned.
//
VSSC_PUBLIC vsc_str_t
vssc_virgil_http_response_service_error_description(const vssc_virgil_http_response_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_VIRGIL_HTTP_RESPONSE_H_INCLUDED
//  @end
