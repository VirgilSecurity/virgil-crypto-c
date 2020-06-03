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
//  Class that handles JWT Payload.
// --------------------------------------------------------------------------

#ifndef VSSC_JWT_PAYLOAD_H_INCLUDED
#define VSSC_JWT_PAYLOAD_H_INCLUDED

#include "vssc_library.h"
#include "vssc_error.h"
#include "vssc_jwt_payload.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_str_buffer.h>
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
//  Handle 'jwt payload' context.
//
typedef struct vssc_jwt_payload_t vssc_jwt_payload_t;

//
//  Return size of 'vssc_jwt_payload_t'.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_jwt_payload_init(vssc_jwt_payload_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_jwt_payload_cleanup(vssc_jwt_payload_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined JWT Payload.
//
VSSC_PUBLIC void
vssc_jwt_payload_init_with_members(vssc_jwt_payload_t *self, vsc_str_t app_id, vsc_str_t identity, size_t issued_at,
        size_t expires_at);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined JWT Payload.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_new_with_members(vsc_str_t app_id, vsc_str_t identity, size_t issued_at, size_t expires_at);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_jwt_payload_delete(const vssc_jwt_payload_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_jwt_payload_new ()'.
//
VSSC_PUBLIC void
vssc_jwt_payload_destroy(vssc_jwt_payload_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_shallow_copy(vssc_jwt_payload_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_jwt_payload_t *
vssc_jwt_payload_shallow_copy_const(const vssc_jwt_payload_t *self);

//
//  Parse JWT Payload from a string representation.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_parse(vsc_str_t payload_str, vssc_error_t *error);

//
//  Return lengh for buffer that can hold JWT Payload string representation.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_as_string_len(const vssc_jwt_payload_t *self);

//
//  Return JWT Payload string representation.
//  Representations is base64url.encode(json).
//
VSSC_PUBLIC void
vssc_jwt_payload_as_string(const vssc_jwt_payload_t *self, vsc_str_buffer_t *str_buffer);

//
//  Return JWT Payload as JSON string.
//
VSSC_PRIVATE vsc_str_t
vssc_jwt_payload_as_json_string(const vssc_jwt_payload_t *self);

//
//  Issuer application id.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_payload_app_id(const vssc_jwt_payload_t *self);

//
//  Return identity to whom this token was issued.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_payload_identity(const vssc_jwt_payload_t *self);

//
//  Return UNIX Timestamp in seconds with issued date.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_issued_at(vssc_jwt_payload_t *self);

//
//  Return UNIX Timestamp in seconds with expiration date.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_expires_at(vssc_jwt_payload_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_JWT_PAYLOAD_H_INCLUDED
//  @end
