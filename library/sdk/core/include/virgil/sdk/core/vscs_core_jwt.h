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
//  Class that handles JWT.
// --------------------------------------------------------------------------

#ifndef VSCS_CORE_JWT_H_INCLUDED
#define VSCS_CORE_JWT_H_INCLUDED

#include "vscs_core_library.h"
#include "vscs_core_jwt_header.h"
#include "vscs_core_jwt_payload.h"
#include "vscs_core_error.h"
#include "vscs_core_jwt.h"

#if !VSCS_CORE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#endif

#if VSCS_CORE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str_buffer.h>
#   include <VSCCommon/vsc_buffer.h>
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
//  Handle 'jwt' context.
//
typedef struct vscs_core_jwt_t vscs_core_jwt_t;

//
//  Return size of 'vscs_core_jwt_t'.
//
VSCS_CORE_PUBLIC size_t
vscs_core_jwt_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_init(vscs_core_jwt_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_cleanup(vscs_core_jwt_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCS_CORE_PUBLIC vscs_core_jwt_t *
vscs_core_jwt_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create object with all members defined.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_init_with_members_disown(vscs_core_jwt_t *self, vscs_core_jwt_header_t **header_ref,
        vscs_core_jwt_payload_t **payload_ref, vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref);

//
//  Allocate class context and perform it's initialization.
//  Create object with all members defined.
//
VSCS_CORE_PUBLIC vscs_core_jwt_t *
vscs_core_jwt_new_with_members_disown(vscs_core_jwt_header_t **header_ref, vscs_core_jwt_payload_t **payload_ref,
        vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_delete(vscs_core_jwt_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscs_core_jwt_new ()'.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_destroy(vscs_core_jwt_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCS_CORE_PUBLIC vscs_core_jwt_t *
vscs_core_jwt_shallow_copy(vscs_core_jwt_t *self);

//
//  Parse JWT from a string representation.
//
VSCS_CORE_PUBLIC vscs_core_jwt_t *
vscs_core_jwt_parse(vsc_str_t str, vscs_core_error_t *error);

//
//  Return JWT string representation.
//
VSCS_CORE_PUBLIC vsc_str_t
vscs_core_jwt_as_string(const vscs_core_jwt_t *self);

//
//  Return identity to whom this token was issued.
//
VSCS_CORE_PUBLIC vsc_str_t
vscs_core_jwt_identity(const vscs_core_jwt_t *self);

//
//  Return true if token is expired.
//
VSCS_CORE_PUBLIC bool
vscs_core_jwt_is_expired(const vscs_core_jwt_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCS_CORE_JWT_H_INCLUDED
//  @end
