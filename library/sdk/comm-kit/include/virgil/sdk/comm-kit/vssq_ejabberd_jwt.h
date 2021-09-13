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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Class that handles Ejabberd JWT.
// --------------------------------------------------------------------------

#ifndef VSSQ_EJABBERD_JWT_H_INCLUDED
#define VSSQ_EJABBERD_JWT_H_INCLUDED

#include "vssq_library.h"
#include "vssq_error.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'ejabberd jwt' context.
//
#ifndef VSSQ_EJABBERD_JWT_T_DEFINED
#define VSSQ_EJABBERD_JWT_T_DEFINED
    typedef struct vssq_ejabberd_jwt_t vssq_ejabberd_jwt_t;
#endif // VSSQ_EJABBERD_JWT_T_DEFINED

//
//  Return size of 'vssq_ejabberd_jwt_t'.
//
VSSQ_PUBLIC size_t
vssq_ejabberd_jwt_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_init(vssq_ejabberd_jwt_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_cleanup(vssq_ejabberd_jwt_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_delete(const vssq_ejabberd_jwt_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_ejabberd_jwt_new ()'.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_destroy(vssq_ejabberd_jwt_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_shallow_copy(vssq_ejabberd_jwt_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_shallow_copy_const(const vssq_ejabberd_jwt_t *self);

//
//  Parse Ejabberd JWT from a string representation.
//
VSSQ_PUBLIC vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_parse(vsc_str_t str, vssq_error_t *error);

//
//  Return Ejabberd JWT string representation.
//
VSSQ_PUBLIC vsc_str_t
vssq_ejabberd_jwt_as_string(const vssq_ejabberd_jwt_t *self);

//
//  Return identity to whom this token was issued.
//
VSSQ_PUBLIC vsc_str_t
vssq_ejabberd_jwt_jid(const vssq_ejabberd_jwt_t *self);

//
//  Return Unix timestamp of JWT expiration.
//
VSSQ_PUBLIC size_t
vssq_ejabberd_jwt_expires_at(const vssq_ejabberd_jwt_t *self);

//
//  Return true if token is expired.
//
VSSQ_PUBLIC bool
vssq_ejabberd_jwt_is_expired(const vssq_ejabberd_jwt_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_EJABBERD_JWT_H_INCLUDED
//  @end
