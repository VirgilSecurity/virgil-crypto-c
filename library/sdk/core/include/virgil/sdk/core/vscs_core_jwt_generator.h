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
//  Class responsible for JWT generation.
// --------------------------------------------------------------------------

#ifndef VSCS_CORE_JWT_GENERATOR_H_INCLUDED
#define VSCS_CORE_JWT_GENERATOR_H_INCLUDED

#include "vscs_core_library.h"
#include "vscs_core_error.h"
#include "vscs_core_jwt.h"
#include "vscs_core_status.h"

#if !VSCS_CORE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str_buffer.h>
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSCS_CORE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCS_CORE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_str_buffer.h>
#endif

#if VSCS_CORE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
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
//  Public integral constants.
//
enum {
    vscs_core_jwt_generator_DEFAULT_TTL = 15 * 60
};

//
//  Handle 'jwt generator' context.
//
typedef struct vscs_core_jwt_generator_t vscs_core_jwt_generator_t;

//
//  Return size of 'vscs_core_jwt_generator_t'.
//
VSCS_CORE_PUBLIC size_t
vscs_core_jwt_generator_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_init(vscs_core_jwt_generator_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_cleanup(vscs_core_jwt_generator_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCS_CORE_PUBLIC vscs_core_jwt_generator_t *
vscs_core_jwt_generator_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create JWT generator with an application credentials.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_init_with_credentials(vscs_core_jwt_generator_t *self, vsc_str_buffer_t *api_id,
        const vscf_impl_t *api_key, vsc_str_buffer_t *api_public_key_identifier);

//
//  Allocate class context and perform it's initialization.
//  Create JWT generator with an application credentials.
//
VSCS_CORE_PUBLIC vscs_core_jwt_generator_t *
vscs_core_jwt_generator_new_with_credentials(vsc_str_buffer_t *api_id, const vscf_impl_t *api_key,
        vsc_str_buffer_t *api_public_key_identifier);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_delete(vscs_core_jwt_generator_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscs_core_jwt_generator_new ()'.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_destroy(vscs_core_jwt_generator_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCS_CORE_PUBLIC vscs_core_jwt_generator_t *
vscs_core_jwt_generator_shallow_copy(vscs_core_jwt_generator_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_use_random(vscs_core_jwt_generator_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_take_random(vscs_core_jwt_generator_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_release_random(vscs_core_jwt_generator_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCS_CORE_PUBLIC vscs_core_status_t
vscs_core_jwt_generator_setup_defaults(vscs_core_jwt_generator_t *self) VSCS_CORE_NODISCARD;

//
//  Set JWT TTL.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_set_ttl(vscs_core_jwt_generator_t *self, size_t ttl);

//
//  Generate new JWT.
//
VSCS_CORE_PUBLIC vscs_core_jwt_t *
vscs_core_jwt_generator_generate_token(const vscs_core_jwt_generator_t *self, vsc_str_t identity,
        const vscs_core_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCS_CORE_JWT_GENERATOR_H_INCLUDED
//  @end
