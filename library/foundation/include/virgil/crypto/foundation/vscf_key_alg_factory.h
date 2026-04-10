//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Create a bridge between "raw keys" and algorithms that can import them.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_ALG_FACTORY_H_INCLUDED
#define VSCF_KEY_ALG_FACTORY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_alg_id.h"
#include "vscf_impl.h"
#include "vscf_raw_public_key.h"
#include "vscf_raw_private_key.h"

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
//  Handle 'key alg factory' context.
//
typedef struct vscf_key_alg_factory_t vscf_key_alg_factory_t;

//
//  Return size of 'vscf_key_alg_factory_t'.
//
VSCF_PUBLIC size_t
vscf_key_alg_factory_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_alg_factory_init(vscf_key_alg_factory_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_alg_factory_cleanup(vscf_key_alg_factory_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_alg_factory_t *
vscf_key_alg_factory_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_alg_factory_delete(vscf_key_alg_factory_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_alg_factory_new ()'.
//
VSCF_PUBLIC void
vscf_key_alg_factory_destroy(vscf_key_alg_factory_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_alg_factory_t *
vscf_key_alg_factory_shallow_copy(vscf_key_alg_factory_t *self);

//
//  Create a key algorithm based on an identifier.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_t alg_id, vscf_impl_t *random, vscf_error_t error);

//
//  Create a key algorithm correspond to a specific key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_key(vscf_impl_t *key, vscf_impl_t *random, vscf_error_t error);

//
//  Create a key algorithm that can import "raw public key".
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_raw_public_key(vscf_raw_public_key_t public_key, vscf_impl_t *random, vscf_error_t error);

//
//  Create a key algorithm that can import "raw private key".
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_raw_private_key(vscf_raw_private_key_t private_key, vscf_impl_t *random, vscf_error_t error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_ALG_FACTORY_H_INCLUDED
//  @end
