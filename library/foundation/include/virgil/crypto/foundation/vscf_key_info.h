//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#ifndef VSCF_KEY_INFO_H_INCLUDED
#define VSCF_KEY_INFO_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"

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
//  Handle 'key info' context.
//
typedef struct vscf_key_info_t vscf_key_info_t;

//
//  Return size of 'vscf_key_info_t'.
//
VSCF_PUBLIC size_t
vscf_key_info_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_info_init(vscf_key_info_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_info_cleanup(vscf_key_info_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_info_t *
vscf_key_info_new(void);

//
//  Perform initialization of pre-allocated context.
//  Build key information based on the generic algorithm information.
//
VSCF_PUBLIC void
vscf_key_info_init_with_alg_info(vscf_key_info_t *self, const vscf_impl_t *alg_info);

//
//  Allocate class context and perform it's initialization.
//  Build key information based on the generic algorithm information.
//
VSCF_PUBLIC vscf_key_info_t *
vscf_key_info_new_with_alg_info(const vscf_impl_t *alg_info);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_info_delete(vscf_key_info_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_info_new ()'.
//
VSCF_PUBLIC void
vscf_key_info_destroy(vscf_key_info_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_info_t *
vscf_key_info_shallow_copy(vscf_key_info_t *self);

//
//  Return true if a key is a compound key
//
VSCF_PUBLIC bool
vscf_key_info_is_compound(const vscf_key_info_t *self);

//
//  Return true if a key is a hybrid key
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid(const vscf_key_info_t *self);

//
//  Return true if a key is a compound key and compounds cipher key
//  and signer key are hybrid keys.
//
VSCF_PUBLIC bool
vscf_key_info_is_compound_hybrid(const vscf_key_info_t *self);

//
//  Return true if a key is a compound key and compounds cipher key
//  is a hybrid key.
//
VSCF_PUBLIC bool
vscf_key_info_is_compound_hybrid_cipher(const vscf_key_info_t *self);

//
//  Return true if a key is a compound key and compounds signer key
//  is a hybrid key.
//
VSCF_PUBLIC bool
vscf_key_info_is_compound_hybrid_signer(const vscf_key_info_t *self);

//
//  Return true if a key is a compound key that contains hybrid keys
//  for encryption/decryption and signing/verifying that itself
//  contains a combination of classic keys and post-quantum keys.
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid_post_quantum(const vscf_key_info_t *self);

//
//  Return true if a key is a compound key that contains a hybrid key
//  for encryption/decryption that contains a classic key and
//  a post-quantum key.
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid_post_quantum_cipher(const vscf_key_info_t *self);

//
//  Return true if a key is a compound key that contains a hybrid key
//  for signing/verifying that contains a classic key and
//  a post-quantum key.
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid_post_quantum_signer(const vscf_key_info_t *self);

//
//  Return common type of the key.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_alg_id(const vscf_key_info_t *self);

//
//  Return compound's cipher key id, if key is compound.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_cipher_alg_id(const vscf_key_info_t *self);

//
//  Return compound's signer key id, if key is compound.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_signer_alg_id(const vscf_key_info_t *self);

//
//  Return hybrid's first key id, if key is hybrid.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_hybrid_first_key_alg_id(const vscf_key_info_t *self);

//
//  Return hybrid's second key id, if key is hybrid.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_hybrid_second_key_alg_id(const vscf_key_info_t *self);

//
//  Return hybrid's first key id of compound's cipher key,
//  if key is compound(hybrid, ...), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_cipher_first_key_alg_id(const vscf_key_info_t *self);

//
//  Return hybrid's second key id of compound's cipher key,
//  if key is compound(hybrid, ...), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_cipher_second_key_alg_id(const vscf_key_info_t *self);

//
//  Return hybrid's first key id of compound's signer key,
//  if key is compound(..., hybrid), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_signer_first_key_alg_id(const vscf_key_info_t *self);

//
//  Return hybrid's second key id of compound's signer key,
//  if key is compound(..., hybrid), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_signer_second_key_alg_id(const vscf_key_info_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_INFO_H_INCLUDED
//  @end
