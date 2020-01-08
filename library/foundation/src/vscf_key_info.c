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

#include "vscf_key_info.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_key_info_defs.h"
#include "vscf_alg_info.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_hybrid_key_alg_info.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_info_init_ctx(vscf_key_info_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_info_cleanup_ctx(vscf_key_info_t *self);

//
//  Build key information based on the generic algorithm information.
//
static void
vscf_key_info_init_ctx_with_alg_info(vscf_key_info_t *self, const vscf_impl_t *alg_info);

//
//  Return size of 'vscf_key_info_t'.
//
VSCF_PUBLIC size_t
vscf_key_info_ctx_size(void) {

    return sizeof(vscf_key_info_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_info_init(vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_key_info_t));

    self->refcnt = 1;

    vscf_key_info_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_info_cleanup(vscf_key_info_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_key_info_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_key_info_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_info_t *
vscf_key_info_new(void) {

    vscf_key_info_t *self = (vscf_key_info_t *) vscf_alloc(sizeof (vscf_key_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_key_info_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Build key information based on the generic algorithm information.
//
VSCF_PUBLIC void
vscf_key_info_init_with_alg_info(vscf_key_info_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_key_info_t));

    self->refcnt = 1;

    vscf_key_info_init_ctx_with_alg_info(self, alg_info);
}

//
//  Allocate class context and perform it's initialization.
//  Build key information based on the generic algorithm information.
//
VSCF_PUBLIC vscf_key_info_t *
vscf_key_info_new_with_alg_info(const vscf_impl_t *alg_info) {

    vscf_key_info_t *self = (vscf_key_info_t *) vscf_alloc(sizeof (vscf_key_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_key_info_init_with_alg_info(self, alg_info);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_info_delete(vscf_key_info_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_key_info_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_info_new ()'.
//
VSCF_PUBLIC void
vscf_key_info_destroy(vscf_key_info_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_key_info_t *self = *self_ref;
    *self_ref = NULL;

    vscf_key_info_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_info_t *
vscf_key_info_shallow_copy(vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_info_init_ctx(vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    self->alg_id = vscf_alg_id_NONE;
    self->hybrid_first_key_alg_id = vscf_alg_id_NONE;
    self->hybrid_second_key_alg_id = vscf_alg_id_NONE;
    self->compound_cipher_alg_id = vscf_alg_id_NONE;
    self->compound_signer_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_cipher_first_key_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_cipher_second_key_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_signer_first_key_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_signer_second_key_alg_id = vscf_alg_id_NONE;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_info_cleanup_ctx(vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Build key information based on the generic algorithm information.
//
static void
vscf_key_info_init_ctx_with_alg_info(vscf_key_info_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));

    self->alg_id = vscf_alg_info_alg_id(alg_info);
    self->hybrid_first_key_alg_id = vscf_alg_id_NONE;
    self->hybrid_second_key_alg_id = vscf_alg_id_NONE;
    self->compound_cipher_alg_id = vscf_alg_id_NONE;
    self->compound_signer_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_cipher_first_key_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_cipher_second_key_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_signer_first_key_alg_id = vscf_alg_id_NONE;
    self->compound_hybrid_signer_second_key_alg_id = vscf_alg_id_NONE;

    if (vscf_impl_tag(alg_info) == vscf_impl_tag_COMPOUND_KEY_ALG_INFO) {
        const vscf_compound_key_alg_info_t *compound_key_alg_info = (const vscf_compound_key_alg_info_t *)alg_info;
        const vscf_impl_t *cipher_alg_info = vscf_compound_key_alg_info_cipher_alg_info(compound_key_alg_info);
        const vscf_impl_t *signer_alg_info = vscf_compound_key_alg_info_signer_alg_info(compound_key_alg_info);

        self->compound_cipher_alg_id = vscf_alg_info_alg_id(cipher_alg_info);
        self->compound_signer_alg_id = vscf_alg_info_alg_id(signer_alg_info);

        if (vscf_impl_tag(cipher_alg_info) == vscf_impl_tag_HYBRID_KEY_ALG_INFO) {
            const vscf_hybrid_key_alg_info_t *hybrid_key_alg_info = (const vscf_hybrid_key_alg_info_t *)cipher_alg_info;
            const vscf_impl_t *first_key_alg_info = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_key_alg_info);
            const vscf_impl_t *second_key_alg_info = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_key_alg_info);

            self->compound_hybrid_cipher_first_key_alg_id = vscf_alg_info_alg_id(first_key_alg_info);
            self->compound_hybrid_cipher_second_key_alg_id = vscf_alg_info_alg_id(second_key_alg_info);
        }

        if (vscf_impl_tag(signer_alg_info) == vscf_impl_tag_HYBRID_KEY_ALG_INFO) {
            const vscf_hybrid_key_alg_info_t *hybrid_key_alg_info = (const vscf_hybrid_key_alg_info_t *)signer_alg_info;
            const vscf_impl_t *first_key_alg_info = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_key_alg_info);
            const vscf_impl_t *second_key_alg_info = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_key_alg_info);

            self->compound_hybrid_signer_first_key_alg_id = vscf_alg_info_alg_id(first_key_alg_info);
            self->compound_hybrid_signer_second_key_alg_id = vscf_alg_info_alg_id(second_key_alg_info);
        }
    }


    if (vscf_impl_tag(alg_info) == vscf_impl_tag_HYBRID_KEY_ALG_INFO) {
        const vscf_hybrid_key_alg_info_t *hybrid_key_alg_info = (const vscf_hybrid_key_alg_info_t *)alg_info;
        const vscf_impl_t *first_key_alg_info = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_key_alg_info);
        const vscf_impl_t *second_key_alg_info = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_key_alg_info);

        self->hybrid_first_key_alg_id = vscf_alg_info_alg_id(first_key_alg_info);
        self->hybrid_second_key_alg_id = vscf_alg_info_alg_id(second_key_alg_info);
    }
}

//
//  Return true if a key is a compound key
//
VSCF_PUBLIC bool
vscf_key_info_is_compound(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_COMPOUND_KEY == self->alg_id;
}

//
//  Return true if a key is a hybrid key
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_HYBRID_KEY == self->alg_id;
}

//
//  Return true if a key is a compound key and compounds cipher key
//  and signer key are hybrid keys.
//
VSCF_PUBLIC bool
vscf_key_info_is_compound_hybrid(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_key_info_is_compound_hybrid_cipher(self) && vscf_key_info_is_compound_hybrid_signer(self);
}

//
//  Return true if a key is a compound key and compounds cipher key
//  is a hybrid key.
//
VSCF_PUBLIC bool
vscf_key_info_is_compound_hybrid_cipher(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return (self->compound_hybrid_cipher_first_key_alg_id != vscf_alg_id_NONE) &&
           (self->compound_hybrid_cipher_second_key_alg_id != vscf_alg_id_NONE);
}

//
//  Return true if a key is a compound key and compounds signer key
//  is a hybrid key.
//
VSCF_PUBLIC bool
vscf_key_info_is_compound_hybrid_signer(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return (self->compound_hybrid_signer_first_key_alg_id != vscf_alg_id_NONE) &&
           (self->compound_hybrid_signer_second_key_alg_id != vscf_alg_id_NONE);
}

//
//  Return true if a key is a compound key that contains hybrid keys
//  for encryption/decryption and signing/verifying that itself
//  contains a combination of classic keys and post-quantum keys.
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid_post_quantum(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_key_info_is_hybrid_post_quantum_cipher(self) && vscf_key_info_is_hybrid_post_quantum_signer(self);
}

//
//  Return true if a key is a compound key that contains a hybrid key
//  for encryption/decryption that contains a classic key and
//  a post-quantum key.
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid_post_quantum_cipher(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    const bool is_first_post_quantum =
            (vscf_alg_id_ROUND5_ND_5KEM_5D == self->compound_hybrid_cipher_first_key_alg_id) &&
            (self->compound_hybrid_cipher_first_key_alg_id != self->compound_hybrid_cipher_second_key_alg_id);

    const bool is_second_post_quantum =
            (vscf_alg_id_ROUND5_ND_5KEM_5D == self->compound_hybrid_cipher_second_key_alg_id) &&
            (self->compound_hybrid_cipher_first_key_alg_id != self->compound_hybrid_cipher_second_key_alg_id);

    return vscf_key_info_is_compound_hybrid_signer(self) && (is_first_post_quantum || is_second_post_quantum);
}

//
//  Return true if a key is a compound key that contains a hybrid key
//  for signing/verifying that contains a classic key and
//  a post-quantum key.
//
VSCF_PUBLIC bool
vscf_key_info_is_hybrid_post_quantum_signer(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    const bool is_first_post_quantum =
            (vscf_alg_id_FALCON == self->compound_hybrid_signer_first_key_alg_id) &&
            (self->compound_hybrid_signer_first_key_alg_id != self->compound_hybrid_signer_second_key_alg_id);

    const bool is_second_post_quantum =
            (vscf_alg_id_FALCON == self->compound_hybrid_signer_second_key_alg_id) &&
            (self->compound_hybrid_signer_first_key_alg_id != self->compound_hybrid_signer_second_key_alg_id);

    return vscf_key_info_is_compound_hybrid_signer(self) && (is_first_post_quantum || is_second_post_quantum);
}

//
//  Return common type of the key.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->alg_id;
}

//
//  Return compound's cipher key id, if key is compound.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_cipher_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->compound_cipher_alg_id;
}

//
//  Return compound's signer key id, if key is compound.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_signer_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->compound_signer_alg_id;
}

//
//  Return hybrid's first key id, if key is hybrid.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_hybrid_first_key_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->hybrid_first_key_alg_id;
}

//
//  Return hybrid's second key id, if key is hybrid.
//  Return None, otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_hybrid_second_key_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->hybrid_second_key_alg_id;
}

//
//  Return hybrid's first key id of compound's cipher key,
//  if key is compound(hybrid, ...), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_cipher_first_key_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->compound_hybrid_cipher_first_key_alg_id;
}

//
//  Return hybrid's second key id of compound's cipher key,
//  if key is compound(hybrid, ...), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_cipher_second_key_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->compound_hybrid_cipher_second_key_alg_id;
}

//
//  Return hybrid's first key id of compound's signer key,
//  if key is compound(..., hybrid), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_signer_first_key_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->compound_hybrid_signer_first_key_alg_id;
}

//
//  Return hybrid's second key id of compound's signer key,
//  if key is compound(..., hybrid), None - otherwise.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_info_compound_hybrid_signer_second_key_alg_id(const vscf_key_info_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->compound_hybrid_signer_second_key_alg_id;
}
