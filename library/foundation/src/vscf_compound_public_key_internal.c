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


//  @description
// --------------------------------------------------------------------------
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_compound_public_key_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_compound_public_key_defs.h"
#include "vscf_key.h"
#include "vscf_key_api.h"
#include "vscf_public_key.h"
#include "vscf_public_key_api.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_compound_public_key_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'key api'.
//
static const vscf_key_api_t key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key' MUST be equal to the 'vscf_api_tag_KEY'.
    //
    vscf_api_tag_KEY,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_COMPOUND_PUBLIC_KEY,
    //
    //  Algorithm identifier the key belongs to.
    //
    (vscf_key_api_alg_id_fn)vscf_compound_public_key_alg_id,
    //
    //  Return algorithm information that can be used for serialization.
    //
    (vscf_key_api_alg_info_fn)vscf_compound_public_key_alg_info,
    //
    //  Length of the key in bytes.
    //
    (vscf_key_api_len_fn)vscf_compound_public_key_len,
    //
    //  Length of the key in bits.
    //
    (vscf_key_api_bitlen_fn)vscf_compound_public_key_bitlen,
    //
    //  Return tag of an associated algorithm that can handle this key.
    //
    (vscf_key_api_impl_tag_fn)vscf_compound_public_key_impl_tag,
    //
    //  Check that key is valid.
    //  Note, this operation can be slow.
    //
    (vscf_key_api_is_valid_fn)vscf_compound_public_key_is_valid
};

//
//  Configuration of the interface API 'public key api'.
//
static const vscf_public_key_api_t public_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'public_key' MUST be equal to the 'vscf_api_tag_PUBLIC_KEY'.
    //
    vscf_api_tag_PUBLIC_KEY,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_COMPOUND_PUBLIC_KEY,
    //
    //  Link to the inherited interface API 'key'.
    //
    &key_api
};

//
//  Compile-time known information about 'compound public key' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_COMPOUND_PUBLIC_KEY,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_compound_public_key_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_compound_public_key_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_compound_public_key_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_compound_public_key_init(vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_compound_public_key_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_compound_public_key_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_compound_public_key_init()'.
//
VSCF_PUBLIC void
vscf_compound_public_key_cleanup(vscf_compound_public_key_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_compound_public_key_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_compound_public_key_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_compound_public_key_t *
vscf_compound_public_key_new(void) {

    vscf_compound_public_key_t *self = (vscf_compound_public_key_t *) vscf_alloc(sizeof (vscf_compound_public_key_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_compound_public_key_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_compound_public_key_new()'.
//
VSCF_PUBLIC void
vscf_compound_public_key_delete(vscf_compound_public_key_t *self) {

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

    vscf_compound_public_key_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_compound_public_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_compound_public_key_destroy(vscf_compound_public_key_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_compound_public_key_t *self = *self_ref;
    *self_ref = NULL;

    vscf_compound_public_key_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_compound_public_key_t *
vscf_compound_public_key_shallow_copy(vscf_compound_public_key_t *self) {

    // Proxy to the parent implementation.
    return (vscf_compound_public_key_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Perform initialization of pre-allocated context.
//  Create compound public key with an encryption public key and
//  a verifying public key.
//
//  Note, keys ownership is transferred.
//
VSCF_PRIVATE void
vscf_compound_public_key_init_with_members(vscf_compound_public_key_t *self, const vscf_impl_t *alg_info,
        vscf_impl_t **encryption_key_ref, vscf_impl_t **verifying_key_ref) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_compound_public_key_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_compound_public_key_init_ctx_with_members(self, alg_info, encryption_key_ref, verifying_key_ref);
}

//
//  Allocate implementation context and perform it's initialization.
//  Create compound public key with an encryption public key and
//  a verifying public key.
//
//  Note, keys ownership is transferred.
//
VSCF_PRIVATE vscf_compound_public_key_t *
vscf_compound_public_key_new_with_members(const vscf_impl_t *alg_info, vscf_impl_t **encryption_key_ref,
        vscf_impl_t **verifying_key_ref) {

    vscf_compound_public_key_t *self = vscf_compound_public_key_new();

    vscf_compound_public_key_init_with_members(self, alg_info, encryption_key_ref, verifying_key_ref);

    return self;
}

//
//  Returns instance of the implemented interface 'public key'.
//
VSCF_PUBLIC const vscf_public_key_api_t *
vscf_compound_public_key_public_key_api(void) {

    return &public_key_api;
}

//
//  Return size of 'vscf_compound_public_key_t' type.
//
VSCF_PUBLIC size_t
vscf_compound_public_key_impl_size(void) {

    return sizeof (vscf_compound_public_key_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_public_key_impl(vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_public_key_impl_const(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_compound_public_key_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_KEY:
            return (const vscf_api_t *) &key_api;
        case vscf_api_tag_PUBLIC_KEY:
            return (const vscf_api_t *) &public_key_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
