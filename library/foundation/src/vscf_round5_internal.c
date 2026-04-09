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

#include "vscf_round5_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_round5_defs.h"
#include "vscf_key_alg.h"
#include "vscf_key_alg_api.h"
#include "vscf_kem.h"
#include "vscf_kem_api.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_round5_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'key alg api'.
//
static const vscf_key_alg_api_t key_alg_api = vscf_api_tag_KEY_ALG;

//
//  Configuration of the interface API 'kem api'.
//
static const vscf_kem_api_t kem_api = vscf_api_tag_KEM;

//
//  Compile-time known information about 'round5' implementation.
//
static const vscf_impl_info_t info = vscf_impl_tag_ROUND5;

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_round5_init(vscf_round5_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_round5_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_round5_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_round5_init()'.
//
VSCF_PUBLIC void
vscf_round5_cleanup(vscf_round5_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_round5_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_round5_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_round5_t *
vscf_round5_new(void) {

    vscf_round5_t *self = (vscf_round5_t *) vscf_alloc(sizeof (vscf_round5_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_round5_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_round5_new()'.
//
VSCF_PUBLIC void
vscf_round5_delete(vscf_round5_t *self) {

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

    vscf_round5_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_round5_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_round5_destroy(vscf_round5_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_round5_t *self = *self_ref;
    *self_ref = NULL;

    vscf_round5_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_round5_t *
vscf_round5_shallow_copy(vscf_round5_t *self) {

    // Proxy to the parent implementation.
    return (vscf_round5_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_round5_t' type.
//
VSCF_PUBLIC size_t
vscf_round5_impl_size(void) {

    return sizeof (vscf_round5_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_impl(vscf_round5_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_round5_impl_const(const vscf_round5_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_round5_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_KEM:
        return (const vscf_api_t *)                 &kem_api;
        case vscf_api_tag_KEY_ALG:
        return (const vscf_api_t *)                 &key_alg_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
