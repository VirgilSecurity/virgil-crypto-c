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

#include "vscf_hybrid_key_alg_info_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_hybrid_key_alg_info_defs.h"
#include "vscf_alg_info.h"
#include "vscf_alg_info_api.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_hybrid_key_alg_info_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg info api'.
//
static const vscf_alg_info_api_t alg_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg_info' MUST be equal to the 'vscf_api_tag_ALG_INFO'.
    //
    vscf_api_tag_ALG_INFO,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_HYBRID_KEY_ALG_INFO,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_info_api_alg_id_fn)vscf_hybrid_key_alg_info_alg_id
};

//
//  Compile-time known information about 'hybrid key alg info' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_HYBRID_KEY_ALG_INFO,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_hybrid_key_alg_info_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_hybrid_key_alg_info_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_hybrid_key_alg_info_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_info_init(vscf_hybrid_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_hybrid_key_alg_info_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_hybrid_key_alg_info_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_hybrid_key_alg_info_init()'.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_info_cleanup(vscf_hybrid_key_alg_info_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_hybrid_key_alg_info_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_hybrid_key_alg_info_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_hybrid_key_alg_info_t *
vscf_hybrid_key_alg_info_new(void) {

    vscf_hybrid_key_alg_info_t *self = (vscf_hybrid_key_alg_info_t *) vscf_alloc(sizeof (vscf_hybrid_key_alg_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_hybrid_key_alg_info_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hybrid_key_alg_info_new()'.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_info_delete(vscf_hybrid_key_alg_info_t *self) {

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

    vscf_hybrid_key_alg_info_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hybrid_key_alg_info_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_info_destroy(vscf_hybrid_key_alg_info_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_hybrid_key_alg_info_t *self = *self_ref;
    *self_ref = NULL;

    vscf_hybrid_key_alg_info_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_hybrid_key_alg_info_t *
vscf_hybrid_key_alg_info_shallow_copy(vscf_hybrid_key_alg_info_t *self) {

    // Proxy to the parent implementation.
    return (vscf_hybrid_key_alg_info_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Perform initialization of pre-allocated context.
//  Create hybrid algorithm information.
//
//  Note, keys ownership is preserved.
//
VSCF_PRIVATE void
vscf_hybrid_key_alg_info_init_with_infos(vscf_hybrid_key_alg_info_t *self, vscf_alg_id_t alg_id,
        const vscf_impl_t *first_key_alg_info, const vscf_impl_t *second_key_alg_info) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_hybrid_key_alg_info_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_hybrid_key_alg_info_init_ctx_with_infos(self, alg_id, first_key_alg_info, second_key_alg_info);
}

//
//  Allocate implementation context and perform it's initialization.
//  Create hybrid algorithm information.
//
//  Note, keys ownership is preserved.
//
VSCF_PRIVATE vscf_hybrid_key_alg_info_t *
vscf_hybrid_key_alg_info_new_with_infos(vscf_alg_id_t alg_id, const vscf_impl_t *first_key_alg_info,
        const vscf_impl_t *second_key_alg_info) {

    vscf_hybrid_key_alg_info_t *self = vscf_hybrid_key_alg_info_new();

    vscf_hybrid_key_alg_info_init_with_infos(self, alg_id, first_key_alg_info, second_key_alg_info);

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create hybrid algorithm information.
//
//  Note, keys ownership is transferred.
//
VSCF_PRIVATE void
vscf_hybrid_key_alg_info_init_with_infos_disown(vscf_hybrid_key_alg_info_t *self, vscf_alg_id_t alg_id,
        vscf_impl_t **first_key_alg_info_ref, vscf_impl_t **second_key_alg_info_ref) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_hybrid_key_alg_info_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_hybrid_key_alg_info_init_ctx_with_infos_disown(self, alg_id, first_key_alg_info_ref, second_key_alg_info_ref);
}

//
//  Allocate implementation context and perform it's initialization.
//  Create hybrid algorithm information.
//
//  Note, keys ownership is transferred.
//
VSCF_PRIVATE vscf_hybrid_key_alg_info_t *
vscf_hybrid_key_alg_info_new_with_infos_disown(vscf_alg_id_t alg_id, vscf_impl_t **first_key_alg_info_ref,
        vscf_impl_t **second_key_alg_info_ref) {

    vscf_hybrid_key_alg_info_t *self = vscf_hybrid_key_alg_info_new();

    vscf_hybrid_key_alg_info_init_with_infos_disown(self, alg_id, first_key_alg_info_ref, second_key_alg_info_ref);

    return self;
}

//
//  Return size of 'vscf_hybrid_key_alg_info_t' type.
//
VSCF_PUBLIC size_t
vscf_hybrid_key_alg_info_impl_size(void) {

    return sizeof (vscf_hybrid_key_alg_info_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hybrid_key_alg_info_impl(vscf_hybrid_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_hybrid_key_alg_info_impl_const(const vscf_hybrid_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_hybrid_key_alg_info_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG_INFO:
            return (const vscf_api_t *) &alg_info_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
