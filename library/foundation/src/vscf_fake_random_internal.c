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

#include "vscf_fake_random_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_fake_random_defs.h"
#include "vscf_random.h"
#include "vscf_random_api.h"
#include "vscf_entropy_source.h"
#include "vscf_entropy_source_api.h"
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
vscf_fake_random_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'random api'.
//
static const vscf_random_api_t random_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'random' MUST be equal to the 'vscf_api_tag_RANDOM'.
    //
    vscf_api_tag_RANDOM,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_FAKE_RANDOM,
    //
    //  Generate random bytes.
    //
    (vscf_random_api_random_fn)vscf_fake_random_random,
    //
    //  Retreive new seed data from the entropy sources.
    //
    (vscf_random_api_reseed_fn)vscf_fake_random_reseed
};

//
//  Configuration of the interface API 'entropy source api'.
//
static const vscf_entropy_source_api_t entropy_source_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'entropy_source' MUST be equal to the 'vscf_api_tag_ENTROPY_SOURCE'.
    //
    vscf_api_tag_ENTROPY_SOURCE,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_FAKE_RANDOM,
    //
    //  Defines that implemented source is strong.
    //
    (vscf_entropy_source_api_is_strong_fn)vscf_fake_random_is_strong,
    //
    //  Gather entropy of the requested length.
    //
    (vscf_entropy_source_api_gather_fn)vscf_fake_random_gather
};

//
//  Compile-time known information about 'fake random' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_FAKE_RANDOM,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_fake_random_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_fake_random_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_fake_random_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_fake_random_init(vscf_fake_random_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_fake_random_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_fake_random_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_fake_random_init()'.
//
VSCF_PUBLIC void
vscf_fake_random_cleanup(vscf_fake_random_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_fake_random_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_fake_random_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_fake_random_t *
vscf_fake_random_new(void) {

    vscf_fake_random_t *self = (vscf_fake_random_t *) vscf_alloc(sizeof (vscf_fake_random_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_fake_random_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_fake_random_new()'.
//
VSCF_PUBLIC void
vscf_fake_random_delete(vscf_fake_random_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    size_t new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    VSCF_ASSERT(old_counter != 0);

    vscf_fake_random_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_fake_random_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_fake_random_destroy(vscf_fake_random_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_fake_random_t *self = *self_ref;
    *self_ref = NULL;

    vscf_fake_random_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_fake_random_t *
vscf_fake_random_shallow_copy(vscf_fake_random_t *self) {

    // Proxy to the parent implementation.
    return (vscf_fake_random_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_fake_random_t' type.
//
VSCF_PUBLIC size_t
vscf_fake_random_impl_size(void) {

    return sizeof (vscf_fake_random_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_fake_random_impl(vscf_fake_random_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_fake_random_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ENTROPY_SOURCE:
            return (const vscf_api_t *) &entropy_source_api;
        case vscf_api_tag_RANDOM:
            return (const vscf_api_t *) &random_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
