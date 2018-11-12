//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include "vscr_virgil_ratchet_fake_rng_internal.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_virgil_ratchet_fake_rng_impl.h"
#include "vscr_ratchet_rng.h"
#include "vscr_ratchet_rng_api.h"
#include "vscr_impl.h"
#include "vscr_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscr_api_t *
vscr_virgil_ratchet_fake_rng_find_api(vscr_api_tag_t api_tag);

//
//  Configuration of the interface API 'ratchet rng api'.
//
static const vscr_ratchet_rng_api_t ratchet_rng_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'ratchet_rng' MUST be equal to the 'vscr_api_tag_RATCHET_RNG'.
    //
    vscr_api_tag_RATCHET_RNG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscr_impl_tag_VIRGIL_RATCHET_FAKE_RNG,
    //
    //  Interface for ratchet rng
    //
    (vscr_ratchet_rng_api_generate_random_data_fn)vscr_virgil_ratchet_fake_rng_generate_random_data
};

//
//  Compile-time known information about 'virgil ratchet fake rng' implementation.
//
static const vscr_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscr_impl_tag_VIRGIL_RATCHET_FAKE_RNG,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscr_virgil_ratchet_fake_rng_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscr_impl_cleanup_fn)vscr_virgil_ratchet_fake_rng_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscr_impl_delete_fn)vscr_virgil_ratchet_fake_rng_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_init(vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl) {

    VSCR_ASSERT_PTR(virgil_ratchet_fake_rng_impl);

    vscr_zeroize(virgil_ratchet_fake_rng_impl, sizeof(vscr_virgil_ratchet_fake_rng_impl_t));

    virgil_ratchet_fake_rng_impl->info = &info;
    virgil_ratchet_fake_rng_impl->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscr_virgil_ratchet_fake_rng_init()'.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_cleanup(vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl) {

    if (virgil_ratchet_fake_rng_impl == NULL || virgil_ratchet_fake_rng_impl->info == NULL) {
        return;
    }

    if (virgil_ratchet_fake_rng_impl->refcnt == 0) {
        return;
    }

    if (--virgil_ratchet_fake_rng_impl->refcnt > 0) {
        return;
    }

    vscr_zeroize(virgil_ratchet_fake_rng_impl, sizeof(vscr_virgil_ratchet_fake_rng_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCR_PUBLIC vscr_virgil_ratchet_fake_rng_impl_t *
vscr_virgil_ratchet_fake_rng_new(void) {

    vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl = (vscr_virgil_ratchet_fake_rng_impl_t *) vscr_alloc(sizeof (vscr_virgil_ratchet_fake_rng_impl_t));
    VSCR_ASSERT_ALLOC(virgil_ratchet_fake_rng_impl);

    vscr_virgil_ratchet_fake_rng_init(virgil_ratchet_fake_rng_impl);

    return virgil_ratchet_fake_rng_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscr_virgil_ratchet_fake_rng_new()'.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_delete(vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl) {

    vscr_virgil_ratchet_fake_rng_cleanup(virgil_ratchet_fake_rng_impl);

    if (virgil_ratchet_fake_rng_impl && (virgil_ratchet_fake_rng_impl->refcnt == 0)) {
        vscr_dealloc(virgil_ratchet_fake_rng_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscr_virgil_ratchet_fake_rng_new()'.
//  Given reference is nullified.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_destroy(vscr_virgil_ratchet_fake_rng_impl_t **virgil_ratchet_fake_rng_impl_ref) {

    VSCR_ASSERT_PTR(virgil_ratchet_fake_rng_impl_ref);

    vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl = *virgil_ratchet_fake_rng_impl_ref;
    *virgil_ratchet_fake_rng_impl_ref = NULL;

    vscr_virgil_ratchet_fake_rng_delete(virgil_ratchet_fake_rng_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCR_PUBLIC vscr_virgil_ratchet_fake_rng_impl_t *
vscr_virgil_ratchet_fake_rng_copy(vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl) {

    // Proxy to the parent implementation.
    return (vscr_virgil_ratchet_fake_rng_impl_t *)vscr_impl_copy((vscr_impl_t *)virgil_ratchet_fake_rng_impl);
}

//
//  Return size of 'vscr_virgil_ratchet_fake_rng_impl_t' type.
//
VSCR_PUBLIC size_t
vscr_virgil_ratchet_fake_rng_impl_size(void) {

    return sizeof (vscr_virgil_ratchet_fake_rng_impl_t);
}

//
//  Cast to the 'vscr_impl_t' type.
//
VSCR_PUBLIC vscr_impl_t *
vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_impl_t *virgil_ratchet_fake_rng_impl) {

    VSCR_ASSERT_PTR(virgil_ratchet_fake_rng_impl);
    return (vscr_impl_t *)(virgil_ratchet_fake_rng_impl);
}

static const vscr_api_t *
vscr_virgil_ratchet_fake_rng_find_api(vscr_api_tag_t api_tag) {

    switch(api_tag) {
        case vscr_api_tag_RATCHET_RNG:
            return (const vscr_api_t *) &ratchet_rng_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
