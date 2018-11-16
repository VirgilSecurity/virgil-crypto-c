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

#include "vscf_ctr_drbg_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ctr_drbg_impl.h"
#include "vscf_random.h"
#include "vscf_random_api.h"
#include "vscf_entropy_source.h"
#include "vscf_impl.h"
#include "vscf_error.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  This method is called when interface 'entropy source' was setup.
//
VSCF_PRIVATE vscf_error_t
vscf_ctr_drbg_did_setup_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  This method is called when interface 'entropy source' was released.
//
VSCF_PRIVATE void
vscf_ctr_drbg_did_release_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

static const vscf_api_t *
vscf_ctr_drbg_find_api(vscf_api_tag_t api_tag);

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
    //  Generate random bytes.
    //
    (vscf_random_api_random_fn)vscf_ctr_drbg_random,
    //
    //  Retreive new seed data from the entropy sources.
    //
    (vscf_random_api_reseed_fn)vscf_ctr_drbg_reseed
};

//
//  Compile-time known information about 'ctr drbg' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_ctr_drbg_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_ctr_drbg_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_ctr_drbg_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ctr_drbg_init(vscf_ctr_drbg_impl_t *ctr_drbg_impl) {

    VSCF_ASSERT_PTR(ctr_drbg_impl);

    vscf_zeroize(ctr_drbg_impl, sizeof(vscf_ctr_drbg_impl_t));

    ctr_drbg_impl->info = &info;
    ctr_drbg_impl->refcnt = 1;

    vscf_ctr_drbg_init_ctx(ctr_drbg_impl);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ctr_drbg_init()'.
//
VSCF_PUBLIC void
vscf_ctr_drbg_cleanup(vscf_ctr_drbg_impl_t *ctr_drbg_impl) {

    if (ctr_drbg_impl == NULL || ctr_drbg_impl->info == NULL) {
        return;
    }

    if (ctr_drbg_impl->refcnt == 0) {
        return;
    }

    if (--ctr_drbg_impl->refcnt > 0) {
        return;
    }

    vscf_ctr_drbg_release_entropy_source(ctr_drbg_impl);

    vscf_ctr_drbg_cleanup_ctx(ctr_drbg_impl);

    vscf_zeroize(ctr_drbg_impl, sizeof(vscf_ctr_drbg_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ctr_drbg_impl_t *
vscf_ctr_drbg_new(void) {

    vscf_ctr_drbg_impl_t *ctr_drbg_impl = (vscf_ctr_drbg_impl_t *) vscf_alloc(sizeof (vscf_ctr_drbg_impl_t));
    VSCF_ASSERT_ALLOC(ctr_drbg_impl);

    vscf_ctr_drbg_init(ctr_drbg_impl);

    return ctr_drbg_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ctr_drbg_new()'.
//
VSCF_PUBLIC void
vscf_ctr_drbg_delete(vscf_ctr_drbg_impl_t *ctr_drbg_impl) {

    vscf_ctr_drbg_cleanup(ctr_drbg_impl);

    if (ctr_drbg_impl && (ctr_drbg_impl->refcnt == 0)) {
        vscf_dealloc(ctr_drbg_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ctr_drbg_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ctr_drbg_destroy(vscf_ctr_drbg_impl_t **ctr_drbg_impl_ref) {

    VSCF_ASSERT_PTR(ctr_drbg_impl_ref);

    vscf_ctr_drbg_impl_t *ctr_drbg_impl = *ctr_drbg_impl_ref;
    *ctr_drbg_impl_ref = NULL;

    vscf_ctr_drbg_delete(ctr_drbg_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_ctr_drbg_impl_t *
vscf_ctr_drbg_copy(vscf_ctr_drbg_impl_t *ctr_drbg_impl) {

    // Proxy to the parent implementation.
    return (vscf_ctr_drbg_impl_t *)vscf_impl_copy((vscf_impl_t *)ctr_drbg_impl);
}

//
//  Return size of 'vscf_ctr_drbg_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_ctr_drbg_impl_size(void) {

    return sizeof (vscf_ctr_drbg_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ctr_drbg_impl(vscf_ctr_drbg_impl_t *ctr_drbg_impl) {

    VSCF_ASSERT_PTR(ctr_drbg_impl);
    return (vscf_impl_t *)(ctr_drbg_impl);
}

//
//  Setup dependency to the interface 'entropy source' with shared ownership.
//
VSCF_PUBLIC vscf_error_t
vscf_ctr_drbg_use_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl, vscf_impl_t *entropy_source) {

    VSCF_ASSERT_PTR(ctr_drbg_impl);
    VSCF_ASSERT_PTR(entropy_source);
    VSCF_ASSERT_PTR(ctr_drbg_impl->entropy_source == NULL);

    VSCF_ASSERT(vscf_entropy_source_is_implemented(entropy_source));

    ctr_drbg_impl->entropy_source = vscf_impl_copy(entropy_source);

    return vscf_ctr_drbg_did_setup_entropy_source(ctr_drbg_impl);
}

//
//  Setup dependency to the interface 'entropy source' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC vscf_error_t
vscf_ctr_drbg_take_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl, vscf_impl_t *entropy_source) {

    VSCF_ASSERT_PTR(ctr_drbg_impl);
    VSCF_ASSERT_PTR(entropy_source);
    VSCF_ASSERT_PTR(ctr_drbg_impl->entropy_source == NULL);

    VSCF_ASSERT(vscf_entropy_source_is_implemented(entropy_source));

    ctr_drbg_impl->entropy_source = entropy_source;

    return vscf_ctr_drbg_did_setup_entropy_source(ctr_drbg_impl);
}

//
//  Release dependency to the interface 'entropy source'.
//
VSCF_PUBLIC void
vscf_ctr_drbg_release_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl) {

    VSCF_ASSERT_PTR(ctr_drbg_impl);

    vscf_impl_destroy(&ctr_drbg_impl->entropy_source);

    vscf_ctr_drbg_did_release_entropy_source(ctr_drbg_impl);
}

static const vscf_api_t *
vscf_ctr_drbg_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
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
