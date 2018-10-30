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

#include "vscf_platform_entropy_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_platform_entropy.h"
#include "vscf_platform_entropy_impl.h"
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
vscf_platform_entropy_find_api(vscf_api_tag_t api_tag);

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
    vscf_impl_tag_PLATFORM_ENTROPY,
    //
    //  Defines that implemented source is strong.
    //
    (vscf_entropy_source_api_is_strong_fn)vscf_platform_entropy_is_strong,
    //
    //  Provide gathered entropy of the requested length.
    //
    (vscf_entropy_source_api_provide_fn)vscf_platform_entropy_provide
};

//
//  Compile-time known information about 'platform entropy' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_PLATFORM_ENTROPY,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_platform_entropy_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_platform_entropy_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_platform_entropy_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_platform_entropy_init(vscf_platform_entropy_impl_t *platform_entropy_impl) {

    VSCF_ASSERT_PTR(platform_entropy_impl);

    vscf_zeroize(platform_entropy_impl, sizeof(vscf_platform_entropy_impl_t));

    platform_entropy_impl->info = &info;
    platform_entropy_impl->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_platform_entropy_init()'.
//
VSCF_PUBLIC void
vscf_platform_entropy_cleanup(vscf_platform_entropy_impl_t *platform_entropy_impl) {

    if (platform_entropy_impl == NULL || platform_entropy_impl->info == NULL) {
        return;
    }

    if (platform_entropy_impl->refcnt == 0) {
        return;
    }

    if (--platform_entropy_impl->refcnt > 0) {
        return;
    }

    vscf_zeroize(platform_entropy_impl, sizeof(vscf_platform_entropy_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_platform_entropy_impl_t *
vscf_platform_entropy_new(void) {

    vscf_platform_entropy_impl_t *platform_entropy_impl = (vscf_platform_entropy_impl_t *) vscf_alloc(sizeof (vscf_platform_entropy_impl_t));
    VSCF_ASSERT_ALLOC(platform_entropy_impl);

    vscf_platform_entropy_init(platform_entropy_impl);

    return platform_entropy_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_platform_entropy_new()'.
//
VSCF_PUBLIC void
vscf_platform_entropy_delete(vscf_platform_entropy_impl_t *platform_entropy_impl) {

    vscf_platform_entropy_cleanup(platform_entropy_impl);

    if (platform_entropy_impl && (platform_entropy_impl->refcnt == 0)) {
        vscf_dealloc(platform_entropy_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_platform_entropy_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_platform_entropy_destroy(vscf_platform_entropy_impl_t **platform_entropy_impl_ref) {

    VSCF_ASSERT_PTR(platform_entropy_impl_ref);

    vscf_platform_entropy_impl_t *platform_entropy_impl = *platform_entropy_impl_ref;
    *platform_entropy_impl_ref = NULL;

    vscf_platform_entropy_delete(platform_entropy_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_platform_entropy_impl_t *
vscf_platform_entropy_copy(vscf_platform_entropy_impl_t *platform_entropy_impl) {

    // Proxy to the parent implementation.
    return (vscf_platform_entropy_impl_t *)vscf_impl_copy((vscf_impl_t *)platform_entropy_impl);
}

//
//  Return size of 'vscf_platform_entropy_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_platform_entropy_impl_size(void) {

    return sizeof (vscf_platform_entropy_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_platform_entropy_impl(vscf_platform_entropy_impl_t *platform_entropy_impl) {

    VSCF_ASSERT_PTR(platform_entropy_impl);
    return (vscf_impl_t *)(platform_entropy_impl);
}

static const vscf_api_t *
vscf_platform_entropy_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ENTROPY_SOURCE:
            return (const vscf_api_t *) &entropy_source_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
