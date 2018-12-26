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

#include "vscf_pbkdf1_alg_info_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_pbkdf1_alg_info_impl.h"
#include "vscf_alg_info.h"
#include "vscf_alg_info_api.h"
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
vscf_pbkdf1_alg_info_find_api(vscf_api_tag_t api_tag);

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
    //  Define KDF algorithm type
    //
    vscf_pbkdf1_alg_info_ALG_TYPE_ID
};

//
//  Compile-time known information about 'pbkdf1 alg info' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_pbkdf1_alg_info_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_pbkdf1_alg_info_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_pbkdf1_alg_info_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_pbkdf1_alg_info_init(vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl) {

    VSCF_ASSERT_PTR(pbkdf1_alg_info_impl);

    vscf_zeroize(pbkdf1_alg_info_impl, sizeof(vscf_pbkdf1_alg_info_impl_t));

    pbkdf1_alg_info_impl->info = &info;
    pbkdf1_alg_info_impl->refcnt = 1;

    vscf_pbkdf1_alg_info_init_ctx(pbkdf1_alg_info_impl);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_pbkdf1_alg_info_init()'.
//
VSCF_PUBLIC void
vscf_pbkdf1_alg_info_cleanup(vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl) {

    if (pbkdf1_alg_info_impl == NULL || pbkdf1_alg_info_impl->info == NULL) {
        return;
    }

    if (pbkdf1_alg_info_impl->refcnt == 0) {
        return;
    }

    if (--pbkdf1_alg_info_impl->refcnt > 0) {
        return;
    }

    vscf_pbkdf1_alg_info_cleanup_ctx(pbkdf1_alg_info_impl);

    vscf_zeroize(pbkdf1_alg_info_impl, sizeof(vscf_pbkdf1_alg_info_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_pbkdf1_alg_info_impl_t *
vscf_pbkdf1_alg_info_new(void) {

    vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl = (vscf_pbkdf1_alg_info_impl_t *) vscf_alloc(sizeof (vscf_pbkdf1_alg_info_impl_t));
    VSCF_ASSERT_ALLOC(pbkdf1_alg_info_impl);

    vscf_pbkdf1_alg_info_init(pbkdf1_alg_info_impl);

    return pbkdf1_alg_info_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pbkdf1_alg_info_new()'.
//
VSCF_PUBLIC void
vscf_pbkdf1_alg_info_delete(vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl) {

    vscf_pbkdf1_alg_info_cleanup(pbkdf1_alg_info_impl);

    if (pbkdf1_alg_info_impl && (pbkdf1_alg_info_impl->refcnt == 0)) {
        vscf_dealloc(pbkdf1_alg_info_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pbkdf1_alg_info_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_pbkdf1_alg_info_destroy(vscf_pbkdf1_alg_info_impl_t **pbkdf1_alg_info_impl_ref) {

    VSCF_ASSERT_PTR(pbkdf1_alg_info_impl_ref);

    vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl = *pbkdf1_alg_info_impl_ref;
    *pbkdf1_alg_info_impl_ref = NULL;

    vscf_pbkdf1_alg_info_delete(pbkdf1_alg_info_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_pbkdf1_alg_info_impl_t *
vscf_pbkdf1_alg_info_copy(vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl) {

    // Proxy to the parent implementation.
    return (vscf_pbkdf1_alg_info_impl_t *)vscf_impl_copy((vscf_impl_t *)pbkdf1_alg_info_impl);
}

//
//  Returns instance of the implemented interface 'alg info'.
//
VSCF_PUBLIC const vscf_alg_info_api_t *
vscf_pbkdf1_alg_info_alg_info_api(void) {

    return &alg_info_api;
}

//
//  Return size of 'vscf_pbkdf1_alg_info_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_pbkdf1_alg_info_impl_size(void) {

    return sizeof (vscf_pbkdf1_alg_info_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pbkdf1_alg_info_impl(vscf_pbkdf1_alg_info_impl_t *pbkdf1_alg_info_impl) {

    VSCF_ASSERT_PTR(pbkdf1_alg_info_impl);
    return (vscf_impl_t *)(pbkdf1_alg_info_impl);
}

static const vscf_api_t *
vscf_pbkdf1_alg_info_find_api(vscf_api_tag_t api_tag) {

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
