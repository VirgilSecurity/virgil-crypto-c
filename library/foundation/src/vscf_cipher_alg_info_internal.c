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

#include "vscf_cipher_alg_info_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_cipher_alg_info_defs.h"
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
vscf_cipher_alg_info_find_api(vscf_api_tag_t api_tag);

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
    //  Provide algorithm identificator.
    //
    (vscf_alg_info_api_alg_id_fn)vscf_cipher_alg_info_alg_id
};

//
//  Compile-time known information about 'cipher alg info' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_cipher_alg_info_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_cipher_alg_info_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_cipher_alg_info_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_cipher_alg_info_init(vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(cipher_alg_info);

    vscf_zeroize(cipher_alg_info, sizeof(vscf_cipher_alg_info_t));

    cipher_alg_info->info = &info;
    cipher_alg_info->refcnt = 1;

    vscf_cipher_alg_info_init_ctx(cipher_alg_info);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_cipher_alg_info_init()'.
//
VSCF_PUBLIC void
vscf_cipher_alg_info_cleanup(vscf_cipher_alg_info_t *cipher_alg_info) {

    if (cipher_alg_info == NULL || cipher_alg_info->info == NULL) {
        return;
    }

    if (cipher_alg_info->refcnt == 0) {
        return;
    }

    if (--cipher_alg_info->refcnt > 0) {
        return;
    }

    vscf_cipher_alg_info_cleanup_ctx(cipher_alg_info);

    vscf_zeroize(cipher_alg_info, sizeof(vscf_cipher_alg_info_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_cipher_alg_info_t *
vscf_cipher_alg_info_new(void) {

    vscf_cipher_alg_info_t *cipher_alg_info = (vscf_cipher_alg_info_t *) vscf_alloc(sizeof (vscf_cipher_alg_info_t));
    VSCF_ASSERT_ALLOC(cipher_alg_info);

    vscf_cipher_alg_info_init(cipher_alg_info);

    return cipher_alg_info;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_cipher_alg_info_new()'.
//
VSCF_PUBLIC void
vscf_cipher_alg_info_delete(vscf_cipher_alg_info_t *cipher_alg_info) {

    vscf_cipher_alg_info_cleanup(cipher_alg_info);

    if (cipher_alg_info && (cipher_alg_info->refcnt == 0)) {
        vscf_dealloc(cipher_alg_info);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_cipher_alg_info_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_cipher_alg_info_destroy(vscf_cipher_alg_info_t **cipher_alg_info_ref) {

    VSCF_ASSERT_PTR(cipher_alg_info_ref);

    vscf_cipher_alg_info_t *cipher_alg_info = *cipher_alg_info_ref;
    *cipher_alg_info_ref = NULL;

    vscf_cipher_alg_info_delete(cipher_alg_info);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_cipher_alg_info_t *
vscf_cipher_alg_info_shallow_copy(vscf_cipher_alg_info_t *cipher_alg_info) {

    // Proxy to the parent implementation.
    return (vscf_cipher_alg_info_t *)vscf_impl_shallow_copy((vscf_impl_t *)cipher_alg_info);
}

//
//  Return size of 'vscf_cipher_alg_info_t' type.
//
VSCF_PUBLIC size_t
vscf_cipher_alg_info_impl_size(void) {

    return sizeof (vscf_cipher_alg_info_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_cipher_alg_info_impl(vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(cipher_alg_info);
    return (vscf_impl_t *)(cipher_alg_info);
}

static const vscf_api_t *
vscf_cipher_alg_info_find_api(vscf_api_tag_t api_tag) {

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
