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

#include "vscf_sha512_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_sha512_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_hash.h"
#include "vscf_hash_api.h"
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
vscf_sha512_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the 'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_sha512_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_sha512_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_sha512_restore_alg_info
};

//
//  Configuration of the interface API 'hash api'.
//
static const vscf_hash_api_t hash_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash' MUST be equal to the 'vscf_api_tag_HASH'.
    //
    vscf_api_tag_HASH,
    //
    //  Calculate hash over given data.
    //
    (vscf_hash_api_hash_fn)vscf_sha512_hash,
    //
    //  Start a new hashing.
    //
    (vscf_hash_api_start_fn)vscf_sha512_start,
    //
    //  Add given data to the hash.
    //
    (vscf_hash_api_update_fn)vscf_sha512_update,
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    (vscf_hash_api_finish_fn)vscf_sha512_finish,
    //
    //  Length of the digest (hashing output) in bytes.
    //
    vscf_sha512_DIGEST_LEN,
    //
    //  Block length of the digest function in bytes.
    //
    vscf_sha512_BLOCK_LEN
};

//
//  Compile-time known information about 'sha512' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_sha512_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_sha512_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_sha512_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_sha512_init(vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);

    vscf_zeroize(sha512, sizeof(vscf_sha512_t));

    sha512->info = &info;
    sha512->refcnt = 1;

    vscf_sha512_init_ctx(sha512);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_sha512_init()'.
//
VSCF_PUBLIC void
vscf_sha512_cleanup(vscf_sha512_t *sha512) {

    if (sha512 == NULL || sha512->info == NULL) {
        return;
    }

    if (sha512->refcnt == 0) {
        return;
    }

    if (--sha512->refcnt > 0) {
        return;
    }

    vscf_sha512_cleanup_ctx(sha512);

    vscf_zeroize(sha512, sizeof(vscf_sha512_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_sha512_t *
vscf_sha512_new(void) {

    vscf_sha512_t *sha512 = (vscf_sha512_t *) vscf_alloc(sizeof (vscf_sha512_t));
    VSCF_ASSERT_ALLOC(sha512);

    vscf_sha512_init(sha512);

    return sha512;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_new()'.
//
VSCF_PUBLIC void
vscf_sha512_delete(vscf_sha512_t *sha512) {

    vscf_sha512_cleanup(sha512);

    if (sha512 && (sha512->refcnt == 0)) {
        vscf_dealloc(sha512);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_sha512_destroy(vscf_sha512_t **sha512_ref) {

    VSCF_ASSERT_PTR(sha512_ref);

    vscf_sha512_t *sha512 = *sha512_ref;
    *sha512_ref = NULL;

    vscf_sha512_delete(sha512);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_sha512_t *
vscf_sha512_shallow_copy(vscf_sha512_t *sha512) {

    // Proxy to the parent implementation.
    return (vscf_sha512_t *)vscf_impl_shallow_copy((vscf_impl_t *)sha512);
}

//
//  Return size of 'vscf_sha512_t' type.
//
VSCF_PUBLIC size_t
vscf_sha512_impl_size(void) {

    return sizeof (vscf_sha512_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha512_impl(vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);
    return (vscf_impl_t *)(sha512);
}

static const vscf_api_t *
vscf_sha512_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_HASH:
            return (const vscf_api_t *) &hash_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
