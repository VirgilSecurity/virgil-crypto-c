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
#include "vscf_sha512.h"
#include "vscf_sha512_impl.h"
#include "vscf_hash_info_api.h"
#include "vscf_hash_api.h"
#include "vscf_hash_stream_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'hash info api'.
//
static const vscf_hash_info_api_t hash_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_info' MUST be equal to the 'vscf_api_tag_HASH_INFO'.
    //
    vscf_api_tag_HASH_INFO,
    //
    //  Size of the digest (hashing output).
    //
    vscf_sha512_DIGEST_SIZE
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
    //  Link to the inherited interface API 'hash info'.
    //
    &hash_info_api,
    //
    //  Calculate hash over given data.
    //
    (vscf_hash_api_hash_fn)vscf_sha512_hash
};

//
//  Configuration of the interface API 'hash stream api'.
//
static const vscf_hash_stream_api_t hash_stream_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_stream' MUST be equal to the 'vscf_api_tag_HASH_STREAM'.
    //
    vscf_api_tag_HASH_STREAM,
    //
    //  Link to the inherited interface API 'hash info'.
    //
    &hash_info_api,
    //
    //  Start a new hashing.
    //
    (vscf_hash_stream_api_start_fn)vscf_sha512_start,
    //
    //  Add given data to the hash.
    //
    (vscf_hash_stream_api_update_fn)vscf_sha512_update,
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    (vscf_hash_stream_api_finish_fn)vscf_sha512_finish
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vscf_api_t *api_array[] = {
    (const vscf_api_t *)&hash_info_api,
    (const vscf_api_t *)&hash_api,
    (const vscf_api_t *)&hash_stream_api,
    NULL
};

//
//  Compile-time known information about 'sha512' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_SHA512,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
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
VSCF_PUBLIC vscf_error_t
vscf_sha512_init(vscf_sha512_impl_t *sha512_impl) {

    VSCF_ASSERT_PTR (sha512_impl);
    VSCF_ASSERT_PTR (sha512_impl->info == NULL);

    sha512_impl->info = &info;

    return vscf_sha512_init_ctx (sha512_impl);
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_init ()'.
//  All dependencies that is under ownership will be destroyed.
//  All dependencies that is not under ownership will untouched.
//
VSCF_PUBLIC void
vscf_sha512_cleanup(vscf_sha512_impl_t *sha512_impl) {

    VSCF_ASSERT_PTR (sha512_impl);

    if (sha512_impl->info == NULL) {
        return;
    }

    vscf_sha512_cleanup_ctx (sha512_impl);

    sha512_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_sha512_impl_t *
vscf_sha512_new(void) {

    vscf_sha512_impl_t *sha512_impl = (vscf_sha512_impl_t *) vscf_alloc (sizeof (vscf_sha512_impl_t));
    if (NULL == sha512_impl) {
        return NULL;
    }

    if (vscf_sha512_init (sha512_impl) != vscf_SUCCESS) {
        vscf_dealloc(sha512_impl);
        return NULL;
    }

    return sha512_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_sha512_delete(vscf_sha512_impl_t *sha512_impl) {

    if (sha512_impl) {
        vscf_sha512_cleanup (sha512_impl);
        vscf_dealloc (sha512_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_sha512_destroy(vscf_sha512_impl_t **sha512_impl_ref) {

    VSCF_ASSERT_PTR (sha512_impl_ref);

    vscf_sha512_impl_t *sha512_impl = *sha512_impl_ref;
    *sha512_impl_ref = NULL;

    vscf_sha512_delete (sha512_impl);
}

//
//  Returns instance of the implemented interface 'hash info'.
//
VSCF_PUBLIC const vscf_hash_info_api_t *
vscf_sha512_hash_info_api(void) {

    return &hash_info_api;
}

//
//  Returns instance of the implemented interface 'hash'.
//
VSCF_PUBLIC const vscf_hash_api_t *
vscf_sha512_hash_api(void) {

    return &hash_api;
}

//
//  Return size of 'vscf_sha512_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_sha512_impl_size(void) {

    return sizeof (vscf_sha512_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha512_impl(vscf_sha512_impl_t *sha512_impl) {

    VSCF_ASSERT_PTR (sha512_impl);
    return (vscf_impl_t *) (sha512_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
