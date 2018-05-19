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

#include "vsf_sha384_internal.h"
#include "vsf_memory.h"
#include "vsf_assert.h"
#include "vsf_sha384.h"
#include "vsf_sha384_impl.h"
#include "vsf_hash_info_api.h"
#include "vsf_hash_api.h"
#include "vsf_hash_stream_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'hash info api'.
//
static const vsf_hash_info_api_t hash_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_info' MUST be equal to the 'vsf_api_tag_HASH_INFO'.
    //
    vsf_api_tag_HASH_INFO,
    //
    //  Size of the digest (hashing output).
    //
    vsf_sha384_DIGEST_SIZE
};

//
//  Configuration of the interface API 'hash api'.
//
static const vsf_hash_api_t hash_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash' MUST be equal to the 'vsf_api_tag_HASH'.
    //
    vsf_api_tag_HASH,
    //
    //  Link to the inherited interface API 'hash info'.
    //
    &hash_info_api,
    //
    //  Calculate hash over given data.
    //
    (vsf_hash_api_hash_fn) vsf_sha384_hash
};

//
//  Configuration of the interface API 'hash stream api'.
//
static const vsf_hash_stream_api_t hash_stream_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_stream' MUST be equal to the 'vsf_api_tag_HASH_STREAM'.
    //
    vsf_api_tag_HASH_STREAM,
    //
    //  Link to the inherited interface API 'hash info'.
    //
    &hash_info_api,
    //
    //  Start a new hashing.
    //
    (vsf_hash_stream_api_start_fn) vsf_sha384_start,
    //
    //  Add given data to the hash.
    //
    (vsf_hash_stream_api_update_fn) vsf_sha384_update,
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    (vsf_hash_stream_api_finish_fn) vsf_sha384_finish
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vsf_api_t* api_array[] = {
    (const vsf_api_t*) &hash_info_api,
    (const vsf_api_t*) &hash_api,
    (const vsf_api_t*) &hash_stream_api,
    NULL
};

//
//  Compile-time known information about 'sha384' implementation.
//
static const vsf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_SHA384,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vsf_impl_cleanup_fn) vsf_sha384_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vsf_impl_destroy_fn) vsf_sha384_destroy
};

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC void
vsf_sha384_init (vsf_sha384_impl_t* sha384_impl) {

    VSF_ASSERT_PTR (sha384_impl);
    VSF_ASSERT_PTR (sha384_impl->info == NULL);

    sha384_impl->info = &info;

    vsf_sha384_init_ctx (sha384_impl);
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_sha384_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_sha384_cleanup (vsf_sha384_impl_t* sha384_impl) {

    VSF_ASSERT_PTR (sha384_impl);

    if (sha384_impl->info == NULL) {
        return;
    }

    vsf_sha384_cleanup_ctx (sha384_impl);

    sha384_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_sha384_impl_t*
vsf_sha384_new (void) {

    vsf_sha384_impl_t *sha384_impl = (vsf_sha384_impl_t *) vsf_alloc (sizeof (vsf_sha384_impl_t));
    VSF_ASSERT_PTR (sha384_impl);

    vsf_sha384_init (sha384_impl);

    return sha384_impl;
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_sha384_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_sha384_destroy (vsf_sha384_impl_t** sha384_impl_ref) {

    VSF_ASSERT_PTR (sha384_impl_ref);

    vsf_sha384_impl_t *sha384_impl = *sha384_impl_ref;
    *sha384_impl_ref = NULL;

    if (sha384_impl) {
        vsf_sha384_cleanup (sha384_impl);
        vsf_dealloc (sha384_impl);
    }
}

//
//  Returns instance of the implemented interface 'hash info'.
//
VSF_PUBLIC const vsf_hash_info_api_t*
vsf_sha384_hash_info_api (void) {

    return &hash_info_api;
}

//
//  Returns instance of the implemented interface 'hash'.
//
VSF_PUBLIC const vsf_hash_api_t*
vsf_sha384_hash_api (void) {

    return &hash_api;
}

//
//  Returns instance of the implemented interface 'hash stream'.
//
VSF_PUBLIC const vsf_hash_stream_api_t*
vsf_sha384_hash_stream_api (void) {

    return &hash_stream_api;
}

//
//  Return size of 'vsf_sha384_impl_t' type.
//
VSF_PUBLIC size_t
vsf_sha384_impl_size (void) {

    return sizeof (vsf_sha384_impl_t);
}

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_sha384_impl (vsf_sha384_impl_t* sha384_impl) {

    VSF_ASSERT_PTR (sha384_impl);
    return (vsf_impl_t *) (sha384_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
