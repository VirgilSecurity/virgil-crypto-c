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
//
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_sha256_internal.h"
#include "vsf_assert.h"
#include "vsf_sha256.h"
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
    vsf_sha256_DIGEST_SIZE
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
    (vsf_hash_api_hash_fn) vsf_sha256_hash
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
    (vsf_hash_stream_api_start_fn) vsf_sha256_start,
    //
    //  Add given data to the hash.
    //
    (vsf_hash_stream_api_update_fn) vsf_sha256_update,
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    (vsf_hash_stream_api_finish_fn) vsf_sha256_finish
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
//  Compile-time known information about 'sha256' implementation.
//
static const vsf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_SHA256,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vsf_impl_cleanup_fn) vsf_sha256_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vsf_impl_destroy_fn) vsf_sha256_destroy
};

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC void
vsf_sha256_init (vsf_sha256_impl_t* sha256_impl) {

    //TODO: Implement me.
}

//
//  Allocate implementation context and perform it's initialization.
//  Return NULL if allocation fails.
//
VSF_PUBLIC vsf_sha256_impl_t*
vsf_sha256_new (void) {

    //TODO: Implement me.
}

//
//  Cleanup sensitive data within implementation context.
//  Note, dependencies are cleaned up as well.
//
VSF_PUBLIC void
vsf_sha256_cleanup (vsf_sha256_impl_t* sha256_impl) {

    //TODO: Implement me.
}

//
//  Destroy given implementation context and it's dependencies.
//  This function SHOULD be called even if context was statically allocated,
//  because it automatically detect this fact for context itself and
//  dependencies as well and destroy them appropriately.
//
VSF_PUBLIC void
vsf_sha256_destroy (vsf_sha256_impl_t** sha256_impl_ref) {

    //TODO: Implement me.
}

//
//  Return size of 'vsf_sha256_impl_t' type.
//
VSF_PUBLIC size_t
vsf_sha256_impl_size (void) {

    return sizeof (vsf_sha256_impl_t);
}

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_sha256_impl (vsf_sha256_impl_t* sha256_impl) {

    VSF_ASSERT (sha256_impl);
    return (vsf_impl_t *) (sha256_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
