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
//  This module contains 'vsf_sha256_t' object management.
//  It includes:
//      - lifecycle functions;
//      - dependency management functions;
//      - RTTI functions.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_sha256.h"
#include "vsf_sha256_private.h"
#include "vsf_sha256_hash_info.h"
#include "vsf_sha256_hash.h"
#include "vsf_sha256_hash_stream.h"
#include "vsf_impl_private.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Objects.
// ==========================================================================

//  Interface 'hash info' API.
static vsf_hash_info_api_t hash_info_api = {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_info' MUST be equal to the 'vsf_api_tag_HASH_INFO'.
    vsf_api_tag_HASH_INFO,

    //  Size of the digest (hashing output).
    vsf_sha256_hash_info_DIGEST_SIZE,
};

//  Interface 'hash' API.
static vsf_hash_api_t hash_api = {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash' MUST be equal to the 'vsf_api_tag_HASH'.
    vsf_api_tag_HASH,

    //  Link to the inherited interface API 'hash info'.
    hash_info_api,

    //  Calculate hash over given data.
    (vsf_hash_api_hash_fn) vsf_sha256_hash_hash,
};

//  Interface 'hash stream' API.
static vsf_hash_stream_api_t hash_stream_api = {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_stream' MUST be equal to the 'vsf_api_tag_HASH_STREAM'.
    vsf_api_tag_HASH_STREAM,

    //  Link to the inherited interface API 'hash'.
    hash_api,

    //  Start a new hashing.
    (vsf_hash_stream_api_start_fn) vsf_sha256_hash_stream_start,

    //  Add given data to the hash.
    (vsf_hash_stream_api_update_fn) vsf_sha256_hash_stream_update,

    //  Accompilsh hashing and return the it's result (a message digest).
    (vsf_hash_stream_api_finish_fn) vsf_sha256_hash_stream_finish,
};

//  NULL terminated array of the implementaed interfaces.
//  MUST be second in the structure.
static vsf_api_t api_array = {
    hash_info_api,
    hash_api,
    hash_stream_api,
    NULL,
};

//  Compile-time known information about 'sha256' implementation.
static vsf_impl_info_t impl_info = {
    //  Implementation unique identifier, MUST be first in the structure.
    vsf_impl_tag_SHA256,

    //  NULL terminated array of the implementaed interfaces.
    //  MUST be second in the structure.
    api_array,

    //  Erase inner state in a secure manner.
    vsf_sha256_cleanup,

    //  Self destruction, according to destruction policy.
    vsf_sha256_destroy,
};


// ==========================================================================
//  Types.
// ==========================================================================

//  This type contains implementation details.
struct vsf_sha256_t {
    //  Compile-time known information about this implementation.
    const vsf_impl_info_t *info;

    //  Interface implementation specific context.
    vsf_sha256_context_t context;
};
typedef struct vsf_sha256_t vsf_sha256_t;


// ==========================================================================
//  Generated functions.
// ==========================================================================

VSF_PUBLIC void
vsf_sha256_cleanup (void) {

    //TODO: Implement me.
}

VSF_PUBLIC void
vsf_sha256_destroy (void) {

    //TODO: Implement me.
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
