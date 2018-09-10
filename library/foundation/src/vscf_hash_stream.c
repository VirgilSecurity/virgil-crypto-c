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
//  Provide interface to calculate hash (message digest) over a stream.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_hash_stream.h"
#include "vscf_assert.h"
#include "vscf_hash_stream_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Start a new hashing.
//
VSCF_PUBLIC void
vscf_hash_stream_start(vscf_impl_t *impl) {

    const vscf_hash_stream_api_t *hash_stream_api = vscf_hash_stream_api (impl);
    VSCF_ASSERT_PTR (hash_stream_api);

    VSCF_ASSERT_PTR (hash_stream_api->start_cb);
    hash_stream_api->start_cb (impl);
}

//
//  Add given data to the hash.
//
VSCF_PUBLIC void
vscf_hash_stream_update(vscf_impl_t *impl, vsc_data_t data) {

    const vscf_hash_stream_api_t *hash_stream_api = vscf_hash_stream_api (impl);
    VSCF_ASSERT_PTR (hash_stream_api);

    VSCF_ASSERT_PTR (hash_stream_api->update_cb);
    hash_stream_api->update_cb (impl, data);
}

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_hash_stream_finish(vscf_impl_t *impl, vsc_buffer_t *digest) {

    const vscf_hash_stream_api_t *hash_stream_api = vscf_hash_stream_api (impl);
    VSCF_ASSERT_PTR (hash_stream_api);

    VSCF_ASSERT_PTR (hash_stream_api->finish_cb);
    hash_stream_api->finish_cb (impl, digest);
}

//
//  Return hash stream API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_hash_stream_api_t *
vscf_hash_stream_api(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_HASH_STREAM);
    return (const vscf_hash_stream_api_t *) api;
}

//
//  Return hash info API.
//
VSCF_PUBLIC const vscf_hash_info_api_t *
vscf_hash_stream_hash_info_api(const vscf_hash_stream_api_t *hash_stream_api) {

    VSCF_ASSERT_PTR (hash_stream_api);

    return hash_stream_api->hash_info_api;
}

//
//  Check if given object implements interface 'hash stream'.
//
VSCF_PUBLIC bool
vscf_hash_stream_is_implemented(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_HASH_STREAM) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_hash_stream_api_tag(const vscf_hash_stream_api_t *hash_stream_api) {

    VSCF_ASSERT_PTR (hash_stream_api);

    return hash_stream_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_hash_stream_impl_tag(const vscf_hash_stream_api_t *hash_stream_api) {

    VSCF_ASSERT_PTR (hash_stream_api);

    return hash_stream_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
