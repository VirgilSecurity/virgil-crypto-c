//  Copyright (c) 2015-2018 Virgil Security Inc.
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


#include "vsf_hash.h"
#include "vsf_hash_api.h"
#include "vsf_assert.h"

//  Start new hashing.
VSF_PUBLIC void
vsf_hash_start (void *impl) {
    VSF_ASSERT (impl);
    VSF_ASSERT (vsf_hash_is_implemented (impl));

    const vsf_hash_api_t *api = vsf_hash_api (impl);
    VSF_ASSERT (api);

    VSF_ASSERT (api->start);
    api->start (impl);
}

//  Append given data to the hash.
VSF_PUBLIC void
vsf_hash_append (void *impl, const byte* data, size_t data_size) {
    VSF_ASSERT (impl);
    VSF_ASSERT (vsf_hash_is_implemented (impl));
    VSF_ASSERT (data);

    const vsf_hash_api_t *api = vsf_hash_api (impl);
    VSF_ASSERT (api);

    VSF_ASSERT (api->append);
    api->append (impl, data, data_size);
}

//  Finalize hashing.
//  Message digest is written to inner buffer and can be accessed via interface "buffer".
VSF_PUBLIC void
vsf_hash_finish (void *impl) {
    VSF_ASSERT (impl);
    VSF_ASSERT (vsf_hash_is_implemented (impl));

    const vsf_hash_api_t *api = vsf_hash_api (impl);
    VSF_ASSERT (api);

    VSF_ASSERT (api->finish);
    api->finish (impl);
}

//  Return number of bytes occupied by output message digest.
VSF_PUBLIC size_t
vsf_hash_digest_size (void *impl) {
    VSF_ASSERT (impl);
    VSF_ASSERT (vsf_hash_is_implemented (impl));

    const vsf_hash_api_t *api = vsf_hash_api (impl);
    VSF_ASSERT (api);

    return api->digest_size;
}

//  Return number of bytes occupied by output message digest.
VSF_PUBLIC size_t
vsf_hash_api_digest_size (const vsf_hash_api_t* api) {
    VSF_ASSERT (api);
    VSF_ASSERT_SAFE (api->api_tag == vsf_api_tag_HASH);

    return api->digest_size;
}

//  Stateless hashing
VSF_PUBLIC void
vsf_hash_api_hash (const vsf_hash_api_t* api,
        const byte* data, size_t data_size,
        byte* digest, size_t digest_size) {
    VSF_ASSERT (api);
    VSF_ASSERT (data);
    VSF_ASSERT (digest);
    VSF_ASSERT (digest_size >= api->digest_size);

    api->hash (data, data_size, digest, digest_size);
}

//  Return stateless part of the given implementation.
//  If given object does not implement interface hash then NULL will be returned.
VSF_PUBLIC const vsf_hash_api_t*
vsf_hash_api (void *impl) {
    VSF_ASSERT (impl);
    return (const vsf_hash_api_t*) vsf_api (impl, vsf_api_tag_HASH);
}


VSF_PUBLIC bool
vsf_hash_is_implemented (void *impl) {
    VSF_ASSERT (impl);
    return vsf_hash_api (impl) != NULL;
}

//  Check algorithm runtime availability.
//  Also check if given object implements hash interface.
VSF_PUBLIC bool
vsf_hash_is_available (void *impl) {
    VSF_ASSERT (impl);

    if (!vsf_hash_is_implemented (impl)) {
        return false;
    }

    const vsf_hash_api_t *api = vsf_hash_api (impl);
    VSF_ASSERT (api);

    return vsf_hash_api_is_available (api);
}

//  Check algorithm runtime availability.
VSF_PUBLIC bool
vsf_hash_api_is_available (const vsf_hash_api_t* api) {
    VSF_ASSERT (api);

    if (api->is_available) {
        return api->is_available ();
    } else {
        //  This feature does not rely on runtime environment,
        //  so it's always available if it's implemented.
        return true;
    }
}
