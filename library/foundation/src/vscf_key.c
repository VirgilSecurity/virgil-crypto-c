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
//  Basic key type.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key.h"
#include "vscf_assert.h"
#include "vscf_key_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_key_alg_id(const vscf_impl_t *impl) {

    const vscf_key_api_t *key_api = vscf_key_api(impl);
    VSCF_ASSERT_PTR (key_api);

    VSCF_ASSERT_PTR (key_api->alg_id_cb);
    return key_api->alg_id_cb (impl);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_key_alg_info(const vscf_impl_t *impl) {

    const vscf_key_api_t *key_api = vscf_key_api(impl);
    VSCF_ASSERT_PTR (key_api);

    VSCF_ASSERT_PTR (key_api->alg_info_cb);
    return key_api->alg_info_cb (impl);
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_key_len(const vscf_impl_t *impl) {

    const vscf_key_api_t *key_api = vscf_key_api(impl);
    VSCF_ASSERT_PTR (key_api);

    VSCF_ASSERT_PTR (key_api->len_cb);
    return key_api->len_cb (impl);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_key_bitlen(const vscf_impl_t *impl) {

    const vscf_key_api_t *key_api = vscf_key_api(impl);
    VSCF_ASSERT_PTR (key_api);

    VSCF_ASSERT_PTR (key_api->bitlen_cb);
    return key_api->bitlen_cb (impl);
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_key_impl_tag(const vscf_impl_t *impl) {

    const vscf_key_api_t *key_api = vscf_key_api(impl);
    VSCF_ASSERT_PTR (key_api);

    VSCF_ASSERT_PTR (key_api->impl_tag_cb);
    return key_api->impl_tag_cb (impl);
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_key_is_valid(const vscf_impl_t *impl) {

    const vscf_key_api_t *key_api = vscf_key_api(impl);
    VSCF_ASSERT_PTR (key_api);

    VSCF_ASSERT_PTR (key_api->is_valid_cb);
    return key_api->is_valid_cb (impl);
}

//
//  Return key API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_api_t *
vscf_key_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_KEY);
    return (const vscf_key_api_t *) api;
}

//
//  Check if given object implements interface 'key'.
//
VSCF_PUBLIC bool
vscf_key_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_KEY) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_key_api_tag(const vscf_key_api_t *key_api) {

    VSCF_ASSERT_PTR (key_api);

    return key_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
