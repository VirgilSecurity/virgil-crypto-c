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
//  Create algorithms based on the given information.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_factory.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_alg_info.h"
#include "vscf_sha224.h"
#include "vscf_sha256.h"
#include "vscf_sha384.h"
#include "vscf_sha512.h"
#include "vscf_hmac.h"
#include "vscf_hkdf.h"
#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_aes256_gcm.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_cipher_alg_info.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Create algorithm that implements "hash stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_hash_alg(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);

    switch (alg_id) {
    case vscf_alg_id_SHA224:
        return vscf_sha224_impl(vscf_sha224_new());

    case vscf_alg_id_SHA256:
        return vscf_sha256_impl(vscf_sha256_new());

    case vscf_alg_id_SHA384:
        return vscf_sha384_impl(vscf_sha384_new());

    case vscf_alg_id_SHA512:
        return vscf_sha512_impl(vscf_sha512_new());

    default:
        VSCF_ASSERT(0 && "Can not create 'hash stream' algorithm from the given alg id.");
        return NULL;
    }
}

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_mac_alg(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);

    if (alg_id == vscf_alg_id_HMAC) {
        const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

        vscf_hmac_t *hmac = vscf_hmac_new();
        vscf_hmac_take_hash(
                hmac, vscf_alg_factory_create_hash_alg(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info)));

        return vscf_hmac_impl(hmac);
    }

    VSCF_ASSERT(0 && "Can not create 'mac stream' algorithm from the given alg id.");
    return NULL;
}

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_salted_kdf_alg(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);

    if (alg_id == vscf_alg_id_HKDF) {
        const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

        vscf_hkdf_t *hkdf = vscf_hkdf_new();
        vscf_hkdf_take_hash(
                hkdf, vscf_alg_factory_create_hash_alg(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info)));

        return vscf_hkdf_impl(hkdf);
    }

    VSCF_ASSERT(0 && "Can not create 'salted kdf' algorithm from the given alg id.");
    return NULL;
}

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_cipher_alg(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);

    if (alg_id == vscf_alg_id_AES256_GCM) {
        const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)alg_info;
        vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();
        vscf_aes256_gcm_set_nonce(aes256_gcm, vscf_cipher_alg_info_nonce(cipher_alg_info));
        return vscf_aes256_gcm_impl(aes256_gcm);
    }

    VSCF_ASSERT(0 && "Can not create 'cipher' algorithm from the given alg id.");
    return NULL;
}
