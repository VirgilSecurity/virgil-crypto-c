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
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_sha224.h"
#include "vscf_sha256.h"
#include "vscf_sha384.h"
#include "vscf_sha512.h"
#include "vscf_kdf1.h"
#include "vscf_kdf2.h"
#include "vscf_hmac.h"
#include "vscf_hkdf.h"
#include "vscf_aes256_gcm.h"
#include "vscf_aes256_cbc.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_pbe_alg_info.h"
#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_pkcs5_pbes2.h"
#include "vscf_rsa_public_key.h"
#include "vscf_rsa_private_key.h"
#include "vscf_ed25519_public_key.h"
#include "vscf_ed25519_private_key.h"
#include "vscf_curve25519_public_key.h"
#include "vscf_curve25519_private_key.h"

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
vscf_alg_factory_create_hash_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

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
vscf_alg_factory_create_mac_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (alg_id == vscf_alg_id_HMAC) {
        const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

        vscf_hmac_t *hmac = vscf_hmac_new();
        vscf_hmac_take_hash(hmac,
                vscf_alg_factory_create_hash_from_info(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info)));

        return vscf_hmac_impl(hmac);
    }

    VSCF_ASSERT(0 && "Can not create 'mac stream' algorithm from the given alg id.");
    return NULL;
}

//
//  Create algorithm that implements "kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_kdf_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (alg_id == vscf_alg_id_KDF1) {
        const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

        vscf_kdf1_t *kdf1 = vscf_kdf1_new();
        vscf_impl_t *hash =
                vscf_alg_factory_create_hash_from_info(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));

        vscf_kdf1_take_hash(kdf1, hash);

        return vscf_kdf1_impl(kdf1);
    }

    if (alg_id == vscf_alg_id_KDF2) {
        const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

        vscf_kdf2_t *kdf2 = vscf_kdf2_new();
        vscf_impl_t *hash =
                vscf_alg_factory_create_hash_from_info(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));

        vscf_kdf2_take_hash(kdf2, hash);

        return vscf_kdf2_impl(kdf2);
    }

    if (alg_id == vscf_alg_id_HKDF || alg_id == vscf_alg_id_PKCS5_PBKDF2) {
        return vscf_alg_factory_create_salted_kdf_from_info(alg_info);
    }

    VSCF_ASSERT(0 && "Can not create 'kdf' algorithm from the given alg id.");
    return NULL;
}

//
//  Create algorithm that implements "salted kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_salted_kdf_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (alg_id == vscf_alg_id_HKDF) {
        const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

        vscf_hkdf_t *hkdf = vscf_hkdf_new();
        vscf_hkdf_take_hash(hkdf,
                vscf_alg_factory_create_hash_from_info(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info)));

        return vscf_hkdf_impl(hkdf);
    }

    if (alg_id == vscf_alg_id_PKCS5_PBKDF2) {
        const vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = (const vscf_salted_kdf_alg_info_t *)alg_info;

        vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
        vscf_impl_t *mac =
                vscf_alg_factory_create_mac_from_info(vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info));
        vsc_data_t salt = vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info);
        size_t iteration_count = vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info);

        vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, mac);
        vscf_pkcs5_pbkdf2_reset(pbkdf2, salt, iteration_count);

        return vscf_pkcs5_pbkdf2_impl(pbkdf2);
    }

    VSCF_ASSERT(0 && "Can not create 'salted kdf' algorithm from the given alg id.");
    return NULL;
}

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_cipher_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (alg_id == vscf_alg_id_AES256_GCM) {
        const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)alg_info;
        vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();
        vscf_aes256_gcm_set_nonce(aes256_gcm, vscf_cipher_alg_info_nonce(cipher_alg_info));
        return vscf_aes256_gcm_impl(aes256_gcm);
    }

    if (alg_id == vscf_alg_id_AES256_CBC) {
        const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)alg_info;
        vscf_aes256_cbc_t *aes256_cbc = vscf_aes256_cbc_new();
        vscf_aes256_cbc_set_nonce(aes256_cbc, vscf_cipher_alg_info_nonce(cipher_alg_info));
        return vscf_aes256_cbc_impl(aes256_cbc);
    }

    VSCF_ASSERT(0 && "Can not create 'cipher' algorithm from the given alg id.");
    return NULL;
}

//
//  Create algorithm that implements "public key" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_public_key_from_raw_key(const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(raw_key);

    vscf_status_t status = vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    vscf_impl_t *public_key = NULL;

    const vscf_alg_id_t alg_id = vscf_raw_key_alg_id(raw_key);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (alg_id == vscf_alg_id_RSA) {
        vscf_rsa_public_key_t *rsa_public_key = vscf_rsa_public_key_new();
        public_key = vscf_rsa_public_key_impl(rsa_public_key);
        status = vscf_rsa_public_key_setup_defaults(rsa_public_key);
    }

    if (alg_id == vscf_alg_id_ED25519) {
        vscf_ed25519_public_key_t *ed25519_public_key = vscf_ed25519_public_key_new();
        public_key = vscf_ed25519_public_key_impl(ed25519_public_key);
        status = vscf_ed25519_public_key_setup_defaults(ed25519_public_key);
    }

    if (alg_id == vscf_alg_id_CURVE25519) {
        vscf_curve25519_public_key_t *curve25519_public_key = vscf_curve25519_public_key_new();
        public_key = vscf_curve25519_public_key_impl(curve25519_public_key);
        status = vscf_curve25519_public_key_setup_defaults(curve25519_public_key);
    }

    if (status == vscf_status_SUCCESS) {
        status = vscf_public_key_import_public_key(public_key, vscf_raw_key_data(raw_key));
    }

    if (status == vscf_status_SUCCESS) {
        return public_key;
    } else {
        vscf_impl_destroy(&public_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }
}

//
//  Create algorithm that implements "private key" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_private_key_from_raw_key(const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(raw_key);

    vscf_status_t status = vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    vscf_impl_t *private_key = NULL;

    const vscf_alg_id_t alg_id = vscf_raw_key_alg_id(raw_key);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (alg_id == vscf_alg_id_RSA) {
        vscf_rsa_private_key_t *rsa_private_key = vscf_rsa_private_key_new();
        private_key = vscf_rsa_private_key_impl(rsa_private_key);
        status = vscf_rsa_private_key_setup_defaults(rsa_private_key);
    }

    if (alg_id == vscf_alg_id_ED25519) {
        vscf_ed25519_private_key_t *ed25519_private_key = vscf_ed25519_private_key_new();
        private_key = vscf_ed25519_private_key_impl(ed25519_private_key);
        status = vscf_ed25519_private_key_setup_defaults(ed25519_private_key);
    }

    if (alg_id == vscf_alg_id_CURVE25519) {
        vscf_curve25519_private_key_t *curve25519_private_key = vscf_curve25519_private_key_new();
        private_key = vscf_curve25519_private_key_impl(curve25519_private_key);
        status = vscf_curve25519_private_key_setup_defaults(curve25519_private_key);
    }

    if (status == vscf_status_SUCCESS) {
        status = vscf_private_key_import_private_key(private_key, vscf_raw_key_data(raw_key));
    }

    if (status == vscf_status_SUCCESS) {
        return private_key;
    } else {
        vscf_impl_destroy(&private_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }
}
