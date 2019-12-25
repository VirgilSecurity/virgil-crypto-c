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
#include "vscf_alg.h"
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
#include "vscf_rsa.h"
#include "vscf_ed25519.h"
#include "vscf_curve25519.h"
#include "vscf_ecc.h"
#include "vscf_random_padding.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Restore algorithm info within a given algorithm and returns it if success,
//  or delete it and returns NULL;
//
static vscf_impl_t *
vscf_alg_factory_restore_alg_info_and_return(vscf_impl_t **alg_ref, const vscf_impl_t *alg_info);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Create algorithm that implements "hash stream" interface.
//
VSCF_PRIVATE vscf_impl_t *
vscf_alg_factory_create_hash_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
#if VSCF_SHA224
    case vscf_alg_id_SHA224:
        return vscf_sha224_impl(vscf_sha224_new());
#endif // VSCF_SHA224

#if VSCF_SHA256
    case vscf_alg_id_SHA256:
        return vscf_sha256_impl(vscf_sha256_new());
#endif // VSCF_SHA256

#if VSCF_SHA384
    case vscf_alg_id_SHA384:
        return vscf_sha384_impl(vscf_sha384_new());
#endif // VSCF_SHA384

#if VSCF_SHA512
    case vscf_alg_id_SHA512:
        return vscf_sha512_impl(vscf_sha512_new());
#endif // VSCF_SHA512

    default:
        return NULL;
    }
}

//
//  Create algorithm that implements "hash stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_hash_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    return vscf_alg_factory_create_hash_from_alg_id(vscf_alg_info_alg_id(alg_info));
}

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PRIVATE vscf_impl_t *
vscf_alg_factory_create_mac_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
#if VSCF_HMAC
    case vscf_alg_id_HMAC:
        return vscf_hmac_impl(vscf_hmac_new());
#endif // VSCF_HMAC

    default:
        return NULL;
    }
}

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_mac_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    vscf_impl_t *alg = vscf_alg_factory_create_mac_from_alg_id(vscf_alg_info_alg_id(alg_info));

    return vscf_alg_factory_restore_alg_info_and_return(&alg, alg_info);
}

//
//  Create algorithm that implements "kdf" interface.
//
VSCF_PRIVATE vscf_impl_t *
vscf_alg_factory_create_kdf_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
#if VSCF_KDF1
    case vscf_alg_id_KDF1:
        return vscf_kdf1_impl(vscf_kdf1_new());
#endif // VSCF_KDF1

#if VSCF_KDF2
    case vscf_alg_id_KDF2:
        return vscf_kdf2_impl(vscf_kdf2_new());
#endif // VSCF_KDF2

    case vscf_alg_id_HKDF:
    case vscf_alg_id_PKCS5_PBKDF2:
        return vscf_alg_factory_create_salted_kdf_from_alg_id(alg_id);

    default:
        return NULL;
    }
}

//
//  Create algorithm that implements "kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_kdf_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    vscf_impl_t *alg = vscf_alg_factory_create_kdf_from_alg_id(vscf_alg_info_alg_id(alg_info));

    return vscf_alg_factory_restore_alg_info_and_return(&alg, alg_info);
}

//
//  Create algorithm that implements "salted kdf" interface.
//
VSCF_PRIVATE vscf_impl_t *
vscf_alg_factory_create_salted_kdf_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
#if VSCF_HKDF
    case vscf_alg_id_HKDF: {
        return vscf_hkdf_impl(vscf_hkdf_new());
    }
#endif // VSCF_HKDF

#if VSCF_PKCS5_PBKDF2
    case vscf_alg_id_PKCS5_PBKDF2: {
        vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
        vscf_pkcs5_pbkdf2_setup_defaults(pbkdf2);
        return vscf_pkcs5_pbkdf2_impl(pbkdf2);
    }
#endif // VSCF_PKCS5_PBKDF2

    default:
        return NULL;
    }
}

//
//  Create algorithm that implements "salted kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_salted_kdf_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    vscf_impl_t *alg = vscf_alg_factory_create_salted_kdf_from_alg_id(vscf_alg_info_alg_id(alg_info));

    return vscf_alg_factory_restore_alg_info_and_return(&alg, alg_info);
}

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PRIVATE vscf_impl_t *
vscf_alg_factory_create_cipher_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
#if VSCF_AES256_GCM
    case vscf_alg_id_AES256_GCM:
        return vscf_aes256_gcm_impl(vscf_aes256_gcm_new());
#endif // VSCF_AES256_GCM

#if VSCF_AES256_CBC
    case vscf_alg_id_AES256_CBC:
        return vscf_aes256_cbc_impl(vscf_aes256_cbc_new());
#endif // VSCF_AES256_CBC

    default:
        return NULL;
    }
}

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_cipher_from_info(const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info);

    vscf_impl_t *alg = vscf_alg_factory_create_cipher_from_alg_id(vscf_alg_info_alg_id(alg_info));

    return vscf_alg_factory_restore_alg_info_and_return(&alg, alg_info);
}

//
//  Create algorithm that implements "padding" interface.
//
VSCF_PRIVATE vscf_impl_t *
vscf_alg_factory_create_padding_from_alg_id(vscf_alg_id_t alg_id, const vscf_impl_t *random) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
#if VSCF_RANDOM_PADDING
    case vscf_alg_id_RANDOM_PADDING: {
        vscf_random_padding_t *padding = vscf_random_padding_new();
        if (random != NULL) {
            vscf_random_padding_use_random(padding, (vscf_impl_t *)random);
        }
        return vscf_random_padding_impl(padding);
    }
#endif // VSCF_RANDOM_PADDING

    default:
        return NULL;
    }
}

//
//  Create algorithm that implements "padding" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_padding_from_info(const vscf_impl_t *alg_info, const vscf_impl_t *random) {

    VSCF_ASSERT_PTR(alg_info);

    vscf_impl_t *alg = vscf_alg_factory_create_padding_from_alg_id(vscf_alg_info_alg_id(alg_info), random);

    return vscf_alg_factory_restore_alg_info_and_return(&alg, alg_info);
}

//
//  Restore algorithm info within a given algorithm and returns it if success,
//  or delete it and returns NULL;
//
static vscf_impl_t *
vscf_alg_factory_restore_alg_info_and_return(vscf_impl_t **alg_ref, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_ref);
    VSCF_ASSERT_PTR(alg_info);

    if (*alg_ref) {
        const vscf_status_t status = vscf_alg_restore_alg_info(*alg_ref, alg_info);
        if (status != vscf_status_SUCCESS) {
            vscf_impl_destroy(alg_ref);
            //  TODO: Log underlying error.
        }
    }

    return *alg_ref;
}
