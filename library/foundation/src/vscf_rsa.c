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
//  This module contains 'rsa' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_rsa.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_mbedtls_md.h"
#include "vscf_simple_alg_info.h"
#include "vscf_asn1_tag.h"
#include "vscf_ctr_drbg.h"
#include "vscf_rsa_public_key_defs.h"
#include "vscf_rsa_private_key_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_random.h"
#include "vscf_rsa_defs.h"
#include "vscf_rsa_internal.h"

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
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_setup_defaults(vscf_rsa_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }
        self->random = vscf_ctr_drbg_impl(random);
    }

    return vscf_status_SUCCESS;
}

//
//  Generate new private key.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_generate_key(const vscf_rsa_t *self, size_t bitlen, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vscf_rsa_private_key_t *rsa_private_key = vscf_rsa_private_key_new();
    rsa_private_key->alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));

    const int mbed_status = mbedtls_rsa_gen_key(
            &rsa_private_key->rsa_ctx, vscf_mbedtls_bridge_random, self->random, (unsigned int)bitlen, 65537);

    if (mbed_status) {
        vscf_rsa_private_key_destroy(&rsa_private_key);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_KEY_GENERATION_FAILED);
        return NULL;
    }

    return vscf_rsa_private_key_impl(rsa_private_key);
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_generate_ephemeral_key(const vscf_rsa_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(key));

    if (vscf_key_impl_tag(key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    size_t bitlen = 0;
    if (vscf_impl_tag(key) == vscf_impl_tag_RSA_PUBLIC_KEY) {
        const vscf_rsa_public_key_t *rsa_public_key = (const vscf_rsa_public_key_t *)key;
        bitlen = mbedtls_rsa_get_len(&rsa_public_key->rsa_ctx);
    } else {
        VSCF_ASSERT(vscf_impl_tag(key) == vscf_impl_tag_RSA_PRIVATE_KEY);
        const vscf_rsa_private_key_t *rsa_private_key = (const vscf_rsa_private_key_t *)key;
        bitlen = mbedtls_rsa_get_len(&rsa_private_key->rsa_ctx);
    }

    return vscf_rsa_generate_key(self, bitlen, error);
}

//
//  Import public key from the raw binary format.
//
//  Return public key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_import_public_key(const vscf_rsa_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(raw_key));

    vscf_rsa_public_key_t *rsa_public_key = vscf_rsa_public_key_new();
    rsa_public_key->impl_tag = self->info->impl_tag;
    const vscf_status_t status = vscf_rsa_public_key_import(rsa_public_key, raw_key);

    if (status == vscf_status_SUCCESS) {
        return vscf_rsa_public_key_impl(rsa_public_key);
    }

    vscf_rsa_public_key_destroy(&rsa_public_key);
    VSCF_ERROR_SAFE_UPDATE(error, status);
    return NULL;
}

//
//  Import public key from the raw binary format.
//
VSCF_PRIVATE vscf_impl_t *
vscf_rsa_import_public_key_data(
        const vscf_rsa_t *self, vsc_data_t key_data, const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);

    return NULL;
}

//
//  Export public key to the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_public_key_t *
vscf_rsa_export_public_key(const vscf_rsa_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_RSA_PUBLIC_KEY);
    const vscf_rsa_public_key_t *rsa_public_key = (const vscf_rsa_public_key_t *)public_key;

    return vscf_rsa_public_key_export(rsa_public_key);
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PRIVATE size_t
vscf_rsa_exported_public_key_data_len(const vscf_rsa_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    //  Unsupported algorithm.

    return 0;
}

//
//  Export public key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PRIVATE vscf_status_t
vscf_rsa_export_public_key_data(const vscf_rsa_t *self, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_rsa_exported_public_key_data_len(self, public_key));

    return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
}

//
//  Import private key from the raw binary format.
//
//  Return private key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_import_private_key(const vscf_rsa_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(raw_key));

    vscf_rsa_private_key_t *rsa_private_key = vscf_rsa_private_key_new();
    const vscf_status_t status = vscf_rsa_private_key_import(rsa_private_key, raw_key);

    if (status == vscf_status_SUCCESS) {
        return vscf_rsa_private_key_impl(rsa_private_key);
    }

    vscf_rsa_private_key_destroy(&rsa_private_key);
    VSCF_ERROR_SAFE_UPDATE(error, status);
    return NULL;
}

//
//  Import private key from the raw binary format.
//
VSCF_PRIVATE vscf_impl_t *
vscf_rsa_import_private_key_data(
        const vscf_rsa_t *self, vsc_data_t key_data, const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);
    VSCF_UNUSED(error);

    VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);

    return NULL;
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_private_key_t *
vscf_rsa_export_private_key(const vscf_rsa_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_RSA_PRIVATE_KEY);
    const vscf_rsa_private_key_t *rsa_private_key = (const vscf_rsa_private_key_t *)private_key;

    return vscf_rsa_private_key_export(rsa_private_key);
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PRIVATE size_t
vscf_rsa_exported_private_key_data_len(const vscf_rsa_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    //  Unsupported algorithm.

    return 0;
}

//
//  Export private key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PRIVATE vscf_status_t
vscf_rsa_export_private_key_data(const vscf_rsa_t *self, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_rsa_exported_private_key_data_len(self, private_key));

    return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
}

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_rsa_can_encrypt(const vscf_rsa_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return false;
    }

    const size_t hash_len = 64; // MBEDTLS_MD_SHA512
    if (vscf_key_len(public_key) >= data_len + 2 * hash_len + 2) {
        return true;
    }

    return false;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_encrypted_len(const vscf_rsa_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_rsa_can_encrypt(self, public_key, data_len));

    return vscf_key_len(public_key);
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_encrypt(const vscf_rsa_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_rsa_can_encrypt(self, public_key, data.len));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_rsa_encrypted_len(self, public_key, data.len));


    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_RSA_PUBLIC_KEY);
    vscf_rsa_public_key_t *rsa_public_key = (vscf_rsa_public_key_t *)public_key;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);
    const int alloc_status = mbedtls_rsa_copy(&rsa, &rsa_public_key->rsa_ctx);
    VSCF_ASSERT_ALLOC(alloc_status == 0);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);

    const int mbed_status = mbedtls_rsa_rsaes_oaep_encrypt(&rsa, vscf_mbedtls_bridge_random, self->random,
            MBEDTLS_RSA_PUBLIC, NULL, 0, data.len, data.bytes, vsc_buffer_unused_bytes(out));

    mbedtls_rsa_free(&rsa);

    switch (mbed_status) {
    case 0:
        vsc_buffer_inc_used(out, vscf_key_len(public_key));
        return vscf_status_SUCCESS;

    case MBEDTLS_ERR_RSA_RNG_FAILED:
        return vscf_status_ERROR_RANDOM_FAILED;

    default:
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_rsa_can_decrypt(const vscf_rsa_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return false;
    }


    return data_len <= vscf_key_len(private_key);
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_decrypted_len(const vscf_rsa_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_rsa_can_decrypt(self, private_key, data_len));

    return vscf_key_len(private_key);
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_decrypt(const vscf_rsa_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_rsa_can_decrypt(self, private_key, data.len));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_rsa_decrypted_len(self, private_key, data.len));

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_RSA_PRIVATE_KEY);
    vscf_rsa_private_key_t *rsa_private_key = (vscf_rsa_private_key_t *)private_key;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);
    const int alloc_status = mbedtls_rsa_copy(&rsa, &rsa_private_key->rsa_ctx);
    VSCF_ASSERT_ALLOC(alloc_status == 0);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);

    size_t out_len = 0;
    const int mbed_status =
            mbedtls_rsa_rsaes_oaep_decrypt(&rsa, vscf_mbedtls_bridge_random, self->random, MBEDTLS_RSA_PRIVATE, NULL, 0,
                    &out_len, data.bytes, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    mbedtls_rsa_free(&rsa);

    switch (mbed_status) {
    case 0:
        vsc_buffer_inc_used(out, out_len);
        return vscf_status_SUCCESS;

    case MBEDTLS_ERR_RSA_RNG_FAILED:
        return vscf_status_ERROR_RANDOM_FAILED;

    default:
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }
}

//
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_rsa_can_sign(const vscf_rsa_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));

    bool is_my_impl = vscf_key_impl_tag(private_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_rsa_signature_len(const vscf_rsa_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));

    return vscf_key_len(private_key);
}

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_sign_hash(const vscf_rsa_t *self, const vscf_impl_t *private_key, vscf_alg_id_t hash_id, vsc_data_t digest,
        vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_rsa_can_sign(self, private_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(vsc_buffer_unused_len(signature) >= vscf_rsa_signature_len(self, private_key));

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_RSA_PRIVATE_KEY);
    vscf_rsa_private_key_t *rsa_private_key = (vscf_rsa_private_key_t *)private_key;

    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(hash_id);
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, md_alg);
    const int alloc_status = mbedtls_rsa_copy(&rsa, &rsa_private_key->rsa_ctx);
    VSCF_ASSERT_ALLOC(alloc_status == 0);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md_alg);

    const int mbed_status = mbedtls_rsa_rsassa_pss_sign(&rsa, vscf_mbedtls_bridge_random, (void *)self->random,
            MBEDTLS_RSA_PRIVATE, md_alg, (unsigned int)digest.len, digest.bytes, vsc_buffer_unused_bytes(signature));
    VSCF_ASSERT_ALLOC(mbed_status != MBEDTLS_ERR_MD_ALLOC_FAILED);

    mbedtls_rsa_free(&rsa);

    switch (mbed_status) {
    case 0:
        vsc_buffer_inc_used(signature, vscf_rsa_signature_len(self, private_key));
        return vscf_status_SUCCESS;

    case MBEDTLS_ERR_RSA_RNG_FAILED:
        return vscf_status_ERROR_RANDOM_FAILED;

    default:
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }
}

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_rsa_can_verify(const vscf_rsa_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_key_is_valid(public_key));

    bool is_my_impl = vscf_key_impl_tag(public_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_rsa_verify_hash(const vscf_rsa_t *self, const vscf_impl_t *public_key, vscf_alg_id_t hash_id, vsc_data_t digest,
        vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_rsa_can_verify(self, public_key));
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));

    if (signature.len != vscf_rsa_signature_len(self, public_key)) {
        return false;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_RSA_PUBLIC_KEY);
    vscf_rsa_public_key_t *rsa_public_key = (vscf_rsa_public_key_t *)public_key;

    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(hash_id);
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, md_alg);
    const int alloc_status = mbedtls_rsa_copy(&rsa, &rsa_public_key->rsa_ctx);
    VSCF_ASSERT_ALLOC(alloc_status == 0);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md_alg);

    int result = mbedtls_rsa_rsassa_pss_verify(
            &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, md_alg, (unsigned int)digest.len, digest.bytes, signature.bytes);

    mbedtls_rsa_free(&rsa);

    return result == 0 ? true : false;
}
