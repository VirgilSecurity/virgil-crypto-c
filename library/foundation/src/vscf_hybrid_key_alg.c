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
//  This module contains 'hybrid key alg' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_hybrid_key_alg.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_oid.h"
#include "vscf_alg_factory.h"
#include "vscf_key_alg_factory.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_kem.h"
#include "vscf_key_signer.h"
#include "vscf_compute_shared_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_sha512.h"
#include "vscf_aes256_gcm.h"
#include "vscf_hybrid_public_key.h"
#include "vscf_hybrid_private_key.h"
#include "vscf_hybrid_key_alg_info.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_hkdf_private.h"
#include "vscf_random.h"
#include "vscf_cipher_auth.h"
#include "vscf_hash.h"
#include "vscf_hybrid_key_alg_defs.h"
#include "vscf_hybrid_key_alg_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Derive cipher key and nonce and configure the given cipher.
//
static void
vscf_hybrid_key_alg_config_cipher(vscf_impl_t *cipher, vscf_impl_t *hash, vsc_data_t shared_key);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_hybrid_key_alg_setup_defaults(vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);

        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }

        vscf_hybrid_key_alg_take_random(self, vscf_ctr_drbg_impl(random));
    }

    if (NULL == self->cipher) {
        self->cipher = vscf_aes256_gcm_impl(vscf_aes256_gcm_new());
    }

    if (NULL == self->hash) {
        self->hash = vscf_sha512_impl(vscf_sha512_new());
    }

    return vscf_status_SUCCESS;
}

//
//  Make hybrid private key from given keys.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hybrid_key_alg_make_key(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *first_key,
        const vscf_impl_t *second_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(first_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(first_key));
    VSCF_ASSERT_PTR(second_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(second_key));

    //
    //  Check algorithms.
    //
    vscf_impl_t *key = NULL;
    vscf_impl_t *alg_info = NULL;
    vscf_impl_t *first_key_alg = NULL;
    vscf_impl_t *second_key_alg = NULL;
    bool is_kem_both_implemented = false;
    bool is_key_signer_both_implemented = false;

    first_key_alg = vscf_key_alg_factory_create_from_key(first_key, NULL, error);

    if (NULL == first_key_alg) {
        goto cleanup;
    }

    second_key_alg = vscf_key_alg_factory_create_from_key(second_key, NULL, error);

    if (NULL == second_key_alg) {
        goto cleanup;
    }

    is_kem_both_implemented = vscf_kem_is_implemented(first_key_alg) && vscf_kem_is_implemented(second_key_alg);

    is_key_signer_both_implemented =
            vscf_key_signer_is_implemented(first_key_alg) && vscf_key_signer_is_implemented(second_key_alg);

    if (!is_kem_both_implemented && !is_key_signer_both_implemented) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    alg_info = vscf_hybrid_key_alg_info_impl(vscf_hybrid_key_alg_info_new_with_infos(
            vscf_alg_id_HYBRID_KEY, vscf_key_alg_info(first_key), vscf_key_alg_info(second_key)));
    key = vscf_hybrid_private_key_impl(vscf_hybrid_private_key_new_with_keys(&alg_info, first_key, second_key));

cleanup:
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);
    return key;
}

//
//  Derive cipher key and nonce and configure the given cipher.
//
static void
vscf_hybrid_key_alg_config_cipher(vscf_impl_t *cipher, vscf_impl_t *hash, vsc_data_t shared_key) {

    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT_PTR(hash);
    VSCF_ASSERT(vsc_data_is_valid(shared_key));

    //
    // Derive keys (encryption key and nonces).
    //
    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));
    const size_t cipher_nonce_len = vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));
    const size_t derived_key_len = cipher_key_len + cipher_nonce_len;
    vsc_buffer_t *derived_key = vsc_buffer_new_with_capacity(derived_key_len);
    vsc_buffer_make_secure(derived_key);

    const size_t digest_len = vscf_hash_digest_len(vscf_hash_api(hash));
    vsc_buffer_t *salt = vsc_buffer_new_with_capacity(digest_len);
    vsc_buffer_t *hkdf_pr_key = vsc_buffer_new_with_capacity(digest_len);
    vsc_buffer_erase(salt); //  Zeroize
    vsc_buffer_inc_used(salt, digest_len);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_use_hash(hkdf, hash);
    vscf_hkdf_extract(hkdf, shared_key, vsc_buffer_data(salt), hkdf_pr_key);
    vscf_hkdf_expand(hkdf, vsc_buffer_data(hkdf_pr_key), vsc_data_from_str("key", 3), derived_key, cipher_key_len);
    vscf_hkdf_expand(hkdf, vsc_buffer_data(hkdf_pr_key), vsc_data_from_str("nonce", 4), derived_key, cipher_nonce_len);

    vsc_data_t cipher_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), 0, cipher_key_len);
    vsc_data_t cipher_nonce = vsc_data_slice_beg(vsc_buffer_data(derived_key), cipher_key_len, cipher_nonce_len);

    //
    //  Configure the cipher.
    //
    vscf_cipher_set_key(cipher, cipher_key);
    vscf_cipher_set_nonce(cipher, cipher_nonce);

    vsc_buffer_destroy(&salt);
    vsc_buffer_destroy(&hkdf_pr_key);
    vsc_buffer_destroy(&derived_key);
    vscf_hkdf_destroy(&hkdf);
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hybrid_key_alg_generate_ephemeral_key(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    if (vscf_key_impl_tag(key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    //
    //  Get underlying keys.
    //
    const vscf_impl_tag_t impl_tag = vscf_impl_tag(key);
    const vscf_impl_t *first_key = NULL;
    const vscf_impl_t *second_key = NULL;
    if (impl_tag == vscf_impl_tag_HYBRID_PUBLIC_KEY) {
        const vscf_hybrid_public_key_t *public_key = (const vscf_hybrid_public_key_t *)key;
        first_key = vscf_hybrid_public_key_first_key(public_key);
        second_key = vscf_hybrid_public_key_second_key(public_key);

    } else if (impl_tag == vscf_impl_tag_HYBRID_PRIVATE_KEY) {
        const vscf_hybrid_private_key_t *private_key = (const vscf_hybrid_private_key_t *)key;
        first_key = vscf_hybrid_private_key_first_key(private_key);
        second_key = vscf_hybrid_private_key_second_key(private_key);

    } else {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    //
    //  Generate ephemeral underlying keys.
    //
    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, error);
    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, error);

    VSCF_ASSERT_PTR(first_key_alg);
    VSCF_ASSERT_PTR(second_key_alg);
    VSCF_ASSERT(vscf_kem_is_implemented(first_key_alg));
    VSCF_ASSERT(vscf_kem_is_implemented(second_key_alg));

    vscf_impl_t *ephemeral_key = NULL;
    vscf_impl_t *first_key_ephemeral_cipher_key = NULL;
    vscf_impl_t *second_key_ephemeral_cipher_key = NULL;


    first_key_ephemeral_cipher_key = vscf_key_alg_generate_ephemeral_key(first_key_alg, first_key, error);
    if (NULL == first_key_ephemeral_cipher_key) {
        goto cleanup;
    }

    second_key_ephemeral_cipher_key = vscf_key_alg_generate_ephemeral_key(second_key_alg, second_key, error);
    if (NULL == second_key_ephemeral_cipher_key) {
        goto cleanup;
    }

    ephemeral_key =
            vscf_hybrid_key_alg_make_key(self, first_key_ephemeral_cipher_key, second_key_ephemeral_cipher_key, error);

cleanup:
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);
    vscf_impl_destroy(&first_key_ephemeral_cipher_key);
    vscf_impl_destroy(&second_key_ephemeral_cipher_key);

    return ephemeral_key;
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
vscf_hybrid_key_alg_import_public_key(
        const vscf_hybrid_key_alg_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_public_key_is_valid(raw_key));

    return vscf_hybrid_key_alg_import_public_key_data(
            self, vscf_raw_public_key_data(raw_key), vscf_raw_public_key_alg_info(raw_key), error);
}

//
//  Import public key from the raw binary format.
//
VSCF_PRIVATE vscf_impl_t *
vscf_hybrid_key_alg_import_public_key_data(
        const vscf_hybrid_key_alg_t *self, vsc_data_t key_data, const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    //
    //  Check if raw key is appropriate.
    //
    if (vscf_impl_tag(key_alg_info) != vscf_impl_tag_HYBRID_KEY_ALG_INFO) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_alg_info_alg_id(key_alg_info) == vscf_alg_id_HYBRID_KEY);

    //
    // Write to the ASN.1 structure.
    //
    // HybridPublicKey ::= SEQUENCE {
    //     firstKey OCTET STRING,
    //     secondKey OCTET STRING
    // }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, key_data);
    vscf_asn1rd_read_sequence(&asn1rd);

    vsc_data_t first_key_data = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t second_key_data = vscf_asn1rd_read_octet_str(&asn1rd);

    const vscf_status_t asn1_status = vscf_asn1rd_status(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (asn1_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_HYBRID_PUBLIC_KEY);
        return NULL;
    }

    //
    //  Prepare keys to be imported.
    //
    const vscf_hybrid_key_alg_info_t *hybrid_key_alg_info = (const vscf_hybrid_key_alg_info_t *)key_alg_info;
    const vscf_impl_t *first_key_alg_info = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_key_alg_info);
    const vscf_impl_t *second_key_alg_info = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_key_alg_info);

    vscf_impl_t *first_key_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(first_key_alg_info);
    vscf_raw_public_key_t *raw_first_key = vscf_raw_public_key_new_with_data(first_key_data, &first_key_alg_info_copy);

    vscf_impl_t *second_key_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(second_key_alg_info);
    vscf_raw_public_key_t *raw_second_key =
            vscf_raw_public_key_new_with_data(second_key_data, &second_key_alg_info_copy);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *first_key_alg = NULL;
    vscf_impl_t *first_key = NULL;
    vscf_impl_t *second_key_alg = NULL;
    vscf_impl_t *second_key = NULL;
    vscf_impl_t *public_key = NULL;
    bool is_kem_both_implemented = false;
    bool is_key_signer_both_implemented = false;

    //
    //  Get correspond algs.
    //
    first_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(first_key_alg_info), self->random, error);

    if (NULL == first_key_alg) {
        goto cleanup;
    }

    second_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(second_key_alg_info), self->random, error);

    if (NULL == second_key_alg) {
        goto cleanup;
    }

    is_kem_both_implemented = vscf_kem_is_implemented(first_key_alg) && vscf_kem_is_implemented(second_key_alg);

    is_key_signer_both_implemented =
            vscf_key_signer_is_implemented(first_key_alg) && vscf_key_signer_is_implemented(second_key_alg);

    if (!is_kem_both_implemented && !is_key_signer_both_implemented) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Import keys.
    //
    first_key = vscf_key_alg_import_public_key(first_key_alg, raw_first_key, error);
    if (NULL == first_key) {
        goto cleanup;
    }

    second_key = vscf_key_alg_import_public_key(second_key_alg, raw_second_key, error);
    if (NULL == second_key) {
        goto cleanup;
    }

    //
    //  Make hybrid key.
    //
    public_key = vscf_hybrid_public_key_impl(
            vscf_hybrid_public_key_new_with_keys_disown(key_alg_info, &first_key, &second_key));

cleanup:
    vscf_raw_public_key_destroy(&raw_first_key);
    vscf_raw_public_key_destroy(&raw_second_key);
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&first_key);
    vscf_impl_destroy(&second_key_alg);
    vscf_impl_destroy(&second_key);

    return public_key;
}

//
//  Export public key to the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_public_key_t *
vscf_hybrid_key_alg_export_public_key(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_HYBRID_PUBLIC_KEY);

    //
    //  Export key data.
    //
    const size_t raw_key_buf_size = vscf_hybrid_key_alg_exported_public_key_data_len(self, public_key);
    vsc_buffer_t *raw_key_buf = vsc_buffer_new_with_capacity(raw_key_buf_size);

    const vscf_status_t export_status = vscf_hybrid_key_alg_export_public_key_data(self, public_key, raw_key_buf);
    if (export_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, export_status);
        return NULL;
    }

    //
    //  Export key alg info.
    //
    vscf_impl_t *alg_info = (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_key_alg_info(public_key));
    vscf_raw_public_key_t *raw_key = vscf_raw_public_key_new_with_buffer(&raw_key_buf, &alg_info);

    return raw_key;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PRIVATE size_t
vscf_hybrid_key_alg_exported_public_key_data_len(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return 0;
    }

    //
    //  Get correspond key algorithms.
    //
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_HYBRID_PUBLIC_KEY);
    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)public_key;

    const vscf_impl_t *first_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    const vscf_impl_t *second_key = vscf_hybrid_public_key_second_key(hybrid_public_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const size_t first_data_key_len = vscf_key_alg_exported_public_key_data_len(first_key_alg, first_key);
    const size_t second_data_key_len = vscf_key_alg_exported_public_key_data_len(second_key_alg, second_key);

    const size_t key_data_len = 1 + 4 +                      // HybridPublicKey ::= SEQUENCE {
                                1 + 4 + first_data_key_len + //     firstKey OCTET STRING,
                                1 + 4 + second_data_key_len; //     secondKey OCTET STRING }

    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return key_data_len;
}

//
//  Export public key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PRIVATE vscf_status_t
vscf_hybrid_key_alg_export_public_key_data(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    //
    // Write to the ASN.1 structure.
    //
    //  HybridPublicKey ::= SEQUENCE {
    //     firstKey OCTET STRING,
    //     secondKey OCTET STRING
    //  }
    //
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_hybrid_key_alg_exported_public_key_data_len(self, public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    vscf_error_t error;
    vscf_error_reset(&error);

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_HYBRID_PUBLIC_KEY);
    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)public_key;

    const vscf_impl_t *first_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    const vscf_impl_t *second_key = vscf_hybrid_public_key_second_key(hybrid_public_key);

    //
    //  Get correspond key algorithms.
    //
    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, &error);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, &error);
    VSCF_ASSERT_PTR(second_key_alg);

    vscf_raw_public_key_t *raw_first_key = NULL;
    vscf_raw_public_key_t *raw_second_key = NULL;

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(first_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(second_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //  TODO: Optimize memcpy by writing directly to the out.
    raw_first_key = vscf_key_alg_export_public_key(first_key_alg, first_key, &error);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    raw_second_key = vscf_key_alg_export_public_key(second_key_alg, second_key, &error);
    if (NULL == raw_second_key) {
        goto cleanup;
    }

    //
    //  Write.
    //
    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t raw_key_len = 0;
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(raw_second_key));
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(raw_first_key));
    raw_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_key_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(out));
    vscf_asn1wr_cleanup(&asn1wr);

    vsc_buffer_inc_used(out, raw_key_len);

cleanup:
    vscf_raw_public_key_destroy(&raw_first_key);
    vscf_raw_public_key_destroy(&raw_second_key);
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return vscf_error_status(&error);
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
vscf_hybrid_key_alg_import_private_key(
        const vscf_hybrid_key_alg_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_private_key_is_valid(raw_key));

    return vscf_hybrid_key_alg_import_private_key_data(
            self, vscf_raw_private_key_data(raw_key), vscf_raw_private_key_alg_info(raw_key), error);
}

//
//  Import private key from the raw binary format.
//
VSCF_PRIVATE vscf_impl_t *
vscf_hybrid_key_alg_import_private_key_data(
        const vscf_hybrid_key_alg_t *self, vsc_data_t key_data, const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    //
    //  Check if raw key is appropriate.
    //
    if (vscf_impl_tag(key_alg_info) != vscf_impl_tag_HYBRID_KEY_ALG_INFO) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_alg_info_alg_id(key_alg_info) == vscf_alg_id_HYBRID_KEY);

    //
    // Write to the ASN.1 structure.
    //
    // HybridPrivateKey ::= SEQUENCE {
    //     firstKey OCTET STRING,
    //     secondKey OCTET STRING
    // }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, key_data);
    vscf_asn1rd_read_sequence(&asn1rd);

    vsc_data_t first_key_data = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t second_key_data = vscf_asn1rd_read_octet_str(&asn1rd);

    const vscf_status_t asn1_status = vscf_asn1rd_status(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (asn1_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_HYBRID_PRIVATE_KEY);
        return NULL;
    }

    //
    //  Prepare keys to be imported.
    //
    const vscf_hybrid_key_alg_info_t *hybrid_key_alg_info = (const vscf_hybrid_key_alg_info_t *)key_alg_info;
    const vscf_impl_t *first_key_alg_info = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_key_alg_info);
    const vscf_impl_t *second_key_alg_info = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_key_alg_info);

    vscf_impl_t *first_key_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(first_key_alg_info);
    vscf_raw_private_key_t *raw_first_key =
            vscf_raw_private_key_new_with_data(first_key_data, &first_key_alg_info_copy);

    vscf_impl_t *second_key_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(second_key_alg_info);
    vscf_raw_private_key_t *raw_second_key =
            vscf_raw_private_key_new_with_data(second_key_data, &second_key_alg_info_copy);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *first_key_alg = NULL;
    vscf_impl_t *first_key = NULL;
    vscf_impl_t *second_key_alg = NULL;
    vscf_impl_t *second_key = NULL;
    vscf_impl_t *private_key = NULL;
    bool is_kem_both_implemented = false;
    bool is_key_signer_both_implemented = false;

    //
    //  Get correspond algs.
    //
    first_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(first_key_alg_info), self->random, error);

    if (NULL == first_key_alg) {
        goto cleanup;
    }

    second_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(second_key_alg_info), self->random, error);

    if (NULL == second_key_alg) {
        goto cleanup;
    }

    is_kem_both_implemented = vscf_kem_is_implemented(first_key_alg) && vscf_kem_is_implemented(second_key_alg);

    is_key_signer_both_implemented =
            vscf_key_signer_is_implemented(first_key_alg) && vscf_key_signer_is_implemented(second_key_alg);

    if (!is_kem_both_implemented && !is_key_signer_both_implemented) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Import keys.
    //
    first_key = vscf_key_alg_import_private_key(first_key_alg, raw_first_key, error);
    if (NULL == first_key) {
        goto cleanup;
    }

    second_key = vscf_key_alg_import_private_key(second_key_alg, raw_second_key, error);
    if (NULL == second_key) {
        goto cleanup;
    }

    //
    //  Make hybrid key.
    //
    private_key = vscf_hybrid_private_key_impl(
            vscf_hybrid_private_key_new_with_keys_disown(key_alg_info, &first_key, &second_key));

cleanup:
    vscf_raw_private_key_destroy(&raw_first_key);
    vscf_raw_private_key_destroy(&raw_second_key);
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&first_key);
    vscf_impl_destroy(&second_key_alg);
    vscf_impl_destroy(&second_key);

    return private_key;
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_private_key_t *
vscf_hybrid_key_alg_export_private_key(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY);

    const size_t raw_key_buf_size = vscf_hybrid_key_alg_exported_private_key_data_len(self, private_key);
    vsc_buffer_t *raw_key_buf = vsc_buffer_new_with_capacity(raw_key_buf_size);

    const vscf_status_t export_status = vscf_hybrid_key_alg_export_private_key_data(self, private_key, raw_key_buf);

    if (export_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, export_status);
        return NULL;
    }

    vscf_impl_t *alg_info = (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_key_alg_info(private_key));
    vscf_raw_private_key_t *raw_key = vscf_raw_private_key_new_with_buffer(&raw_key_buf, &alg_info);

    return raw_key;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PRIVATE size_t
vscf_hybrid_key_alg_exported_private_key_data_len(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return 0;
    }

    //
    //  Get correspond key algorithms.
    //
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY);
    const vscf_hybrid_private_key_t *hybrid_private_key = (const vscf_hybrid_private_key_t *)private_key;

    const vscf_impl_t *first_key = vscf_hybrid_private_key_first_key(hybrid_private_key);
    const vscf_impl_t *second_key = vscf_hybrid_private_key_second_key(hybrid_private_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const size_t first_data_key_len = vscf_key_alg_exported_private_key_data_len(first_key_alg, first_key);
    const size_t second_data_key_len = vscf_key_alg_exported_private_key_data_len(second_key_alg, second_key);

    const size_t key_data_len = 1 + 4 +                      // HybridPrivateKey ::= SEQUENCE {
                                1 + 4 + first_data_key_len + //     firstKey OCTET STRING,
                                1 + 4 + second_data_key_len; //     secondKey OCTET STRING }

    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return key_data_len;
}

//
//  Export private key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PRIVATE vscf_status_t
vscf_hybrid_key_alg_export_private_key_data(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    //
    // Write to the ASN.1 structure.
    //
    // HybridPrivateKey ::= SEQUENCE {
    //     firstKey OCTET STRING,
    //     signerKey OCTET STRING
    // }
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_hybrid_key_alg_exported_private_key_data_len(self, private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    vscf_error_t error;
    vscf_error_reset(&error);

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY);
    const vscf_hybrid_private_key_t *hybrid_private_key = (const vscf_hybrid_private_key_t *)private_key;

    const vscf_impl_t *first_key = vscf_hybrid_private_key_first_key(hybrid_private_key);
    const vscf_impl_t *second_key = vscf_hybrid_private_key_second_key(hybrid_private_key);

    //
    //  Get correspond key algorithms.
    //
    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, &error);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, &error);
    VSCF_ASSERT_PTR(second_key_alg);

    vscf_raw_private_key_t *raw_first_key = NULL;
    vscf_raw_private_key_t *raw_second_key = NULL;

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(first_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(second_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //  TODO: Optimize memcpy by writing directly to the out.
    raw_first_key = vscf_key_alg_export_private_key(first_key_alg, first_key, &error);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    raw_second_key = vscf_key_alg_export_private_key(second_key_alg, second_key, &error);
    if (NULL == raw_second_key) {
        goto cleanup;
    }

    //
    //  Write.
    //
    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t raw_key_len = 0;
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(raw_second_key));
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(raw_first_key));
    raw_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_key_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(out));
    vscf_asn1wr_cleanup(&asn1wr);

    vsc_buffer_inc_used(out, raw_key_len);

cleanup:
    vscf_raw_private_key_destroy(&raw_first_key);
    vscf_raw_private_key_destroy(&raw_second_key);
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return vscf_error_status(&error);
}

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_hybrid_key_alg_can_encrypt(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_UNUSED(data_len);

    if (vscf_impl_tag(public_key) == vscf_impl_tag_HYBRID_PUBLIC_KEY) {
        return true;
    }

    return false;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_hybrid_key_alg_encrypted_len(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(public_key);

    if (vscf_impl_tag(public_key) != vscf_impl_tag_HYBRID_PUBLIC_KEY) {
        return 0;
    }

    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)public_key;
    const vscf_impl_t *first_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    const vscf_impl_t *second_key = vscf_hybrid_public_key_second_key(hybrid_public_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);
    const size_t first_encapsulated_key_len = vscf_kem_kem_encapsulated_key_len(first_key_alg, first_key);
    vscf_impl_destroy(&first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);
    const size_t second_encapsulated_key_len = vscf_kem_kem_encapsulated_key_len(second_key_alg, second_key);
    vscf_impl_destroy(&second_key_alg);

    const size_t hybrid_encrypted_content_info_len =
            1 + 4 +                              //  HybridEncryptedContentInfo ::= SEQUENCE {
            1 + 1 + 1 +                          //      version INTEGER { v0(0) },
            1 + 1 + 16 +                         //      hash OBJECT IDENTIFIER,
            1 + 1 + 16 +                         //      cipher OBJECT IDENTIFIER,
            1 + 3 + first_encapsulated_key_len + //      firstEncapsulatedKey OCTET STRING,
            1 + 3 + second_encapsulated_key_len; //      secondEncapsulatedKey OCTET STRING }

    const size_t len = hybrid_encrypted_content_info_len + vscf_encrypt_encrypted_len(self->cipher, data_len);

    return len;
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_hybrid_key_alg_encrypt(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_hybrid_key_alg_can_encrypt(self, public_key, data.len));
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_HYBRID_PUBLIC_KEY);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_hybrid_key_alg_encrypted_len(self, public_key, data.len));

    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)public_key;
    const vscf_impl_t *first_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    const vscf_impl_t *second_key = vscf_hybrid_public_key_second_key(hybrid_public_key);

    //
    //  Prepare algs.
    //
    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    //
    //  Prepare vars.
    //
    const size_t first_shared_key_len = vscf_kem_kem_shared_key_len(first_key_alg, first_key);
    vsc_buffer_t *first_shared_key = vsc_buffer_new_with_capacity(first_shared_key_len);
    vsc_buffer_make_secure(first_shared_key);

    const size_t first_encapsulated_key_len = vscf_kem_kem_encapsulated_key_len(first_key_alg, first_key);
    vsc_buffer_t *first_encapsulated_key = vsc_buffer_new_with_capacity(first_encapsulated_key_len);
    vsc_buffer_make_secure(first_encapsulated_key);

    const size_t second_shared_key_len = vscf_kem_kem_shared_key_len(second_key_alg, second_key);
    vsc_buffer_t *second_shared_key = vsc_buffer_new_with_capacity(second_shared_key_len);
    vsc_buffer_make_secure(second_shared_key);

    const size_t second_encapsulated_key_len = vscf_kem_kem_encapsulated_key_len(second_key_alg, second_key);
    vsc_buffer_t *second_encapsulated_key = vsc_buffer_new_with_capacity(second_encapsulated_key_len);
    vsc_buffer_make_secure(second_encapsulated_key);


    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Get shared keys via KEM and configure cipher.
    //
    error.status = vscf_kem_kem_encapsulate(first_key_alg, first_key, first_shared_key, first_encapsulated_key);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    error.status = vscf_kem_kem_encapsulate(second_key_alg, second_key, second_shared_key, second_encapsulated_key);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(first_shared_key_len + second_shared_key_len);
    vsc_buffer_make_secure(shared_key);
    vsc_buffer_write_data(shared_key, vsc_buffer_data(first_shared_key));
    vsc_buffer_write_data(shared_key, vsc_buffer_data(second_shared_key));

    vscf_hybrid_key_alg_config_cipher(self->cipher, self->hash, vsc_buffer_data(shared_key));

    vsc_buffer_destroy(&shared_key);

    //
    //  Write ciphertext content info.
    //
    //  HybridEncryptedContentInfo ::= SEQUENCE {
    //      version INTEGER { v0(0) },
    //      hash OBJECT IDENTIFIER,
    //      cipher OBJECT IDENTIFIER,
    //      firstEncapsulatedKey OCTET STRING,
    //      secondEncapsulatedKey OCTET STRING
    //  }
    //

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    size_t written_alg_info_len = 0;
    written_alg_info_len += vscf_asn1wr_write_octet_str(&asn1wr, vsc_buffer_data(second_encapsulated_key));
    written_alg_info_len += vscf_asn1wr_write_octet_str(&asn1wr, vsc_buffer_data(first_encapsulated_key));
    written_alg_info_len += vscf_asn1wr_write_oid(&asn1wr, vscf_oid_from_alg_id(vscf_alg_alg_id(self->cipher)));
    written_alg_info_len += vscf_asn1wr_write_oid(&asn1wr, vscf_oid_from_alg_id(vscf_alg_alg_id(self->hash)));
    written_alg_info_len += vscf_asn1wr_write_int(&asn1wr, 0);
    written_alg_info_len += vscf_asn1wr_write_sequence(&asn1wr, written_alg_info_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, false);
    vscf_asn1wr_cleanup(&asn1wr);
    vsc_buffer_inc_used(out, written_alg_info_len);

    //
    //  Encrypt.
    //
    error.status = vscf_encrypt(self->cipher, data, out);

cleanup:
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);
    vsc_buffer_destroy(&first_shared_key);
    vsc_buffer_destroy(&first_encapsulated_key);
    vsc_buffer_destroy(&second_shared_key);
    vsc_buffer_destroy(&second_encapsulated_key);

    return vscf_error_status(&error);
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_hybrid_key_alg_can_decrypt(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_UNUSED(data_len);

    if (vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY) {
        return true;
    }

    return false;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_hybrid_key_alg_decrypted_len(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(private_key);

    if (vscf_impl_tag(private_key) != vscf_impl_tag_HYBRID_PRIVATE_KEY) {
        return 0;
    }

    return data_len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_hybrid_key_alg_decrypt(
        const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_hybrid_key_alg_can_decrypt(self, private_key, data.len));
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_hybrid_key_alg_decrypted_len(self, private_key, data.len));

    //
    //  Read ciphertext content info.
    //
    //  HybridEncryptedContentInfo ::= SEQUENCE {
    //      version INTEGER { v0(0) },
    //      hash OBJECT IDENTIFIER,
    //      cipher OBJECT IDENTIFIER,
    //      firstEncapsulatedKey OCTET STRING,
    //      secondEncapsulatedKey OCTET STRING
    //  }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, data);

    const size_t content_info_len = vscf_asn1rd_get_data_len(&asn1rd);
    if (vscf_asn1rd_has_error(&asn1rd) || (content_info_len > data.len)) {
        vscf_asn1rd_cleanup(&asn1rd);
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    vsc_data_t content_info = vsc_data_slice_beg(data, 0, content_info_len);
    vsc_data_t encrypted_content = vsc_data_slice_beg(data, content_info_len, data.len - content_info_len);

    vscf_asn1rd_reset(&asn1rd, content_info);
    vscf_asn1rd_read_sequence(&asn1rd);
    const int version = vscf_asn1rd_read_int(&asn1rd);
    vsc_data_t hash_oid = vscf_asn1rd_read_oid(&asn1rd);
    vsc_data_t cipher_oid = vscf_asn1rd_read_oid(&asn1rd);
    vsc_data_t first_encapsulated_key = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t second_encapsulated_key = vscf_asn1rd_read_octet_str(&asn1rd);

    if (vscf_asn1rd_has_error(&asn1rd) || (version != 0) || (vscf_asn1rd_left_len(&asn1rd) > 0)) {
        vscf_asn1rd_cleanup(&asn1rd);
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }
    vscf_asn1rd_cleanup(&asn1rd);

    const vscf_alg_id_t hash_alg_id = vscf_oid_to_alg_id(hash_oid);
    const vscf_alg_id_t cipher_alg_id = vscf_oid_to_alg_id(cipher_oid);
    if ((hash_alg_id == vscf_alg_id_NONE) || (cipher_alg_id == vscf_alg_id_NONE)) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    vscf_impl_t *hash = vscf_alg_factory_create_hash_from_alg_id(hash_alg_id);
    VSCF_ASSERT_PTR(hash);

    vscf_impl_t *cipher = vscf_alg_factory_create_cipher_from_alg_id(cipher_alg_id);
    VSCF_ASSERT_PTR(cipher);

    const vscf_hybrid_private_key_t *hybrid_private_key = (const vscf_hybrid_private_key_t *)private_key;
    const vscf_impl_t *first_key = vscf_hybrid_private_key_first_key(hybrid_private_key);
    const vscf_impl_t *second_key = vscf_hybrid_private_key_second_key(hybrid_private_key);

    //
    //  Prepare algs.
    //
    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    //
    //  Prepare vars.
    //
    const size_t first_shared_key_len = vscf_kem_kem_shared_key_len(first_key_alg, first_key);
    vsc_buffer_t *first_shared_key = vsc_buffer_new_with_capacity(first_shared_key_len);
    vsc_buffer_make_secure(first_shared_key);

    const size_t second_shared_key_len = vscf_kem_kem_shared_key_len(second_key_alg, second_key);
    vsc_buffer_t *second_shared_key = vsc_buffer_new_with_capacity(second_shared_key_len);
    vsc_buffer_make_secure(second_shared_key);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Get shared keys via KEM and configure cipher.
    //
    error.status = vscf_kem_kem_decapsulate(first_key_alg, first_encapsulated_key, first_key, first_shared_key);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    error.status = vscf_kem_kem_decapsulate(second_key_alg, second_encapsulated_key, second_key, second_shared_key);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(first_shared_key_len + second_shared_key_len);
    vsc_buffer_make_secure(shared_key);
    vsc_buffer_write_data(shared_key, vsc_buffer_data(first_shared_key));
    vsc_buffer_write_data(shared_key, vsc_buffer_data(second_shared_key));

    vscf_hybrid_key_alg_config_cipher(cipher, hash, vsc_buffer_data(shared_key));

    vsc_buffer_destroy(&shared_key);

    //
    //  Encrypt.
    //
    error.status = vscf_decrypt(cipher, encrypted_content, out);

cleanup:
    vscf_impl_destroy(&hash);
    vscf_impl_destroy(&cipher);
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);
    vsc_buffer_destroy(&first_shared_key);
    vsc_buffer_destroy(&second_shared_key);
    vscf_asn1rd_cleanup(&asn1rd);

    return vscf_error_status(&error);
}

//
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_hybrid_key_alg_can_sign(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY);

    const vscf_hybrid_private_key_t *hybrid_private_key = (const vscf_hybrid_private_key_t *)private_key;
    const vscf_impl_t *first_key = vscf_hybrid_private_key_first_key(hybrid_private_key);
    const vscf_impl_t *second_key = vscf_hybrid_private_key_second_key(hybrid_private_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const bool first_key_can_sign = vscf_key_signer_can_sign(first_key_alg, first_key);
    const bool second_key_can_sign = vscf_key_signer_can_sign(second_key_alg, second_key);

    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return first_key_can_sign && second_key_can_sign;
}

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_hybrid_key_alg_signature_len(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_HYBRID_PRIVATE_KEY);

    const vscf_hybrid_private_key_t *hybrid_private_key = (const vscf_hybrid_private_key_t *)private_key;
    const vscf_impl_t *first_key = vscf_hybrid_private_key_first_key(hybrid_private_key);
    const vscf_impl_t *second_key = vscf_hybrid_private_key_second_key(hybrid_private_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const size_t first_key_signature_len = vscf_key_signer_signature_len(first_key_alg, first_key);
    const size_t second_key_signature_len = vscf_key_signer_signature_len(second_key_alg, second_key);

    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    if (first_key_signature_len == 0 || second_key_signature_len == 0) {
        //  One of the keys (or both) can not produce signature.
        return 0;
    }

    const size_t len = 1 + 4 +                           // HybridSignature ::= SEQUENCE {
                       1 + 3 + first_key_signature_len + //     firstKeySignature OCTET STRING,
                       1 + 3 + second_key_signature_len; //     secondKeySignature OCTET STRING }


    return len;
}

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_hybrid_key_alg_sign_hash(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *private_key, vscf_alg_id_t hash_id,
        vsc_data_t digest, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_hybrid_key_alg_can_sign(self, private_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(vsc_buffer_unused_len(signature) >= vscf_hybrid_key_alg_signature_len(self, private_key));

    const vscf_hybrid_private_key_t *hybrid_private_key = (const vscf_hybrid_private_key_t *)private_key;
    const vscf_impl_t *first_key = vscf_hybrid_private_key_first_key(hybrid_private_key);
    const vscf_impl_t *second_key = vscf_hybrid_private_key_second_key(hybrid_private_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const size_t first_key_signature_len = vscf_key_signer_signature_len(first_key_alg, first_key);
    vsc_buffer_t *first_key_signature = vsc_buffer_new_with_capacity(first_key_signature_len);

    const size_t second_key_signature_len = vscf_key_signer_signature_len(second_key_alg, second_key);
    vsc_buffer_t *second_key_signature = vsc_buffer_new_with_capacity(second_key_signature_len);

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);

    size_t signature_len = 0;

    vscf_status_t status = vscf_key_signer_sign_hash(first_key_alg, first_key, hash_id, digest, first_key_signature);
    if (vscf_status_SUCCESS != status) {
        goto cleanup;
    }

    status = vscf_key_signer_sign_hash(second_key_alg, second_key, hash_id, digest, second_key_signature);
    if (vscf_status_SUCCESS != status) {
        goto cleanup;
    }

    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(signature), vsc_buffer_unused_len(signature));

    signature_len += vscf_asn1wr_write_octet_str(&asn1wr, vsc_buffer_data(second_key_signature));
    signature_len += vscf_asn1wr_write_octet_str(&asn1wr, vsc_buffer_data(first_key_signature));
    signature_len += vscf_asn1wr_write_sequence(&asn1wr, signature_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(signature));
    vsc_buffer_inc_used(signature, signature_len);

cleanup:
    vscf_asn1wr_cleanup(&asn1wr);
    vsc_buffer_destroy(&first_key_signature);
    vsc_buffer_destroy(&second_key_signature);
    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return status;
}

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_hybrid_key_alg_can_verify(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_HYBRID_PUBLIC_KEY);

    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)public_key;
    const vscf_impl_t *first_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    const vscf_impl_t *second_key = vscf_hybrid_public_key_second_key(hybrid_public_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const bool first_key_can_verify = vscf_key_signer_can_verify(first_key_alg, first_key);
    const bool second_key_can_verify = vscf_key_signer_can_verify(second_key_alg, second_key);

    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return first_key_can_verify && second_key_can_verify;
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_hybrid_key_alg_verify_hash(const vscf_hybrid_key_alg_t *self, const vscf_impl_t *public_key, vscf_alg_id_t hash_id,
        vsc_data_t digest, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_hybrid_key_alg_can_verify(self, public_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));

    //
    // Read signature.
    //
    // HybridSignature ::= SEQUENCE {
    //     firstKeySignature OCTET STRING,
    //     secondKeySignature OCTET STRING
    // }
    //

    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, signature);

    vscf_asn1rd_read_sequence(&asn1rd);
    vsc_data_t first_key_signature = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t second_key_signature = vscf_asn1rd_read_octet_str(&asn1rd);

    const bool is_valid_format = !vscf_asn1rd_has_error(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (!is_valid_format) {
        return false;
    }

    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)public_key;
    const vscf_impl_t *first_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    const vscf_impl_t *second_key = vscf_hybrid_public_key_second_key(hybrid_public_key);

    vscf_impl_t *first_key_alg = vscf_key_alg_factory_create_from_key(first_key, self->random, NULL);
    VSCF_ASSERT_PTR(first_key_alg);

    vscf_impl_t *second_key_alg = vscf_key_alg_factory_create_from_key(second_key, self->random, NULL);
    VSCF_ASSERT_PTR(second_key_alg);

    const bool first_key_is_verified =
            vscf_key_signer_verify_hash(first_key_alg, first_key, hash_id, digest, first_key_signature);
    const bool second_key_is_verified =
            vscf_key_signer_verify_hash(second_key_alg, second_key, hash_id, digest, second_key_signature);

    vscf_impl_destroy(&first_key_alg);
    vscf_impl_destroy(&second_key_alg);

    return first_key_is_verified && second_key_is_verified;
}
