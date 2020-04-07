//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  This module contains 'round5' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_round5.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_simple_alg_info.h"
#include "vscf_raw_public_key_defs.h"
#include "vscf_raw_private_key_defs.h"
#include "vscf_random.h"
#include "vscf_round5_defs.h"
#include "vscf_round5_internal.h"

#include <round5/rng.h>
#include <round5/r5_cca_kem.h>
#include <round5/r5_parameter_sets.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vscf_round5_SEED_LEN = 48
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_setup_defaults(vscf_round5_t *self) {

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
vscf_round5_generate_key(const vscf_round5_t *self, vscf_alg_id_t alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(alg_id != vscf_alg_id_NONE);

    if (alg_id != vscf_alg_id_ROUND5_ND_5KEM_5D) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    const size_t sk_len = CRYPTO_SECRETKEYBYTES;
    const size_t pk_len = CRYPTO_PUBLICKEYBYTES;

    //
    //  Make random SEED
    //
    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_round5_SEED_LEN);
    const vscf_status_t rng_status = vscf_random(self->random, vscf_round5_SEED_LEN, seed);
    if (rng_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, rng_status);
        vsc_buffer_destroy(&seed);
        return NULL;
    }
    vsc_buffer_make_secure(seed);

    vsc_buffer_t *sk = vsc_buffer_new_with_capacity(sk_len);
    vsc_buffer_t *pk = vsc_buffer_new_with_capacity(pk_len);

    //
    //  Initialize DRBG
    //
    VSCF_ATOMIC_CRITICAL_SECTION_DECLARE(keygen);
    VSCF_ATOMIC_CRITICAL_SECTION_BEGIN(keygen);
    randombytes_init(vsc_buffer_begin(seed), NULL, 1 /* is not used, so can be any */);

    //
    //  Generate keys
    //
    const int gen_status = r5_cca_kem_keygen(vsc_buffer_unused_bytes(pk), vsc_buffer_unused_bytes(sk));
    VSCF_ATOMIC_CRITICAL_SECTION_END(keygen);
    vsc_buffer_destroy(&seed);

    if (gen_status != 0) {
        vsc_buffer_destroy(&pk);
        vsc_buffer_destroy(&sk);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_RANDOM_FAILED);
    }

    vsc_buffer_make_secure(sk);
    vsc_buffer_inc_used(pk, pk_len);
    vsc_buffer_inc_used(sk, sk_len);

    vscf_impl_t *pub_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5KEM_5D));
    vscf_impl_t *priv_alg_info = vscf_impl_shallow_copy(pub_alg_info);

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_buffer(&pk, &pub_alg_info);
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_buffer(&sk, &priv_alg_info);

    raw_public_key->impl_tag = self->info->impl_tag;
    raw_private_key->impl_tag = self->info->impl_tag;

    vscf_raw_private_key_set_public_key(raw_private_key, &raw_public_key);

    return vscf_raw_private_key_impl(raw_private_key);
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_generate_ephemeral_key(const vscf_round5_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    if (vscf_key_impl_tag(key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    return vscf_round5_generate_key(self, vscf_key_alg_id(key), error);
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
vscf_round5_import_public_key(const vscf_round5_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_public_key_is_valid(raw_key));

    return vscf_round5_import_public_key_data(
            self, vscf_raw_public_key_data(raw_key), vscf_raw_public_key_alg_info(raw_key), error);
}

//
//  Import public key from the raw binary format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_import_public_key_data(
        const vscf_round5_t *self, vsc_data_t key_data, const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    if (vscf_alg_info_alg_id(key_alg_info) != vscf_alg_id_ROUND5_ND_5KEM_5D) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    if (key_data.len != CRYPTO_PUBLICKEYBYTES) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ROUND5_PUBLIC_KEY);
        return NULL;
    }

    vscf_raw_public_key_t *public_key =
            vscf_raw_public_key_new_with_members(key_data, key_alg_info, self->info->impl_tag);

    return vscf_raw_public_key_impl(public_key);
}

//
//  Export public key to the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_public_key_t *
vscf_round5_export_public_key(const vscf_round5_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_RAW_PUBLIC_KEY);
    vscf_raw_public_key_t *raw_public_key = (vscf_raw_public_key_t *)(public_key);

    return vscf_raw_public_key_shallow_copy(raw_public_key);
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_round5_exported_public_key_data_len(const vscf_round5_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));

    return CRYPTO_PUBLICKEYBYTES;
}

//
//  Export public key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_export_public_key_data(const vscf_round5_t *self, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_round5_exported_public_key_data_len(self, public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_RAW_PUBLIC_KEY);
    vscf_raw_public_key_t *raw_public_key = (vscf_raw_public_key_t *)(public_key);

    vsc_buffer_write_data(out, vscf_raw_public_key_data(raw_public_key));

    return vscf_status_SUCCESS;
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
vscf_round5_import_private_key(const vscf_round5_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_private_key_is_valid(raw_key));

    return vscf_round5_import_private_key_data(
            self, vscf_raw_private_key_data(raw_key), vscf_raw_private_key_alg_info(raw_key), error);
}

//
//  Import private key from the raw binary format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_import_private_key_data(
        const vscf_round5_t *self, vsc_data_t key_data, const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    if (vscf_alg_info_alg_id(key_alg_info) != vscf_alg_id_ROUND5_ND_5KEM_5D) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    const size_t pk_len = CRYPTO_PUBLICKEYBYTES;
    const size_t sk_len = CRYPTO_SECRETKEYBYTES;

    if (key_data.len != CRYPTO_SECRETKEYBYTES) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY);
        return NULL;
    }

    //
    //  Extract public key (private key includes public key)
    //
    VSCF_ASSERT(pk_len < sk_len);
    vsc_buffer_t *public_key_buf = vsc_buffer_new_with_data(vsc_data_slice_end(key_data, 0, pk_len));

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new();
    raw_public_key->buffer = public_key_buf;
    raw_public_key->alg_info = vscf_impl_shallow_copy((vscf_impl_t *)key_alg_info);
    raw_public_key->impl_tag = self->info->impl_tag;

    //  Configure private key.
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_members(key_data, key_alg_info, self->info->impl_tag);
    vscf_raw_private_key_set_public_key(raw_private_key, &raw_public_key);

    return vscf_raw_private_key_impl(raw_private_key);
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_private_key_t *
vscf_round5_export_private_key(const vscf_round5_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_RAW_PRIVATE_KEY);
    vscf_raw_private_key_t *raw_private_key = (vscf_raw_private_key_t *)(private_key);

    return vscf_raw_private_key_shallow_copy(raw_private_key);
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_round5_exported_private_key_data_len(const vscf_round5_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));

    return CRYPTO_SECRETKEYBYTES;
}

//
//  Export private key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_export_private_key_data(const vscf_round5_t *self, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_round5_exported_private_key_data_len(self, private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_RAW_PRIVATE_KEY);
    vscf_raw_private_key_t *raw_private_key = (vscf_raw_private_key_t *)(private_key);

    vsc_buffer_write_data(out, vscf_raw_private_key_data(raw_private_key));

    return vscf_status_SUCCESS;
}

//
//  Return length in bytes required to hold encapsulated shared key.
//
VSCF_PUBLIC size_t
vscf_round5_kem_shared_key_len(const vscf_round5_t *self, const vscf_impl_t *key) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(key);

    return PARAMS_KAPPA_BYTES;
}

//
//  Return length in bytes required to hold encapsulated key.
//
VSCF_PUBLIC size_t
vscf_round5_kem_encapsulated_key_len(const vscf_round5_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(public_key);

    return PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;
}

//
//  Generate a shared key and a key encapsulated message.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_kem_encapsulate(const vscf_round5_t *self, const vscf_impl_t *public_key, vsc_buffer_t *shared_key,
        vsc_buffer_t *encapsulated_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_PTR(shared_key);
    VSCF_ASSERT(vsc_buffer_is_valid(shared_key));
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= vscf_round5_kem_shared_key_len(self, public_key));
    VSCF_ASSERT_PTR(encapsulated_key);
    VSCF_ASSERT(vsc_buffer_is_valid(encapsulated_key));
    VSCF_ASSERT(vsc_buffer_unused_len(encapsulated_key) >= vscf_round5_kem_encapsulated_key_len(self, public_key));

    //
    //  Make random SEED
    //
    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_round5_SEED_LEN);
    const vscf_status_t rng_status = vscf_random(self->random, vscf_round5_SEED_LEN, seed);
    if (rng_status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&seed);
        return rng_status;
    }
    vsc_buffer_make_secure(seed);

    vsc_data_t public_key_data = vscf_raw_public_key_data((vscf_raw_public_key_t *)public_key);

    //
    //  Initialize DRBG
    //
    VSCF_ATOMIC_CRITICAL_SECTION_DECLARE(encapsulate);
    VSCF_ATOMIC_CRITICAL_SECTION_BEGIN(encapsulate);
    randombytes_init(vsc_buffer_begin(seed), NULL, 1 /* is not used, so can be any */);

    //
    //  Encrypt
    //
    const int enc_status = r5_cca_kem_encapsulate(
            vsc_buffer_unused_bytes(encapsulated_key), vsc_buffer_unused_bytes(shared_key), public_key_data.bytes);

    VSCF_ATOMIC_CRITICAL_SECTION_END(encapsulate);
    vsc_buffer_destroy(&seed);

    if (enc_status == 0) {
        vsc_buffer_inc_used(encapsulated_key, vscf_round5_kem_encapsulated_key_len(self, public_key));
        vsc_buffer_inc_used(shared_key, vscf_round5_kem_shared_key_len(self, public_key));
        return vscf_status_SUCCESS;
    }

    return vscf_status_ERROR_ROUND5;
}

//
//  Decapsulate the shared key.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_kem_decapsulate(const vscf_round5_t *self, vsc_data_t encapsulated_key, const vscf_impl_t *private_key,
        vsc_buffer_t *shared_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT_PTR(shared_key);
    VSCF_ASSERT(vsc_buffer_is_valid(shared_key));
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= vscf_round5_kem_shared_key_len(self, private_key));

    if (encapsulated_key.len != vscf_round5_kem_encapsulated_key_len(self, private_key)) {
        return vscf_status_ERROR_ROUND5;
    }

    vsc_data_t private_key_data = vscf_raw_private_key_data((vscf_raw_private_key_t *)private_key);
    const int status =
            r5_cca_kem_decapsulate(vsc_buffer_unused_bytes(shared_key), encapsulated_key.bytes, private_key_data.bytes);

    if (status == 0) {
        vsc_buffer_inc_used(shared_key, vscf_round5_kem_shared_key_len(self, private_key));
        return vscf_status_SUCCESS;
    }

    return vscf_status_ERROR_ROUND5;
}
