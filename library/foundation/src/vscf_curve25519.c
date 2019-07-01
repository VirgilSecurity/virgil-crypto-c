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
//  This module contains 'curve25519' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_curve25519.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_simple_alg_info.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_raw_public_key_defs.h"
#include "vscf_raw_private_key_defs.h"
#include "vscf_random.h"
#include "vscf_curve25519_defs.h"
#include "vscf_curve25519_internal.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

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
//  This method is called when class 'ecies' was setup.
//
VSCF_PRIVATE void
vscf_curve25519_did_setup_ecies(vscf_curve25519_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);

    vscf_ecies_set_key_alg(self->ecies, vscf_curve25519_impl(self));
}

//
//  This method is called when class 'ecies' was released.
//
VSCF_PRIVATE void
vscf_curve25519_did_release_ecies(vscf_curve25519_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_setup_defaults(vscf_curve25519_t *self) {

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

    if (NULL == self->ecies) {
        vscf_ecies_t *ecies = vscf_ecies_new();
        vscf_ecies_use_random(ecies, self->random);
        vscf_status_t status = vscf_ecies_setup_defaults(ecies);

        if (status != vscf_status_SUCCESS) {
            vscf_ecies_destroy(&ecies);
            return status;
        }

        vscf_curve25519_take_ecies(self, ecies);
    }

    return vscf_status_SUCCESS;
}

//
//  Generate new private key.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_curve25519_generate_key(const vscf_curve25519_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vsc_buffer_t *private_key_buf = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);

    vscf_status_t status = vscf_random(self->random, ED25519_KEY_LEN, private_key_buf);
    if (status != vscf_status_SUCCESS || vsc_buffer_len(private_key_buf) != ED25519_KEY_LEN) {
        vsc_buffer_destroy(&private_key_buf);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_KEY_GENERATION_FAILED);
        return NULL;
    }

    vsc_buffer_t *public_key_buf = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    const int ret = curve25519_get_pubkey(vsc_buffer_unused_bytes(public_key_buf), vsc_buffer_bytes(private_key_buf));
    VSCF_ASSERT(ret == 0);
    vsc_buffer_inc_used(public_key_buf, ED25519_KEY_LEN);

    vscf_impl_t *pub_alg_info = vscf_curve25519_produce_alg_info(self);
    vscf_impl_t *priv_alg_info = vscf_impl_shallow_copy(pub_alg_info);

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_buffer(&public_key_buf, &pub_alg_info);
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_buffer(&private_key_buf, &priv_alg_info);

    raw_public_key->impl_tag = self->info->impl_tag;
    raw_private_key->impl_tag = self->info->impl_tag;

    vscf_raw_private_key_set_public_key(raw_private_key, &raw_public_key);

    return vscf_raw_private_key_impl(raw_private_key);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_curve25519_alg_id(const vscf_curve25519_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_CURVE25519;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_curve25519_produce_alg_info(const vscf_curve25519_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_restore_alg_info(vscf_curve25519_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_CURVE25519);

    return vscf_status_SUCCESS;
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_curve25519_generate_ephemeral_key(const vscf_curve25519_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    if (vscf_key_impl_tag(key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    return vscf_curve25519_generate_key(self, error);
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
vscf_curve25519_import_public_key(
        const vscf_curve25519_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_public_key_is_valid(raw_key));

    if (vscf_raw_public_key_alg_id(raw_key) != vscf_alg_id_CURVE25519) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    vsc_data_t raw_key_data = vscf_raw_public_key_data(raw_key);
    if (raw_key_data.len != ED25519_KEY_LEN) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY);
        return NULL;
    }

    vscf_raw_public_key_t *public_key = vscf_raw_public_key_new_with_redefined_impl_tag(raw_key, self->info->impl_tag);
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
vscf_curve25519_export_public_key(const vscf_curve25519_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

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
vscf_curve25519_import_private_key(
        const vscf_curve25519_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_private_key_is_valid(raw_key));

    if (vscf_raw_private_key_alg_id(raw_key) != vscf_alg_id_CURVE25519) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    vsc_data_t raw_key_data = vscf_raw_private_key_data(raw_key);
    if (raw_key_data.len != ED25519_KEY_LEN) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY);
        return NULL;
    }

    //  Extract public key
    vsc_buffer_t *public_key_buf = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    const int ret =
            curve25519_get_pubkey(vsc_buffer_unused_bytes(public_key_buf), vscf_raw_private_key_data(raw_key).bytes);
    VSCF_ASSERT(ret == 0);
    vsc_buffer_inc_used(public_key_buf, ED25519_KEY_LEN);

    vscf_impl_t *alg_info = (vscf_impl_t *)vscf_raw_private_key_alg_info(raw_key);
    VSCF_ASSERT_PTR(alg_info);

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_buffer(&public_key_buf, &alg_info);
    raw_public_key->impl_tag = self->info->impl_tag;

    //  Configure privat key
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_redefined_impl_tag(raw_key, self->info->impl_tag);
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
vscf_curve25519_export_private_key(const vscf_curve25519_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

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
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_curve25519_can_encrypt(const vscf_curve25519_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_UNUSED(data_len);

    bool is_my_impl = vscf_key_impl_tag(public_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_curve25519_encrypted_len(const vscf_curve25519_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_UNUSED(data_len);

    return vscf_ecies_encrypted_len(self->ecies, public_key, data_len);
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_encrypt(
        const vscf_curve25519_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_curve25519_can_encrypt(self, public_key, data.len));
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_curve25519_encrypted_len(self, public_key, data.len));

    vscf_status_t status = vscf_ecies_encrypt(self->ecies, public_key, data, out);
    return status;
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_curve25519_can_decrypt(const vscf_curve25519_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_UNUSED(data_len);

    bool is_my_impl = vscf_key_impl_tag(private_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_curve25519_decrypted_len(const vscf_curve25519_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_curve25519_can_decrypt(self, private_key, data_len));

    return vscf_ecies_decrypted_len(self->ecies, private_key, data_len);
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_decrypt(
        const vscf_curve25519_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_curve25519_can_decrypt(self, private_key, data.len));
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_curve25519_decrypted_len(self, private_key, data.len));

    vscf_status_t status = vscf_ecies_decrypt(self->ecies, private_key, data, out);
    return status;
}

//
//  Compute shared key for 2 asymmetric keys.
//  Note, computed shared key can be used only within symmetric cryptography.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_compute_shared_key(const vscf_curve25519_t *self, const vscf_impl_t *public_key,
        const vscf_impl_t *private_key, vsc_buffer_t *shared_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(shared_key));
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= vscf_curve25519_shared_key_len(self, public_key));


    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_RAW_PUBLIC_KEY);
    vsc_data_t public_key_data = vscf_raw_public_key_data((vscf_raw_public_key_t *)public_key);


    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_RAW_PRIVATE_KEY);
    vsc_data_t private_key_data = vscf_raw_private_key_data((vscf_raw_private_key_t *)private_key);

    const int status =
            curve25519_key_exchange(vsc_buffer_unused_bytes(shared_key), public_key_data.bytes, private_key_data.bytes);

    if (status != 0) {
        return vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED;
    }

    vsc_buffer_inc_used(shared_key, vscf_curve25519_shared_key_len(self, public_key));

    return vscf_status_SUCCESS;
}

//
//  Return number of bytes required to hold shared key.
//  Expect Public Key or Private Key.
//
VSCF_PUBLIC size_t
vscf_curve25519_shared_key_len(const vscf_curve25519_t *self, const vscf_impl_t *key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    return ED25519_DH_LEN;
}
