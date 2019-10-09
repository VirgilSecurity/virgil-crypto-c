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
//  This module contains 'falcon' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_falcon.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_simple_alg_info.h"
#include "vscf_raw_public_key_defs.h"
#include "vscf_raw_private_key_defs.h"
#include "vscf_random.h"
#include "vscf_falcon_defs.h"
#include "vscf_falcon_internal.h"

#include <falcon/falcon.h>

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
    vscf_falcon_SEED_LEN = 48,
    vscf_falcon_LOGN_512 = 9,
    vscf_falcon_LOGN_1024 = 10
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Generate new private key.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_falcon_generate_key(const vscf_falcon_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    //
    //  Make random SEED
    //
    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_falcon_SEED_LEN);
    const vscf_status_t status = vscf_random(self->random, vscf_falcon_SEED_LEN, seed);
    if (status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        vsc_buffer_destroy(&seed);
        return NULL;
    }
    vsc_buffer_make_secure(seed);

    vsc_buffer_t *private_key_buf = vsc_buffer_new_with_capacity(FALCON_PRIVKEY_SIZE(vscf_falcon_LOGN_512));
    vsc_buffer_t *public_key_buf = vsc_buffer_new_with_capacity(FALCON_PUBKEY_SIZE(vscf_falcon_LOGN_512));

    //
    //  Initialize DRBG
    //
    falcon_shake256_context shake256;
    falcon_shake256_init(&shake256);
    falcon_shake256_inject(&shake256, vsc_buffer_bytes(seed), vsc_buffer_len(seed));
    falcon_shake256_flip(&shake256);
    vsc_buffer_destroy(&seed);

    //
    //  Generate keys
    //
    byte tmp[FALCON_TMPSIZE_KEYGEN(vscf_falcon_LOGN_512)] = {0x00};
    const int falcon_status = falcon_keygen_make(&shake256, vscf_falcon_LOGN_512,
            vsc_buffer_unused_bytes(private_key_buf), vsc_buffer_unused_len(private_key_buf),
            vsc_buffer_unused_bytes(public_key_buf), vsc_buffer_unused_len(public_key_buf), tmp, sizeof(tmp));
    VSCF_ASSERT(falcon_status == 0);

    vsc_buffer_inc_used(private_key_buf, FALCON_PRIVKEY_SIZE(vscf_falcon_LOGN_512));
    vsc_buffer_inc_used(public_key_buf, FALCON_PUBKEY_SIZE(vscf_falcon_LOGN_512));

    vscf_impl_t *pub_alg_info = vscf_falcon_produce_alg_info(self);
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
vscf_falcon_alg_id(const vscf_falcon_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_FALCON;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_falcon_produce_alg_info(const vscf_falcon_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_falcon_restore_alg_info(vscf_falcon_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_falcon_generate_ephemeral_key(const vscf_falcon_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    if (vscf_key_impl_tag(key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    return vscf_falcon_generate_key(self, error);
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
vscf_falcon_import_public_key(const vscf_falcon_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_public_key_is_valid(raw_key));

    if (vscf_raw_public_key_alg_id(raw_key) != vscf_alg_id_FALCON) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    vsc_data_t raw_key_data = vscf_raw_public_key_data(raw_key);
    if (raw_key_data.len != FALCON_PUBKEY_SIZE(vscf_falcon_LOGN_512)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_FALCON_PUBLIC_KEY);
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
vscf_falcon_export_public_key(const vscf_falcon_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

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
vscf_falcon_import_private_key(const vscf_falcon_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_private_key_is_valid(raw_key));

    if (vscf_raw_private_key_alg_id(raw_key) != vscf_alg_id_FALCON) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }
    vsc_data_t raw_key_data = vscf_raw_private_key_data(raw_key);
    if (raw_key_data.len != FALCON_PRIVKEY_SIZE(vscf_falcon_LOGN_512)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY);
        return NULL;
    }

    //  Extract public key
    byte tmp[FALCON_TMPSIZE_MAKEPUB(vscf_falcon_LOGN_512)];
    vsc_buffer_t *public_key_buf = vsc_buffer_new_with_capacity(FALCON_PUBKEY_SIZE(vscf_falcon_LOGN_512));
    const int ret = falcon_make_public(vsc_buffer_unused_bytes(public_key_buf), vsc_buffer_unused_len(public_key_buf),
            vscf_raw_private_key_data(raw_key).bytes, vscf_raw_private_key_data(raw_key).len, tmp, sizeof(tmp));
    VSCF_ASSERT(ret == 0);
    vsc_buffer_inc_used(public_key_buf, FALCON_TMPSIZE_MAKEPUB(vscf_falcon_LOGN_512));

    vscf_impl_t *alg_info = vscf_impl_shallow_copy((vscf_impl_t *)vscf_raw_private_key_alg_info(raw_key));
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
vscf_falcon_export_private_key(const vscf_falcon_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

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
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_falcon_can_sign(const vscf_falcon_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    return true;
}

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_falcon_signature_len(const vscf_falcon_t *self, const vscf_impl_t *key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);

    return 0;
}

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_falcon_sign_hash(const vscf_falcon_t *self, const vscf_impl_t *private_key, vscf_alg_id_t hash_id,
        vsc_data_t digest, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));

    return vscf_status_SUCCESS;
}

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_falcon_can_verify(const vscf_falcon_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    return true;
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_falcon_verify_hash(const vscf_falcon_t *self, const vscf_impl_t *public_key, vscf_alg_id_t hash_id,
        vsc_data_t digest, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));

    return false;
}
