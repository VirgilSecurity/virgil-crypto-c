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
//  This module contains 'ed25519 private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ed25519_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_ed25519_public_key_defs.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_ctr_drbg.h"
#include "vscf_random.h"
#include "vscf_ed25519_private_key_defs.h"
#include "vscf_ed25519_private_key_internal.h"

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
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_ed25519_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ed25519_private_key_init_ctx(vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ed25519_private_key_cleanup_ctx(vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    vscf_erase(self->secret_key, ED25519_KEY_LEN);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_setup_defaults(vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_ctr_drbg_setup_defaults(random);
        self->random = vscf_ctr_drbg_impl(random);
    }

    if (NULL == self->ecies) {
        self->ecies = vscf_ecies_new();
        vscf_ecies_use_random(self->ecies, self->random);
        vscf_ecies_setup_defaults(self->ecies);
    }

    return vscf_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_ed25519_private_key_alg_id(const vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_ED25519;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ed25519_private_key_produce_alg_info(const vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_restore_alg_info(vscf_ed25519_private_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_ED25519);

    return vscf_SUCCESS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_key_len(const vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return ED25519_KEY_LEN;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_key_bitlen(const vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return (8 * ED25519_KEY_LEN);
}

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_generate_key(vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    vsc_buffer_t *generated = vsc_buffer_new();
    VSCF_ASSERT_PTR(generated);
    vsc_buffer_use(generated, self->secret_key, ED25519_KEY_LEN);
    if (vscf_SUCCESS != vscf_random(self->random, ED25519_KEY_LEN, generated)) {
        vsc_buffer_destroy(&generated);
        return vscf_error_KEY_GENERATION_FAILED;
    }
    vsc_buffer_destroy(&generated);
    return vscf_SUCCESS;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_decrypt(vscf_ed25519_private_key_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ed25519_private_key_decrypted_len(self, data.len));

    vscf_ecies_use_decryption_key(self->ecies, vscf_ed25519_private_key_impl(self));
    vscf_error_t status = vscf_ecies_decrypt(self->ecies, data, out);
    vscf_ecies_release_decryption_key(self->ecies);

    if (status != vscf_SUCCESS) {
        //  TODO: Log underlying error
        return vscf_error_BAD_ENCRYPTED_DATA;
    }

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_decrypted_len(vscf_ed25519_private_key_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);

    return vscf_ecies_decrypted_len(self->ecies, data_len);
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_sign(vscf_ed25519_private_key_t *self, vsc_data_t data, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(ED25519_SIG_LEN == vsc_buffer_capacity(signature));
    VSCF_ASSERT_PTR(data.bytes);
    int ret = ed25519_sign(vsc_buffer_unused_bytes(signature), self->secret_key, data.bytes, data.len);
    VSCF_ASSERT(ret == 0);
    vsc_buffer_inc_used(signature, vscf_ed25519_private_key_signature_len(self));
    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_signature_len(vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return ED25519_SIG_LEN;
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ed25519_private_key_extract_public_key(const vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ed25519_public_key_t *ed25519_public_key = vscf_ed25519_public_key_new();
    int ret = ed25519_get_pubkey(ed25519_public_key->public_key, self->secret_key);
    VSCF_ASSERT(ret == 0);

    return vscf_ed25519_public_key_impl(ed25519_public_key);
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_export_private_key(const vscf_ed25519_private_key_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ed25519_private_key_exported_private_key_len(self));

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t len = vscf_asn1wr_write_octet_str(&asn1wr, vsc_data(self->secret_key, ED25519_KEY_LEN));
    vsc_buffer_inc_used(out, len);

    if (!vsc_buffer_is_reverse(out)) {
        vscf_asn1wr_finish(&asn1wr);
    }

    vscf_asn1wr_cleanup(&asn1wr);

    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_exported_private_key_len(const vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //
    //  https://tools.ietf.org/rfc/rfc8410.txt
    //
    //  CurvePrivateKey ::= OCTET STRING
    //
    return 2 + ED25519_KEY_LEN;
}

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_import_private_key(vscf_ed25519_private_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));

    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, data);

    vsc_data_t key = vscf_asn1rd_read_octet_str(&asn1rd);

    vscf_asn1rd_cleanup(&asn1rd);

    if (vscf_asn1rd_error(&asn1rd) != vscf_SUCCESS || key.len != ED25519_KEY_LEN) {
        return vscf_error_BAD_ED25519_PRIVATE_KEY;
    }

    memcpy(self->secret_key, key.bytes, ED25519_KEY_LEN);

    return vscf_SUCCESS;
}

//
//  Compute shared key for 2 asymmetric keys.
//  Note, shared key can be used only for symmetric cryptography.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_compute_shared_key(
        vscf_ed25519_private_key_t *self, const vscf_impl_t *public_key, vsc_buffer_t *shared_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(shared_key));
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= ED25519_DH_LEN);

    unsigned char x25519_public_key[ED25519_KEY_LEN] = {0x00};
    unsigned char x25519_private_key[ED25519_KEY_LEN] = {0x00};

    const vscf_ed25519_public_key_t *ed25519_public_key = (const vscf_ed25519_public_key_t *)public_key;

    ed25519_pubkey_to_curve25519(x25519_public_key, ed25519_public_key->public_key);
    ed25519_key_to_curve25519(x25519_private_key, self->secret_key);

    const int status =
            curve25519_key_exchange(vsc_buffer_unused_bytes(shared_key), x25519_public_key, x25519_private_key);

    if (status != 0) {
        return vscf_error_SHARED_KEY_EXCHANGE_FAILED;
    }

    vsc_buffer_inc_used(shared_key, ED25519_DH_LEN);

    return vscf_SUCCESS;
}

//
//  Return number of bytes required to hold shared key.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_shared_key_len(vscf_ed25519_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return ED25519_KEY_LEN;
}
