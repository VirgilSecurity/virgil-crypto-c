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
//  This module contains 'x25519 public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_x25519_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_simple_alg_info.h"
#include "vscf_alg_info.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_x25519_private_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_random.h"
#include "vscf_x25519_public_key_defs.h"
#include "vscf_x25519_public_key_internal.h"

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
//  Note, this method is called automatically when method vscf_x25519_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_x25519_public_key_init_ctx(vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_x25519_public_key_cleanup_ctx(vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_x25519_public_key_setup_defaults(vscf_x25519_public_key_t *self) {

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

    return vscf_status_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_x25519_public_key_alg_id(const vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_X25519;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_x25519_public_key_produce_alg_info(const vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_X25519));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_x25519_public_key_restore_alg_info(vscf_x25519_public_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_X25519);

    return vscf_status_SUCCESS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_x25519_public_key_key_len(const vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return ED25519_KEY_LEN;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_x25519_public_key_key_bitlen(const vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return (8 * ED25519_KEY_LEN);
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_x25519_public_key_encrypt(vscf_x25519_public_key_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_x25519_public_key_encrypted_len(self, data.len));

    vscf_ecies_use_encryption_key(self->ecies, vscf_x25519_public_key_impl(self));
    vscf_status_t status = vscf_ecies_encrypt(self->ecies, data, out);
    vscf_ecies_release_encryption_key(self->ecies);

    if (status != vscf_status_SUCCESS) {
        //  TODO: Log underlying error
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_x25519_public_key_encrypted_len(vscf_x25519_public_key_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);

    return vscf_ecies_encrypted_len(self->ecies, data_len);
}

//
//  Export public key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_x25519_public_key_export_public_key(const vscf_x25519_public_key_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_x25519_public_key_exported_public_key_len(self));

    vsc_buffer_write_data(out, vsc_data(self->public_key, ED25519_KEY_LEN));

    return vscf_status_SUCCESS;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_x25519_public_key_exported_public_key_len(const vscf_x25519_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return ED25519_KEY_LEN;
}

//
//  Import public key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_x25519_public_key_import_public_key(vscf_x25519_public_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));

    if (data.len != ED25519_KEY_LEN) {
        return vscf_status_ERROR_BAD_X25519_PUBLIC_KEY;
    }

    memcpy(self->public_key, data.bytes, ED25519_KEY_LEN);

    return vscf_status_SUCCESS;
}

//
//  Generate ephemeral private key of the same type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_x25519_public_key_generate_ephemeral_key(vscf_x25519_public_key_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();
    vscf_x25519_private_key_use_random(private_key, self->random);

    vscf_status_t status = vscf_x25519_private_key_generate_key(private_key);
    if (status != vscf_status_SUCCESS) {
        vscf_x25519_private_key_destroy(&private_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    if (self->ecies) {
        vscf_x25519_private_key_use_ecies(private_key, self->ecies);
    }

    return vscf_x25519_private_key_impl(private_key);
}
